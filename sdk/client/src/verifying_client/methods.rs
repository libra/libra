// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::{Error, Result},
    request::MethodRequest,
    response::{MethodResponse, Response},
    state::State,
};
use diem_json_rpc_types::views::{
    AccountStateWithProofView, AccountView, CurrencyInfoView, EventView, MetadataView,
    TransactionListView,
};
use diem_types::{
    account_address::AccountAddress,
    account_config::{diem_root_address, NewBlockEvent},
    account_state::AccountState,
    account_state_blob::AccountStateWithProof,
    block_metadata::new_block_event_key,
    contract_event::{EventByVersionWithProof, EventWithProof},
    event::EventKey,
    ledger_info::LedgerInfo,
    proof::{AccumulatorConsistencyProof, TransactionAccumulatorSummary},
    state_proof::StateProof,
    transaction::{AccountTransactionsWithProof, Version},
    trusted_state::TrustedState,
};
use std::convert::TryFrom;

pub(crate) struct VerifyingBatch {
    requests: Vec<VerifyingRequest>,
}

impl VerifyingBatch {
    pub(crate) fn from_batch(requests: Vec<MethodRequest>) -> Self {
        Self {
            requests: requests.into_iter().map(VerifyingRequest::from).collect(),
        }
    }

    pub(crate) fn num_subrequests(&self) -> usize {
        self.requests
            .iter()
            .map(|request| request.subrequests.len())
            .sum::<usize>()
            + 1 /* get_state_proof */
    }

    pub(crate) fn collect_requests(&self, request_version: Version) -> Vec<MethodRequest> {
        let mut requests = self
            .requests
            .iter()
            .flat_map(|request| request.subrequests.iter().cloned())
            .collect::<Vec<_>>();
        requests.push(MethodRequest::get_state_proof(request_version));
        requests
    }

    pub(crate) fn validate_responses(
        self,
        request_trusted_state: &TrustedState,
        mut responses: Vec<Result<Response<MethodResponse>>>,
    ) -> Result<(Option<TrustedState>, Vec<Result<Response<MethodResponse>>>)> {
        // make sure we get the exact number of responses back as we expect
        let num_subrequests = self.num_subrequests();
        if num_subrequests != responses.len() {
            return Err(Error::rpc_response(format!(
                "expected {} responses, received {} responses in batch",
                num_subrequests,
                responses.len()
            )));
        }

        // pull out the state proof response, since we need to ratchet our state
        // first before validating the subsequent responses
        // note: the .unwrap() is ok since we just checked that we have enough responses above
        let (state_proof_response, state) = responses.pop().unwrap()?.into_parts();
        let state_proof_view = state_proof_response.try_into_get_state_proof()?;
        let state_proof = StateProof::try_from(&state_proof_view).map_err(Error::decode)?;

        // check the response metadata matches the state proof
        verify_latest_li_matches_state(state_proof.latest_ledger_info(), &state)?;

        // check that all responses fulfilled at the same chain state
        for response in responses.iter().flatten() {
            if response.state() != &state {
                return Err(Error::rpc_response(format!(
                    "expected all responses in batch to have the same metadata: {:?}, \
                         received unexpected response metadata: {:?}",
                    state,
                    response.state(),
                )));
            }
        }

        // try to verify and ratchet our trusted state using the state proof
        let new_state = request_trusted_state
            .verify_and_ratchet(&state_proof, None)
            .map_err(Error::invalid_proof)?
            .new_state();

        // remote says we're too far behind and need to sync. we have to throw
        // out the batch since we can't verify any proofs
        if state_proof.epoch_changes().more {
            // TODO(philiphayes): what is the right behaviour here? it would obv.
            // be more convenient to just call `self.sync` here and then retry,
            // but maybe a client would like to control the syncs itself?
            return Err(Error::unknown(
                "our client is too far behind, we need to sync",
            ));
        }

        // unflatten subresponses, verify, and collect into one response per request
        let mut responses_iter = responses.into_iter();
        let validated_responses = self
            .requests
            .into_iter()
            .map(|request| {
                let n = request.subrequests.len();
                let subresponses = responses_iter.by_ref().take(n).collect();
                request.validate_subresponses(
                    request_trusted_state.version(),
                    &state,
                    &state_proof,
                    subresponses,
                )
            })
            .collect::<Vec<_>>();

        Ok((new_state, validated_responses))
    }
}

/// Check that certain metadata (version and timestamp) in a `LedgerInfo` matches
/// the response `State`.
pub(crate) fn verify_latest_li_matches_state(latest_li: &LedgerInfo, state: &State) -> Result<()> {
    if latest_li.version() != state.version {
        return Err(Error::invalid_proof(format!(
            "latest LedgerInfo version ({}) doesn't match response version ({})",
            latest_li.version(),
            state.version,
        )));
    }
    if latest_li.timestamp_usecs() != state.timestamp_usecs {
        return Err(Error::invalid_proof(format!(
            "latest LedgerInfo timestamp ({}) doesn't match response timestamp ({})",
            latest_li.timestamp_usecs(),
            state.timestamp_usecs,
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RequestContext<'a> {
    #[allow(dead_code)]
    start_version: Version,

    state: &'a State,

    state_proof: &'a StateProof,

    #[allow(dead_code)]
    request: &'a MethodRequest,

    #[allow(dead_code)]
    subrequests: &'a [MethodRequest],
}

type RequestCallback =
    Box<dyn FnOnce(RequestContext<'_>, &[MethodResponse]) -> Result<MethodResponse>>;

struct VerifyingRequest {
    request: MethodRequest,
    subrequests: Vec<MethodRequest>,
    callback: RequestCallback,
}

impl VerifyingRequest {
    fn new(
        request: MethodRequest,
        subrequests: Vec<MethodRequest>,
        callback: RequestCallback,
    ) -> Self {
        Self {
            request,
            subrequests,
            callback,
        }
    }

    fn map<F>(self, f: F) -> VerifyingRequest
    where
        F: FnOnce(RequestContext<'_>, MethodResponse) -> MethodResponse + 'static,
    {
        let inner = self.callback;
        let callback: RequestCallback = Box::new(move |ctxt, subresponses| {
            let response = inner(ctxt, subresponses)?;
            Ok(f(ctxt, response))
        });
        Self::new(self.request, self.subrequests, callback)
    }

    // TODO(philiphayes): this would be easier if the Error's were cloneable...

    fn validate_subresponses(
        self,
        start_version: Version,
        state: &State,
        state_proof: &StateProof,
        subresponses: Vec<Result<Response<MethodResponse>>>,
    ) -> Result<Response<MethodResponse>> {
        if subresponses.len() != self.subrequests.len() {
            return Err(Error::rpc_response(format!(
                "expected {} subresponses for our request {:?}, received {} subresponses in batch",
                self.subrequests.len(),
                self.request.method(),
                subresponses.len(),
            )));
        }

        let ctxt = RequestContext {
            start_version,
            state,
            state_proof,
            request: &self.request,
            subrequests: &self.subrequests.as_slice(),
        };

        // TODO(philiphayes): coalesce the Result's somehow so we don't lose error info.

        let subresponses_only = subresponses
            .into_iter()
            .map(|result| result.map(Response::into_inner))
            .collect::<Result<Vec<_>>>()?;

        let response = (self.callback)(ctxt, subresponses_only.as_slice())?;
        Ok(Response::new(response, state.clone()))
    }
}

impl From<MethodRequest> for VerifyingRequest {
    fn from(request: MethodRequest) -> Self {
        match request {
            MethodRequest::Submit((txn,)) => submit(txn),
            MethodRequest::GetMetadata((None,)) => get_latest_metadata(),
            MethodRequest::GetMetadata((Some(version),)) => get_historical_metadata(version),
            MethodRequest::GetAccount(address, version) => get_account(address, version),
            MethodRequest::GetTransactions(start_version, limit, include_events) => {
                get_transactions(start_version, limit, include_events)
            }
            MethodRequest::GetAccountTransactions(
                address,
                start_seq_num,
                limit,
                include_events,
            ) => get_account_transactions(address, start_seq_num, limit, include_events),
            MethodRequest::GetAccountTransaction(address, seq_num, include_events) => {
                get_account_transaction(address, seq_num, include_events)
            }
            MethodRequest::GetEvents(key, start_seq, limit) => get_events(key, start_seq, limit),
            MethodRequest::GetCurrencies([]) => get_currencies(),
            MethodRequest::GetNetworkStatus([]) => get_network_status(),
            _ => panic!(
                "unsupported verifying client method: {:?}",
                request.method()
            ),
        }
    }
}

fn submit(txn: String) -> VerifyingRequest {
    let request = MethodRequest::Submit((txn,));
    let subrequests = vec![request.clone()];
    let callback: RequestCallback = Box::new(move |_ctxt, subresponses| {
        match subresponses {
            [MethodResponse::Submit] => (),
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [Submit] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };
        Ok(MethodResponse::Submit)
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_latest_metadata() -> VerifyingRequest {
    let request = MethodRequest::GetMetadata((None,));
    let subrequests = vec![MethodRequest::GetAccountStateWithProof(
        diem_root_address(),
        None,
        None,
    )];
    let callback: RequestCallback = Box::new(move |ctxt, subresponses| {
        let diem_root = match subresponses {
            [MethodResponse::GetAccountStateWithProof(ref account)] => account,
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetAccountStateWithProof] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };

        let latest_li = ctxt.state_proof.latest_ledger_info();
        let diem_root = verify_account_state(ctxt, &diem_root, diem_root_address(), None)?
            .ok_or_else(|| Error::rpc_response("DiemRoot account is missing"))?;

        let version = latest_li.version();
        let accumulator_root_hash = latest_li.transaction_accumulator_hash();
        let timestamp = latest_li.timestamp_usecs();
        let chain_id = ctxt.state.chain_id;

        let mut metadata_view =
            MetadataView::new(version, accumulator_root_hash, timestamp, chain_id);
        metadata_view
            .with_diem_root(&diem_root)
            .map_err(Error::rpc_response)?;

        Ok(MethodResponse::GetMetadata(metadata_view))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_historical_metadata(version: Version) -> VerifyingRequest {
    let request = MethodRequest::GetMetadata((Some(version),));
    let subrequests = vec![
        MethodRequest::GetAccumulatorConsistencyProof(None, Some(version)),
        MethodRequest::GetAccumulatorConsistencyProof(Some(version), None),
        MethodRequest::GetEventByVersionWithProof(new_block_event_key(), Some(version)),
    ];
    let callback: RequestCallback = Box::new(move |ctxt, subresponses| {
        let (consistency_pg2v, consistency_v2li, block_event) = match subresponses {
            [MethodResponse::GetAccumulatorConsistencyProof(ref c1), MethodResponse::GetAccumulatorConsistencyProof(ref c2), MethodResponse::GetEventByVersionWithProof(ref e)] => (c1, c2, e),
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetAccumulatorConsistencyProof, GetAccumulatorConsistencyProof, GetEventByVersionWithProof] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };

        let latest_li = ctxt.state_proof.latest_ledger_info();

        // deserialize
        let consistency_pg2v =
            AccumulatorConsistencyProof::try_from(consistency_pg2v).map_err(Error::decode)?;
        let consistency_v2li =
            AccumulatorConsistencyProof::try_from(consistency_v2li).map_err(Error::decode)?;
        let block_event = EventByVersionWithProof::try_from(block_event).map_err(Error::decode)?;

        // build the accumulator summary from pre-genesis to the requested version
        let accumulator_summary =
            TransactionAccumulatorSummary::try_from_genesis_proof(consistency_pg2v, version)
                .map_err(Error::invalid_proof)?;
        // compute the root hash at the requested version
        let accumulator_root_hash = accumulator_summary.root_hash();

        // verify that the historical accumulator_summary is actually a prefix of
        // our latest verified accumulator_summary.
        let _ = accumulator_summary
            .try_extend_with_proof(&consistency_v2li, &latest_li)
            .map_err(Error::invalid_proof)?;

        // NewBlockEvent can be special cased so we don't need to lookup the diem_root::DiemBlock->height
        let event_count = None;
        // verify the block event for the requested version
        block_event
            .verify(latest_li, &new_block_event_key(), event_count, version)
            .map_err(Error::invalid_proof)?;

        // extract the timestamp
        let timestamp = match (block_event.lower_bound_incl, block_event.upper_bound_excl) {
            // For block events specifically, these cases should only happen at genesis.
            (None, None) | (None, Some(_)) => {
                if version == 0 {
                    0 // genesis timestamp is 0
                } else {
                    return Err(Error::rpc_response("not genesis"));
                }
            }
            // This logic is for all request versions before the current, latest block.
            (Some(block_event), Some(_)) => {
                let block_event =
                    NewBlockEvent::try_from(&block_event.event).map_err(Error::decode)?;
                block_event.proposed_time()
            }
            // This logic is for the current, latest block.
            (Some(block_event), None) => {
                let block_event =
                    NewBlockEvent::try_from(&block_event.event).map_err(Error::decode)?;
                let timestamp = block_event.proposed_time();
                // since the timestamp must increment across an epoch boundary,
                // (round, timestamp) provides a total order across blocks.
                //
                // If these two values don't match with our verified latest ledger
                // info, then we know this can't be the latest block.
                if block_event.round() != latest_li.round()
                    || timestamp != latest_li.timestamp_usecs()
                {
                    return Err(Error::rpc_response("not latest block"));
                }
                timestamp
            }
        };

        let chain_id = ctxt.state.chain_id;
        let metadata_view = MetadataView::new(version, accumulator_root_hash, timestamp, chain_id);
        Ok(MethodResponse::GetMetadata(metadata_view))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_account(address: AccountAddress, version: Option<Version>) -> VerifyingRequest {
    let request = MethodRequest::GetAccount(address, version);
    let subrequests = vec![MethodRequest::GetAccountStateWithProof(
        address, version, None,
    )];
    let callback: RequestCallback = Box::new(move |ctxt, subresponses| {
        let account = match subresponses {
            [MethodResponse::GetAccountStateWithProof(ref account)] => account,
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetAccountStateWithProof] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };

        let ledger_version = ctxt.state_proof.latest_ledger_info().version();
        let version = version.unwrap_or(ledger_version);
        let maybe_account_state = verify_account_state(ctxt, &account, address, Some(version))?;
        let maybe_account_view = maybe_account_state
            .map(|account_state| {
                AccountView::try_from_account_state(address, account_state, version)
                    .map_err(Error::decode)
            })
            .transpose()?;

        Ok(MethodResponse::GetAccount(maybe_account_view))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_transactions(start_version: Version, limit: u64, include_events: bool) -> VerifyingRequest {
    let request = MethodRequest::GetTransactions(start_version, limit, include_events);
    let subrequests = vec![MethodRequest::GetTransactionsWithProofs(
        start_version,
        limit,
        include_events,
    )];
    let callback: RequestCallback = Box::new(move |ctxt, subresponses| {
        let maybe_txs_with_proofs_view = match subresponses {
            [MethodResponse::GetTransactionsWithProofs(ref txs)] => txs,
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetTransactionsWithProofs] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };

        // We don't guarantee that our response contains _all_ possible transactions
        // in the range (start_version..start_version + min(limit, ledger_version - start_version + 1)).
        // Instead, the remote server may return any prefix in the above range;
        // however, our verification here _will_ verify the prefix.

        let txs_with_proofs_view = if let Some(txs_with_proofs_view) = maybe_txs_with_proofs_view {
            txs_with_proofs_view
        } else {
            return Ok(MethodResponse::GetTransactions(Vec::new()));
        };

        // Check that the presence of events in the response matches our expectation.
        let has_events = txs_with_proofs_view.serialized_events.is_some();
        if include_events != has_events {
            return Err(Error::rpc_response(format!(
                "expected events: {}, received events: {}",
                include_events, has_events
            )));
        }

        // Deserialize the diem-types from the json-rpc-types view.
        let txn_list_with_proof = txs_with_proofs_view
            .try_into_txn_list_with_proof(start_version)
            .map_err(Error::decode)?;

        // Verify the proofs
        let latest_li = ctxt.state_proof.latest_ledger_info();
        txn_list_with_proof
            .verify(latest_li, Some(start_version))
            .map_err(Error::invalid_proof)?;

        // Project into a list of TransactionView's.
        let txn_list_view =
            TransactionListView::try_from(txn_list_with_proof).map_err(Error::decode)?;

        Ok(MethodResponse::GetTransactions(txn_list_view.0))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_account_transactions(
    address: AccountAddress,
    start_seq_num: u64,
    limit: u64,
    include_events: bool,
) -> VerifyingRequest {
    let request =
        MethodRequest::GetAccountTransactions(address, start_seq_num, limit, include_events);
    let subrequests = vec![MethodRequest::GetAccountTransactionsWithProofs(
        address,
        start_seq_num,
        limit,
        include_events,
        None, /* ledger_version must be None so proofs are verifiable at the latest state */
    )];
    let callback: RequestCallback = Box::new(move |ctxt, subresponses| {
        let acct_txns_with_proof_view = match subresponses {
            [MethodResponse::GetAccountTransactionsWithProofs(ref txs)] => txs,
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetAccountTransactionsWithProofs] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };

        let acct_txns_with_proof =
            AccountTransactionsWithProof::try_from(acct_txns_with_proof_view)
                .map_err(Error::decode)?;

        let latest_li = ctxt.state_proof.latest_ledger_info();
        let ledger_version = latest_li.version();

        acct_txns_with_proof
            .verify(
                latest_li,
                address,
                start_seq_num,
                limit,
                include_events,
                ledger_version,
            )
            .map_err(Error::invalid_proof)?;

        let txs = TransactionListView::try_from(acct_txns_with_proof).map_err(Error::decode)?;

        Ok(MethodResponse::GetAccountTransactions(txs.0))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_account_transaction(
    address: AccountAddress,
    seq_num: u64,
    include_events: bool,
) -> VerifyingRequest {
    get_account_transactions(address, seq_num, 1, include_events).map(|_ctxt, response| {
        match response {
            MethodResponse::GetAccountTransactions(txns) => {
                MethodResponse::GetAccountTransaction(txns.into_iter().next())
            }
            response => panic!(
                "expected GetAccountTransactions response, got: {:?}",
                response
            ),
        }
    })
}

fn get_events(key: EventKey, start_seq: u64, limit: u64) -> VerifyingRequest {
    let request = MethodRequest::GetEvents(key, start_seq, limit);
    let subrequests = vec![MethodRequest::GetEventsWithProofs(key, start_seq, limit)];

    let callback: RequestCallback = Box::new(move |ctxt, subresponses| {
        let event_with_proof_views = match subresponses {
            [MethodResponse::GetEventsWithProofs(ref inner)] => inner,
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetEventsWithProofs] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };

        // Make sure we didn't get more than we requested. Note that remote can
        // always return a shorter prefix than is on-chain and we don't consider
        // that an invalid response.
        let num_received = event_with_proof_views.len() as u64;
        if num_received > limit {
            return Err(Error::rpc_response(format!(
                "more events than limit: limit {} events, received {} events",
                limit, num_received,
            )));
        }

        let latest_li = ctxt.state_proof.latest_ledger_info();
        let event_views = event_with_proof_views
            .iter()
            .enumerate()
            .map(|(offset, event_with_proof_view)| {
                // Deserialize the diem-core type from the json-rpc view type.
                let event_with_proof =
                    EventWithProof::try_from(event_with_proof_view).map_err(Error::decode)?;

                // Actually verify the proof. Once verified, we should be guaranteed
                // that this event exists on-chain in the `key` event stream with
                // the given sequence number and transaction version.
                let txn_version = event_with_proof.transaction_version;
                event_with_proof
                    .verify(
                        latest_li,
                        &key,
                        start_seq + offset as u64,
                        txn_version,
                        event_with_proof.event_index,
                    )
                    .map_err(Error::invalid_proof)?;

                // Project into the json-rpc type
                let event_view = EventView::try_from((txn_version, event_with_proof.event))
                    .map_err(Error::decode)?;

                Ok(event_view)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(MethodResponse::GetEvents(event_views))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_currencies() -> VerifyingRequest {
    let request = MethodRequest::GetCurrencies([]);
    let subrequests = vec![MethodRequest::GetAccountStateWithProof(
        diem_root_address(),
        None,
        None,
    )];
    let callback: RequestCallback = Box::new(|ctxt, subresponses| {
        let diem_root = match subresponses {
            [MethodResponse::GetAccountStateWithProof(ref diem_root)] => diem_root,
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetAccountStateWithProof] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };

        let diem_root = verify_account_state(ctxt, &diem_root, diem_root_address(), None)?
            .ok_or_else(|| Error::rpc_response("DiemRoot account is missing"))?;
        let currency_infos = diem_root
            .get_registered_currency_info_resources()
            .map_err(Error::decode)?;
        let currency_views = currency_infos.iter().map(CurrencyInfoView::from).collect();

        Ok(MethodResponse::GetCurrencies(currency_views))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn get_network_status() -> VerifyingRequest {
    let request = MethodRequest::get_network_status();
    let subrequests = vec![MethodRequest::get_network_status()];
    let callback: RequestCallback = Box::new(|_ctxt, subresponses| {
        let status = match subresponses {
            [MethodResponse::GetNetworkStatus(ref status)] => *status,
            subresponses => {
                return Err(Error::rpc_response(format!(
                    "expected [GetNetworkStatus] subresponses, received: {:?}",
                    subresponses,
                )))
            }
        };
        Ok(MethodResponse::GetNetworkStatus(status))
    });
    VerifyingRequest::new(request, subrequests, callback)
}

fn verify_account_state(
    ctxt: RequestContext<'_>,
    view: &AccountStateWithProofView,
    address: AccountAddress,
    version: Option<Version>,
) -> Result<Option<AccountState>> {
    let account_state_with_proof = AccountStateWithProof::try_from(view).map_err(Error::decode)?;

    let latest_li = ctxt.state_proof.latest_ledger_info();
    let ledger_version = latest_li.version();
    let version = version.unwrap_or(ledger_version);

    account_state_with_proof
        .verify(latest_li, version, address)
        .map_err(Error::invalid_proof)?;

    account_state_with_proof
        .blob
        .map(|blob| AccountState::try_from(&blob).map_err(Error::decode))
        .transpose()
}
