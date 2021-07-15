// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    client::Client,
    error::{Error, Result, WaitForTransactionError},
    request::MethodRequest,
    response::{MethodResponse, Response},
    state::State,
};
use diem_crypto::hash::{CryptoHash, HashValue};
use diem_json_rpc_types::views::{
    AccountStateWithProofView, AccountView, CurrencyInfoView, EventView, MetadataView,
    TransactionListView, TransactionView,
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
    transaction::{AccountTransactionsWithProof, SignedTransaction, Transaction, Version},
    trusted_state::TrustedState,
    waypoint::Waypoint,
};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::Debug,
    sync::{Arc, RwLock},
    time::Duration,
};

// TODO(philiphayes): figure out retry strategy
// TODO(philiphayes): real on-disk waypoint persistence
// TODO(philiphayes): fill out rest of the methods
// TODO(philiphayes): all clients should validate chain id (allow users to trust-on-first-use or pre-configure)
// TODO(philiphayes): we could abstract the async client so VerifyingClient takes a dyn Trait?

/// The `VerifyingClient` is a [Diem JSON-RPC client] that verifies Diem's
/// cryptographic proofs when it makes API calls.
///
/// ## Concurrency
///
/// When issuing multiple concurrent requests with the `VerifyingClient`, we guarantee:
///
/// 1. Each response batch is fulfilled and verified at a ledger version that
///    is greater than or equal to the current trusted version _at the time we
///    made the request batch_, though not necessarily the globally most
///    recent trusted ledger version.
///
/// 2. Requests made serially within a single thread of execution appear
///    strictly ordered, i.e., they were fulfilled and verified at
///    monotonically increasing ledger versions (`v1 <= v2 <= ...`).
///
/// Consequently, without any other effort, multiple concurrent requests may have
/// responses that appear inconsistent or out-of-order. For example, naively
/// making concurrent `get_account(..)` requests will (most likely) show accounts
/// at different ledger versions; even further, the first response you receive may
/// show a more recent ledger version than the second response.
///
/// To avoid this issue, users should pin a concurrent batch of requests to the
/// same ledger version if they want to avoid an inconsistent ledger view.
///
/// [Diem JSON-RPC client]: https://github.com/diem/diem/blob/master/json-rpc/json-rpc-spec.md
#[derive(Clone, Debug)]
pub struct VerifyingClient<S> {
    inner: Client,
    trusted_state_store: Arc<RwLock<TrustedStateStore<S>>>,
}

impl<S: Storage> VerifyingClient<S> {
    // TODO(philiphayes): construct the client ourselves? we probably want to
    // control the retries out here. For example, during sync, if we get a stale
    // state proof the retry logic should include that and not just fail immediately.
    pub fn new(inner: Client, storage: S) -> Result<Self> {
        let trusted_state_store = TrustedStateStore::new(storage)?;
        Ok(Self {
            inner,
            trusted_state_store: Arc::new(RwLock::new(trusted_state_store)),
        })
    }

    pub fn new_with_state(inner: Client, trusted_state: TrustedState, storage: S) -> Self {
        let trusted_state_store = TrustedStateStore::new_with_state(trusted_state, storage);
        Self {
            inner,
            trusted_state_store: Arc::new(RwLock::new(trusted_state_store)),
        }
    }

    /// Get a snapshot of our current trusted ledger [`Version`].
    pub fn version(&self) -> Version {
        self.trusted_state_store.read().unwrap().version()
    }

    /// Get a snapshot of our current trusted [`Waypoint`].
    pub fn waypoint(&self) -> Waypoint {
        self.trusted_state_store.read().unwrap().waypoint()
    }

    /// Get a snapshot of our current [`TrustedState`].
    pub fn trusted_state(&self) -> TrustedState {
        self.trusted_state_store
            .read()
            .unwrap()
            .trusted_state()
            .clone()
    }

    pub async fn wait_for_signed_transaction(
        &self,
        txn: &SignedTransaction,
        timeout: Option<Duration>,
        delay: Option<Duration>,
    ) -> Result<Response<TransactionView>, WaitForTransactionError> {
        let response = self
            .wait_for_transaction(
                txn.sender(),
                txn.sequence_number(),
                txn.expiration_timestamp_secs(),
                Transaction::UserTransaction(txn.clone()).hash(),
                timeout,
                delay,
            )
            .await?;

        if !response.inner().vm_status.is_executed() {
            return Err(WaitForTransactionError::TransactionExecutionFailed(
                response.into_inner(),
            ));
        }

        Ok(response)
    }

    pub async fn wait_for_transaction(
        &self,
        address: AccountAddress,
        seq: u64,
        expiration_time_secs: u64,
        txn_hash: HashValue,
        timeout: Option<Duration>,
        delay: Option<Duration>,
    ) -> Result<Response<TransactionView>, WaitForTransactionError> {
        const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
        const DEFAULT_DELAY: Duration = Duration::from_millis(50);

        let start = std::time::Instant::now();
        while start.elapsed() < timeout.unwrap_or(DEFAULT_TIMEOUT) {
            let txn_resp = self
                .get_account_transaction(address, seq, true)
                .await
                .map_err(WaitForTransactionError::GetTransactionError)?;

            let (maybe_txn, state) = txn_resp.into_parts();

            if let Some(txn) = maybe_txn {
                if txn.hash != txn_hash {
                    return Err(WaitForTransactionError::TransactionHashMismatchError(txn));
                }

                return Ok(Response::new(txn, state));
            }

            if expiration_time_secs <= state.timestamp_usecs / 1_000_000 {
                return Err(WaitForTransactionError::TransactionExpired);
            }

            tokio::time::sleep(delay.unwrap_or(DEFAULT_DELAY)).await;
        }

        Err(WaitForTransactionError::Timeout)
    }

    /// Issue `get_state_proof` requests until we successfully sync to the remote
    /// node's current version (unless we experience a verification error or other
    /// I/O error).
    pub async fn sync(&self) -> Result<()> {
        // TODO(philiphayes): retries
        while self.sync_one_step().await? {}
        Ok(())
    }

    /// Issue a single `get_state_proof` request and try to verify it. Returns
    /// `Ok(true)` if, after verification, we still need to sync more. Returns
    /// `Ok(false)` if we have finished syncing.
    pub async fn sync_one_step(&self) -> Result<bool> {
        let request_trusted_state = self.trusted_state();
        let need_initial_accumulator = request_trusted_state.accumulator_summary().is_none();
        let current_version = request_trusted_state.version();

        // request a state proof from remote and an optional initial transaction
        // accumulator if we're just starting out from an epoch waypoint.
        let (state_proof, maybe_accumulator) = self
            .get_state_proof_and_maybe_accumulator(current_version, need_initial_accumulator)
            .await?;

        // try to ratchet our trusted state using the state proof
        self.verify_and_ratchet(
            &request_trusted_state,
            &state_proof,
            maybe_accumulator.as_ref(),
        )?;

        // return true if we need to sync more epoch changes
        Ok(state_proof.epoch_changes().more)
    }

    async fn get_state_proof_and_maybe_accumulator(
        &self,
        current_version: Version,
        need_initial_accumulator: bool,
    ) -> Result<(StateProof, Option<TransactionAccumulatorSummary>)> {
        let (state_proof_view, state, maybe_consistency_proof_view) = if !need_initial_accumulator {
            // just request the state proof, since we don't need the initial accumulator
            let (state_proof_view, state) = self
                .inner
                .get_state_proof(current_version)
                .await?
                .into_parts();
            (state_proof_view, state, None)
        } else {
            // request both a state proof and an initial accumulator from genesis
            // to the current version.
            let batch = vec![
                MethodRequest::get_accumulator_consistency_proof(None, Some(current_version)),
                MethodRequest::get_state_proof(current_version),
            ];
            let resps = self.inner.batch(batch).await?;
            let mut resps_iter = resps.into_iter();

            // inner client guarantees us that # responses matches # requests
            let (resp1, state1) = resps_iter.next().unwrap()?.into_parts();
            let (resp2, state2) = resps_iter.next().unwrap()?.into_parts();

            if state1 != state2 {
                return Err(Error::rpc_response(format!(
                    "expected batch response states equal: state1={:?}, state2={:?}",
                    state1, state2
                )));
            }

            let consistency_proof_view = resp1.try_into_get_accumulator_consistency_proof()?;
            let state_proof_view = resp2.try_into_get_state_proof()?;
            (state_proof_view, state1, Some(consistency_proof_view))
        };

        // deserialize responses
        let state_proof = StateProof::try_from(&state_proof_view).map_err(Error::decode)?;
        let maybe_accumulator = maybe_consistency_proof_view
            .map(|consistency_proof_view| {
                let consistency_proof =
                    AccumulatorConsistencyProof::try_from(&consistency_proof_view)
                        .map_err(Error::decode)?;
                TransactionAccumulatorSummary::try_from_genesis_proof(
                    consistency_proof,
                    current_version,
                )
                .map_err(Error::invalid_proof)
            })
            .transpose()?;

        // check the response metadata matches the state proof
        verify_latest_li_matches_state(state_proof.latest_ledger_info(), &state)?;

        Ok((state_proof, maybe_accumulator))
    }

    /// Verify and ratchet forward a request's trusted state using a state proof
    /// and potentially persisting the new trusted state if it is the newest.
    pub fn verify_and_ratchet(
        &self,
        request_trusted_state: &TrustedState,
        state_proof: &StateProof,
        maybe_accumulator: Option<&TransactionAccumulatorSummary>,
    ) -> Result<()> {
        // Verify the response's state proof starting from the trusted state when
        // we first made the request. If successful, this means the potential new
        // trusted state is at least a descendent of the request trusted state,
        // though not necessarily the globally most-recent trusted state.
        let change = request_trusted_state
            .verify_and_ratchet(state_proof, maybe_accumulator)
            .map_err(Error::invalid_proof)?;

        // Try to compare-and-swap the new trusted state into the state store.
        // If the client is issuing muiltiple concurrent requests, the potential
        // new trusted state might not be newer than the current trusted state,
        // in which case we just don't persist this change.
        if let Some(new_state) = change.new_state() {
            self.trusted_state_store
                .write()
                .unwrap()
                .ratchet(new_state)?;
        }

        Ok(())
    }

    /// Submit a new signed user transaction.
    ///
    /// Note: we don't verify anything about the server's response here. If the
    /// server is behaving maliciously, they can claim our transaction is
    /// malformed when it is not, they can broadcast our valid transaction but
    /// tell us it is too old, or they can accept our invalid transaction without
    /// giving us any indication that it's bad.
    ///
    /// Unfortunately, there's nothing for us to verify that their response is
    /// correct or not; the only way to get around this is by broadcasting our
    /// transaction to multiple different servers. As long as one is honest, our
    /// valid transaction will eventually be committed. This client handles a
    /// connection to a single server, so the broadcasting needs to happen at a
    /// higher layer.
    pub async fn submit(&self, txn: &SignedTransaction) -> Result<Response<()>> {
        self.request(MethodRequest::submit(txn).map_err(Error::request)?)
            .await?
            .and_then(MethodResponse::try_into_submit)
    }

    pub async fn get_metadata_by_version(
        &self,
        version: Version,
    ) -> Result<Response<MetadataView>> {
        self.request(MethodRequest::get_metadata_by_version(version))
            .await?
            .and_then(MethodResponse::try_into_get_metadata)
    }

    pub async fn get_metadata(&self) -> Result<Response<MetadataView>> {
        self.request(MethodRequest::get_metadata())
            .await?
            .and_then(MethodResponse::try_into_get_metadata)
    }

    pub async fn get_account(
        &self,
        address: AccountAddress,
    ) -> Result<Response<Option<AccountView>>> {
        self.request(MethodRequest::get_account(address))
            .await?
            .and_then(MethodResponse::try_into_get_account)
    }

    pub async fn get_account_by_version(
        &self,
        address: AccountAddress,
        version: Version,
    ) -> Result<Response<Option<AccountView>>> {
        self.request(MethodRequest::get_account_by_version(address, version))
            .await?
            .and_then(MethodResponse::try_into_get_account)
    }

    pub async fn get_transactions(
        &self,
        start_version: Version,
        limit: u64,
        include_events: bool,
    ) -> Result<Response<Vec<TransactionView>>> {
        self.request(MethodRequest::get_transactions(
            start_version,
            limit,
            include_events,
        ))
        .await?
        .and_then(MethodResponse::try_into_get_transactions)
    }

    pub async fn get_account_transaction(
        &self,
        address: AccountAddress,
        seq_num: u64,
        include_events: bool,
    ) -> Result<Response<Option<TransactionView>>> {
        self.request(MethodRequest::get_account_transaction(
            address,
            seq_num,
            include_events,
        ))
        .await?
        .and_then(MethodResponse::try_into_get_account_transaction)
    }

    pub async fn get_account_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
    ) -> Result<Response<Vec<TransactionView>>> {
        self.request(MethodRequest::get_account_transactions(
            address,
            start_seq_num,
            limit,
            include_events,
        ))
        .await?
        .and_then(MethodResponse::try_into_get_account_transactions)
    }

    pub async fn get_events(
        &self,
        key: EventKey,
        start_seq: u64,
        limit: u64,
    ) -> Result<Response<Vec<EventView>>> {
        self.request(MethodRequest::get_events(key, start_seq, limit))
            .await?
            .and_then(MethodResponse::try_into_get_events)
    }

    pub async fn get_currencies(&self) -> Result<Response<Vec<CurrencyInfoView>>> {
        self.request(MethodRequest::get_currencies())
            .await?
            .and_then(MethodResponse::try_into_get_currencies)
    }

    pub async fn get_network_status(&self) -> Result<Response<u64>> {
        self.request(MethodRequest::get_network_status())
            .await?
            .and_then(MethodResponse::try_into_get_network_status)
    }

    /// Send a single request via `VerifyingClient::batch`.
    pub async fn request(&self, request: MethodRequest) -> Result<Response<MethodResponse>> {
        let mut responses = self.batch(vec![request]).await?.into_iter();
        let response = match responses.next() {
            Some(response) => response,
            None => {
                return Err(Error::rpc_response(
                    "expected one response, received empty response batch",
                ))
            }
        };
        let rest = responses.as_slice();
        if !rest.is_empty() {
            return Err(Error::rpc_response(format!(
                "expected one response, received unexpected responses: {:?}",
                rest,
            )));
        }
        response
    }

    pub fn actual_batch_size(requests: &[MethodRequest]) -> usize {
        let actual_requests = VerifyingBatch::from_batch(requests.to_vec()).collect_requests();
        actual_requests.len() + 1 /* get_state_proof */
    }

    pub async fn batch(
        &self,
        requests: Vec<MethodRequest>,
    ) -> Result<Vec<Result<Response<MethodResponse>>>> {
        let request_trusted_state = self.trusted_state();

        // if we haven't built an accumulator yet, we need to do a sync first.
        if request_trusted_state.accumulator_summary().is_none() {
            // TODO(philiphayes): sync fallback
            return Err(Error::unknown(
                "our client is too far behind, we need to sync",
            ));
        }

        // transform each request into verifying sub-request batches
        let batch = VerifyingBatch::from_batch(requests);

        // flatten and collect sub-request batches into flat list of requests
        let mut requests = batch.collect_requests();
        // append get_state_proof request
        let start_version = self.version();
        requests.push(MethodRequest::get_state_proof(start_version));

        // actually send the batch
        let mut responses = self.inner.batch(requests).await?;

        // extract and verify the state proof
        let (state_proof_response, state) = responses.pop().unwrap()?.into_parts();
        let state_proof_view = state_proof_response.try_into_get_state_proof()?;
        let state_proof = StateProof::try_from(&state_proof_view).map_err(Error::decode)?;

        // check the response metadata matches the state proof
        verify_latest_li_matches_state(state_proof.latest_ledger_info(), &state)?;

        // try to ratchet our trusted state using the state proof
        self.verify_and_ratchet(&request_trusted_state, &state_proof, None)?;

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
        batch.validate_responses(start_version, &state, &state_proof, responses)
    }
}

/// Check that certain metadata (version and timestamp) in a `LedgerInfo` matches
/// the response `State`.
fn verify_latest_li_matches_state(latest_li: &LedgerInfo, state: &State) -> Result<()> {
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

struct VerifyingBatch {
    requests: Vec<VerifyingRequest>,
}

impl VerifyingBatch {
    fn from_batch(requests: Vec<MethodRequest>) -> Self {
        Self {
            requests: requests.into_iter().map(VerifyingRequest::from).collect(),
        }
    }

    fn num_subrequests(&self) -> usize {
        self.requests
            .iter()
            .map(|request| request.subrequests.len())
            .sum()
    }

    fn collect_requests(&self) -> Vec<MethodRequest> {
        self.requests
            .iter()
            .flat_map(|request| request.subrequests.iter().cloned())
            .collect()
    }

    fn validate_responses(
        self,
        start_version: Version,
        state: &State,
        state_proof: &StateProof,
        responses: Vec<Result<Response<MethodResponse>>>,
    ) -> Result<Vec<Result<Response<MethodResponse>>>> {
        let num_subrequests = self.num_subrequests();
        if num_subrequests != responses.len() {
            return Err(Error::rpc_response(format!(
                "expected {} responses, received {} responses in batch",
                num_subrequests,
                responses.len()
            )));
        }

        for response in responses.iter().flatten() {
            if response.state() != state {
                return Err(Error::rpc_response(format!(
                    "expected all responses in batch to have the same metadata: {:?}, \
                         received unexpected response metadata: {:?}",
                    state,
                    response.state(),
                )));
            }
        }

        let mut responses_iter = responses.into_iter();

        Ok(self
            .requests
            .into_iter()
            .map(|request| {
                let n = request.subrequests.len();
                let subresponses = responses_iter.by_ref().take(n).collect();
                request.validate_subresponses(start_version, state, state_proof, subresponses)
            })
            .collect())
    }
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
            MethodRequest::Submit((txn,)) => verifying_submit(txn),
            MethodRequest::GetMetadata((None,)) => verifying_get_latest_metadata(),
            MethodRequest::GetMetadata((Some(version),)) => {
                verifying_get_historical_metadata(version)
            }
            MethodRequest::GetAccount(address, version) => verifying_get_account(address, version),
            MethodRequest::GetTransactions(start_version, limit, include_events) => {
                verifying_get_transactions(start_version, limit, include_events)
            }
            MethodRequest::GetAccountTransactions(
                address,
                start_seq_num,
                limit,
                include_events,
            ) => verifying_get_account_transactions(address, start_seq_num, limit, include_events),
            MethodRequest::GetAccountTransaction(address, seq_num, include_events) => {
                verifying_get_account_transaction(address, seq_num, include_events)
            }
            MethodRequest::GetEvents(key, start_seq, limit) => {
                verifying_get_events(key, start_seq, limit)
            }
            MethodRequest::GetCurrencies([]) => verifying_get_currencies(),
            MethodRequest::GetNetworkStatus([]) => verifying_get_network_status(),
            _ => todo!(),
        }
    }
}

// TODO(philiphayes): add separate type for each MethodRequest? like:
//
// ```
// struct GetAccount((address,));
//
// enum MethodRequest {
//     GetAccount(GetAccount),
//     // ..
// }
// ```
//
// would allow the from(MethodRequest) above to call a method on the enum inner
// instead of these ad-hoc methods i think

fn verifying_submit(txn: String) -> VerifyingRequest {
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

fn verifying_get_latest_metadata() -> VerifyingRequest {
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

fn verifying_get_historical_metadata(version: Version) -> VerifyingRequest {
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

fn verifying_get_account(address: AccountAddress, version: Option<Version>) -> VerifyingRequest {
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

fn verifying_get_transactions(
    start_version: Version,
    limit: u64,
    include_events: bool,
) -> VerifyingRequest {
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

fn verifying_get_account_transactions(
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

fn verifying_get_account_transaction(
    address: AccountAddress,
    seq_num: u64,
    include_events: bool,
) -> VerifyingRequest {
    verifying_get_account_transactions(address, seq_num, 1, include_events).map(
        |_ctxt, response| match response {
            MethodResponse::GetAccountTransactions(txns) => {
                MethodResponse::GetAccountTransaction(txns.into_iter().next())
            }
            response => panic!(
                "expected GetAccountTransactions response, got: {:?}",
                response
            ),
        },
    )
}

fn verifying_get_events(key: EventKey, start_seq: u64, limit: u64) -> VerifyingRequest {
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

fn verifying_get_currencies() -> VerifyingRequest {
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

fn verifying_get_network_status() -> VerifyingRequest {
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

mod private {
    pub trait Sealed {}

    impl Sealed for super::InMemoryStorage {}
}

// TODO(philiphayes): unseal `Storage` trait once verifying client stabilizes.
pub trait Storage: private::Sealed + Debug {
    fn get(&self, key: &str) -> Result<Vec<u8>>;
    fn set(&mut self, key: &str, value: Vec<u8>) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct InMemoryStorage {
    data: HashMap<String, Vec<u8>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Storage for InMemoryStorage {
    fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.data
            .get(key)
            .map(Clone::clone)
            .ok_or_else(|| Error::unknown("key not set"))
    }

    fn set(&mut self, key: &str, value: Vec<u8>) -> Result<()> {
        self.data.insert(key.to_owned(), value);
        Ok(())
    }
}

pub const TRUSTED_STATE_KEY: &str = "trusted_state";

#[derive(Debug)]
struct TrustedStateStore<S> {
    trusted_state: TrustedState,
    storage: S,
}

impl<S: Storage> TrustedStateStore<S> {
    fn new(storage: S) -> Result<Self> {
        let trusted_state = storage
            .get(TRUSTED_STATE_KEY)
            .and_then(|bytes| bcs::from_bytes(&bytes).map_err(Error::decode))?;

        Ok(Self {
            trusted_state,
            storage,
        })
    }

    fn new_with_state(trusted_state: TrustedState, storage: S) -> Self {
        let maybe_stored_state: Result<TrustedState> = storage
            .get(TRUSTED_STATE_KEY)
            .and_then(|bytes| bcs::from_bytes(&bytes).map_err(Error::decode));

        let trusted_state = if let Ok(stored_state) = maybe_stored_state {
            if trusted_state.version() > stored_state.version() {
                trusted_state
            } else {
                stored_state
            }
        } else {
            trusted_state
        };

        Self {
            trusted_state,
            storage,
        }
    }

    fn version(&self) -> Version {
        self.trusted_state.version()
    }

    fn waypoint(&self) -> Waypoint {
        self.trusted_state.waypoint()
    }

    fn trusted_state(&self) -> &TrustedState {
        &self.trusted_state
    }

    fn ratchet(&mut self, new_state: TrustedState) -> Result<()> {
        // We only need to store the potential new trusted state if it's actually
        // ahead of what we have stored locally.
        if new_state.version() > self.version() {
            self.trusted_state = new_state;
            let trusted_state_bytes = bcs::to_bytes(&self.trusted_state).map_err(Error::decode)?;
            self.storage.set(TRUSTED_STATE_KEY, trusted_state_bytes)?;
        }
        Ok(())
    }
}
