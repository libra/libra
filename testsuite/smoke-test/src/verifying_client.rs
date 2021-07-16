// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use diem_sdk::{
    client::{
        BlockingClient, Client, InMemoryStorage, MethodRequest, MethodResponse, Response, Result,
        VerifyingClient,
    },
    transaction_builder::Currency,
    types::{
        account_address::AccountAddress,
        account_config::constants::addresses::{
            diem_root_address, testnet_dd_account_address, treasury_compliance_account_address,
            validator_set_address,
        },
        epoch_change::EpochChangeProof,
        event::{EventHandle, EventKey},
        transaction::Version,
        trusted_state::TrustedState,
        waypoint::Waypoint,
        LocalAccount,
    },
};
use forge::{PublicUsageContext, PublicUsageTest, Result as ForgeResult, Test};
use proptest::{collection::vec, prelude::*, sample::select};
use std::cmp::max;
use tokio::runtime::Builder;

//TODO expose genesis transaction and genesis waypoint from Forge
fn verifying_client(json_rpc_endpoint: &str) -> ForgeResult<VerifyingClient<InMemoryStorage>> {
    let client = BlockingClient::new(json_rpc_endpoint);
    let epoch_change_proof: EpochChangeProof = bcs::from_bytes(
        client
            .get_state_proof(0)?
            .into_inner()
            .epoch_change_proof
            .inner(),
    )?;
    let waypoint = Waypoint::new_epoch_boundary(
        epoch_change_proof
            .ledger_info_with_sigs
            .last()
            .unwrap()
            .ledger_info(),
    )?;

    let trusted_state = TrustedState::from_epoch_waypoint(waypoint);
    let storage = InMemoryStorage::new();
    Ok(VerifyingClient::new_with_state(
        Client::new(json_rpc_endpoint),
        trusted_state,
        storage,
    ))
}

fn fund_new_account(ctx: &mut PublicUsageContext<'_>, amount: u64) -> ForgeResult<LocalAccount> {
    let account = ctx.random_account();
    ctx.create_parent_vasp_account(account.authentication_key())?;
    ctx.fund(account.address(), amount)?;

    Ok(account)
}

struct Environment {
    pub max_batch_size: usize,
    pub client: Client,
    pub verifying_client: VerifyingClient<InMemoryStorage>,
}

impl Environment {
    fn new(url: &str) -> Self {
        let client = Client::new(url);
        let verifying_client = verifying_client(url).unwrap();

        Self {
            max_batch_size: 20,
            client,
            verifying_client,
        }
    }

    fn latest_observed_version(&self) -> Version {
        let version_nv = self
            .client
            .last_known_state()
            .map(|state| state.version)
            .unwrap_or(0);
        let version_v = self.verifying_client.version();
        max(version_nv, version_v)
    }

    /// Send a request using both verifying and non-verifying clients.
    async fn request(
        &self,
        request: MethodRequest,
    ) -> (
        Result<Response<MethodResponse>>,
        Result<Response<MethodResponse>>,
    ) {
        let send_nv = self.client.request(request.clone());
        let send_v = self.verifying_client.request(request);

        tokio::join!(send_nv, send_v)
    }

    /// Send a request batch using both verifying and non-verifying clients.
    async fn batch(
        &self,
        batch: Vec<MethodRequest>,
    ) -> (
        Result<Vec<Result<Response<MethodResponse>>>>,
        Result<Vec<Result<Response<MethodResponse>>>>,
    ) {
        let send_nv = self.client.batch(batch.clone());
        let send_v = self.verifying_client.batch(batch);

        tokio::join!(send_nv, send_v)
    }

    /// Scan the chain for some event handles. This is not too complicated; we
    /// just look up the first few handle ids for each account that we know about.
    async fn scan_event_handles(&self, accounts: &[AccountAddress]) -> Vec<EventHandle> {
        let mut event_handles = Vec::new();

        for account in accounts {
            // scan for a few handle ids
            for id in 0..10 {
                // TODO(philiphayes): add Order to get_events to allow us to just
                // look up latest event.
                let key = EventKey::new_from_address(account, id);
                let start_seq = 0;
                let limit = 1000;
                let events = self
                    .client
                    .get_events(key, start_seq, limit)
                    .await
                    .unwrap()
                    .into_inner();

                let count = events.len() as u64;
                if count != 0 {
                    event_handles.push(EventHandle::new(key, count));
                }
            }
        }

        event_handles
    }
}

/// Running a request against a `VerifyingClient` and non-verifying `Client`
/// at the same state version should always return the same response.
fn assert_responses_equal(
    recv_nv: Result<Response<MethodResponse>>,
    recv_v: Result<Response<MethodResponse>>,
) {
    match (recv_nv, recv_v) {
        (Ok(resp_nv), Ok(resp_v)) => {
            let (inner_nv, state_nv) = resp_nv.into_parts();
            let (inner_v, state_v) = resp_v.into_parts();

            assert_eq!(state_nv.chain_id, state_v.chain_id);
            assert_eq!(inner_nv, inner_v);
        }
        (Err(_), Err(_)) => (),
        (recv_nv, recv_v) => {
            panic!(
                "client handling mismatch:\n\
                 1. non-verifying client response: {:?}\n\
                 2.     verifying client response: {:?}",
                recv_nv, recv_v,
            );
        }
    }
}

/// Running a batch of requests against a `VerifyingClient` and non-verifying
/// `Client` at the same state version should always return the same responses.
fn assert_batches_equal(
    recv_nv: Result<Vec<Result<Response<MethodResponse>>>>,
    recv_v: Result<Vec<Result<Response<MethodResponse>>>>,
) {
    let (batch_nv, batch_v) = match (recv_nv, recv_v) {
        (Ok(batch_nv), Ok(batch_v)) => (batch_nv, batch_v),
        (Err(_), Err(_)) => return,
        (recv_nv, recv_v) => {
            panic!(
                "client batch handling mismatch:\n\
                 1. non-verifying client batch response: {:?}\n\
                 2.     verifying client batch response: {:?}",
                recv_nv, recv_v,
            );
        }
    };

    if batch_nv.len() != batch_v.len() {
        panic!(
            "clients returned different batch sizes: {} vs {}\n\
             1. non-verifying client batch: {:?}\n\
             2.     verifying client batch: {:?}",
            batch_nv.len(),
            batch_v.len(),
            batch_nv,
            batch_v,
        );
    }

    for (resp_nv, resp_v) in batch_nv.into_iter().zip(batch_v.into_iter()) {
        assert_responses_equal(resp_nv, resp_v);
    }
}

/// A `Strategy` for generating a `MethodRequest` at or before the given version
/// and querying from the given set of accounts.
fn arb_request(
    accounts: &[AccountAddress],
    event_handles: &[EventHandle],
    current_state_version: u64,
) -> impl Strategy<Value = MethodRequest> {
    let arb_account = select(accounts.to_owned());
    let arb_version = prop_oneof! [
        5 => Just(current_state_version),
        // query a historical version
        20 => 0u64..current_state_version,
        // occasionally choose an invalid version
        1 => Just(u64::MAX / 2),
    ];

    let arb_version_and_limit = arb_version.clone().prop_flat_map(move |start_version| {
        // We need to be careful how we choose our limit here, since both requests
        // are handled at different times. In order to avoid a race where
        // start_version..start_version+limit contains more transactions in the
        // second request, we constrain the max limit to always give a valid
        // response no matter the order/timing.
        let max_limit = current_state_version.saturating_sub(start_version) + 1;
        let arb_limit = prop_oneof! [
            // usually pick a normal limit
            20 => 1u64..=max_limit,
            // occasionally pick some weird limits
            1 => Just(0u64),
            1 => Just(u64::MAX / 2),
        ];
        (Just(start_version), arb_limit)
    });
    let arb_include_events = any::<bool>();

    let arb_event_handle = prop_oneof! [
        20 => select(event_handles.to_owned()),
        // occasionally choose some garbage handles
        1 => select(accounts.to_owned()).prop_map(|addr| {
            let key = EventKey::new_from_address(&addr, u64::MAX / 2);
            EventHandle::new(key, 1)
        }),
    ];
    // choose event queries that we know are valid at the time we scanned.
    let arb_events = arb_event_handle.prop_flat_map(|event_handle| {
        let num_events = event_handle.count();
        let arb_seq_num = 0..num_events;
        arb_seq_num.prop_flat_map(move |seq_num| {
            let max_limit = num_events - seq_num;
            let arb_limit = 1..=max_limit;
            (Just(*event_handle.key()), Just(seq_num), arb_limit)
        })
    });

    // we are not producing any transactions, so we don't need to worry about races
    // between verifying and non-verifying queries
    let arb_seq_num = prop_oneof! [
        10 => Just(0u64),
        10 => 1u64..50,
        1 => Just(u64::MAX / 2),
    ];
    let arb_limit = prop_oneof! [
        20 => 1u64..100,
        1 => Just(0u64),
        1 => Just(u64::MAX / 2),
    ];
    let arb_acct_txns = (
        arb_account.clone(),
        arb_seq_num.clone(),
        arb_limit,
        arb_include_events,
    );
    let arb_acct_txn = (arb_account.clone(), arb_seq_num, arb_include_events);

    let arb_metadata_version = prop_oneof! [
        // note: the exclusive upper bound is intentional so we don't get super
        // unlucky and call get_metadata(current_state_version) on a ledger state
        // with the same version.
        20 => 0u64..current_state_version,
        1 => Just(u64::MAX / 2),
        1 => Just(u64::MAX),
    ];

    prop_oneof![
        arb_metadata_version.prop_map(MethodRequest::get_metadata_by_version),
        (arb_account, arb_version).prop_map(|(a, v)| MethodRequest::GetAccount(a, Some(v))),
        (arb_version_and_limit, arb_include_events)
            .prop_map(|((v, l), i)| MethodRequest::GetTransactions(v, l, i)),
        arb_acct_txns.prop_map(|(a, s, l, i)| MethodRequest::GetAccountTransactions(a, s, l, i)),
        arb_acct_txn.prop_map(|(a, s, i)| MethodRequest::GetAccountTransaction(a, s, i)),
        arb_events.prop_map(|(k, s, l)| MethodRequest::GetEvents(k, s, l)),
        Just(MethodRequest::get_currencies()),
    ]
}

/// A `Strategy` for generating a batch of `MethodRequest`s with the added restriction
/// that it will still be accepted by the JSON-RPC server after going through the
/// VerifyingClient request transformation.
fn arb_batch(
    max_batch_size: usize,
    accounts: &[AccountAddress],
    event_handles: &[EventHandle],
    current_state_version: u64,
    verifying_client: VerifyingClient<InMemoryStorage>,
) -> impl Strategy<Value = Vec<MethodRequest>> {
    vec(
        arb_request(accounts, event_handles, current_state_version),
        1..max_batch_size,
    )
    .prop_filter(
        "batch rejected: actual size too large; won't be accepted by the JSON-RPC server",
        move |batch| {
            let actual_batch_size = verifying_client.actual_batch_size(batch.as_slice());
            actual_batch_size <= max_batch_size
        },
    )
}

pub struct VerifyingClientEquivalence;

impl Test for VerifyingClientEquivalence {
    fn name(&self) -> &'static str {
        "smoke-test::verifying-client-equivalence"
    }
}

impl PublicUsageTest for VerifyingClientEquivalence {
    fn run<'t>(&self, ctx: &mut PublicUsageContext<'t>) -> ForgeResult<()> {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let env = Environment::new(ctx.url());

        // Accounts we can query from
        let accounts = vec![
            // Some standard diem accounts
            diem_root_address(),
            validator_set_address(),
            treasury_compliance_account_address(),
            testnet_dd_account_address(),
            // Fund some new accounts
            fund_new_account(ctx, 1000)?.address(),
            fund_new_account(ctx, 2000)?.address(),
            fund_new_account(ctx, 3000)?.address(),
            // Some random, likely non-existent accounts
            AccountAddress::ZERO,
            AccountAddress::random(),
            AccountAddress::random(),
        ];

        // Scan the accounts for some event handles we can query from
        let event_handles = rt.block_on(env.scan_event_handles(&accounts));

        // Sync the verifying client
        rt.block_on(env.verifying_client.sync()).unwrap();

        // Generate random requests and ensure that both verifying and non-verifying
        // clients handle each request identically.
        let request_strategy =
            arb_request(&accounts, &event_handles, env.latest_observed_version());
        proptest!(|(request in request_strategy)| {
            let (recv_nv, recv_v) = rt.block_on(env.request(request));
            assert_responses_equal(recv_nv, recv_v);
        });

        // Do the same but with random request batches instead of single requests.
        let batch_strategy = arb_batch(
            env.max_batch_size,
            &accounts,
            &event_handles,
            env.latest_observed_version(),
            env.verifying_client.clone(),
        );
        proptest!(|(batch in batch_strategy)| {
            let (recv_nv, recv_v) = rt.block_on(env.batch(batch));
            assert_batches_equal(recv_nv, recv_v);
        });

        Ok(())
    }
}

pub struct VerifyingSubmit;

impl Test for VerifyingSubmit {
    fn name(&self) -> &'static str {
        "smoke-test::verifying-submit"
    }
}

impl PublicUsageTest for VerifyingSubmit {
    fn run<'t>(&self, ctx: &mut PublicUsageContext<'t>) -> ForgeResult<()> {
        let rt = Builder::new_current_thread().enable_all().build()?;

        let verifying_client = verifying_client(ctx.url())?;
        let factory = ctx.transaction_factory();

        let start_amount = 1_000_000;
        let transfer_amount = 100;
        let currency = Currency::XUS;

        let mut account_1 = ctx.random_account();
        ctx.create_parent_vasp_account(account_1.authentication_key())?;
        ctx.fund(account_1.address(), start_amount)?;

        let account_2 = ctx.random_account();
        ctx.create_parent_vasp_account(account_2.authentication_key())?;
        ctx.fund(account_2.address(), start_amount)?;

        rt.block_on(verifying_client.sync()).unwrap();

        let txn = account_1.sign_with_transaction_builder(factory.peer_to_peer(
            currency,
            account_2.address(),
            transfer_amount,
        ));

        rt.block_on(verifying_client.submit(&txn)).unwrap();
        rt.block_on(verifying_client.wait_for_signed_transaction(&txn, None, None))
            .unwrap();

        let account_view_1 = rt
            .block_on(verifying_client.get_account(account_1.address()))
            .unwrap()
            .into_inner()
            .unwrap();
        let balance_1 = account_view_1
            .balances
            .iter()
            .find(|b| b.currency == currency)
            .unwrap();

        let account_view_2 = rt
            .block_on(verifying_client.get_account(account_2.address()))
            .unwrap()
            .into_inner()
            .unwrap();
        let balance_2 = account_view_2
            .balances
            .iter()
            .find(|b| b.currency == currency)
            .unwrap();

        assert_eq!(balance_1.amount, start_amount - transfer_amount);
        assert_eq!(balance_2.amount, start_amount + transfer_amount);
        Ok(())
    }
}

pub struct VerifyingGetLatestMetadata;

impl Test for VerifyingGetLatestMetadata {
    fn name(&self) -> &'static str {
        "smoke-test::verifying-get-latest-metadata"
    }
}

impl PublicUsageTest for VerifyingGetLatestMetadata {
    fn run<'t>(&self, ctx: &mut PublicUsageContext<'t>) -> ForgeResult<()> {
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let env = Environment::new(ctx.url());

        rt.block_on(env.verifying_client.sync()).unwrap();

        let (resp_nv, resp_v) = rt.block_on(env.request(MethodRequest::get_metadata()));

        let meta_nv = resp_nv
            .unwrap()
            .into_inner()
            .try_into_get_metadata()
            .unwrap();
        let meta_v = resp_v
            .unwrap()
            .into_inner()
            .try_into_get_metadata()
            .unwrap();

        // only check that the "non-volatile" fields match up, since we're not 100%
        // guaranteed that these requests are fulfilled at the same exact version.

        assert_eq!(meta_nv.chain_id, meta_v.chain_id);
        assert_eq!(
            meta_nv.script_hash_allow_list,
            meta_v.script_hash_allow_list
        );
        assert_eq!(
            meta_nv.module_publishing_allowed,
            meta_v.module_publishing_allowed
        );
        assert_eq!(meta_nv.diem_version, meta_v.diem_version);
        assert_eq!(
            meta_nv.dual_attestation_limit,
            meta_v.dual_attestation_limit
        );

        Ok(())
    }
}
