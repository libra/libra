// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    request::{JsonRpcRequest, MethodRequest},
    response::{MethodResponse, Response},
    state::StateManager,
    validate, validate_batch, BatchResponse, USER_AGENT,
};
use crate::{
    error::WaitForTransactionError,
    move_deserialize::{self, Event},
    views::{
        AccountStateWithProofView, AccountView, AccumulatorConsistencyProofView, CurrencyInfoView,
        EventView, EventWithProofView, MetadataView, StateProofView, TransactionView,
        TransactionsWithProofsView, AccountRoleView, EventDataView,
    },
    Error, Result, Retry, State,
};
use diem_crypto::{hash::CryptoHash, HashValue};
use diem_types::{
    account_address::AccountAddress,
    event::EventKey,
    transaction::{SignedTransaction, Transaction},
    account_config::treasury_compliance_account_address,
};
use move_core_types::move_resource::{MoveResource, MoveStructType};
use reqwest::Client as ReqwestClient;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Client {
    url: String,
    inner: ReqwestClient,
    state: StateManager,
    retry: Retry,
}

impl Client {
    pub fn new<T: Into<String>>(url: T) -> Self {
        Self::new_with_retry(url, Retry::default())
    }

    pub fn new_with_retry<T: Into<String>>(url: T, retry: Retry) -> Self {
        let inner = ReqwestClient::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        Self {
            url: url.into(),
            inner,
            state: StateManager::new(),
            retry,
        }
    }

    pub fn last_known_state(&self) -> Option<State> {
        self.state.last_known_state()
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
            if let (Some(txn), state) = txn_resp.into_parts() {
                if txn.hash != txn_hash {
                    return Err(WaitForTransactionError::TransactionHashMismatchError(txn));
                }

                return Ok(Response::new(txn, state));
            }

            if let Some(state) = self.last_known_state() {
                if expiration_time_secs <= state.timestamp_usecs / 1_000_000 {
                    return Err(WaitForTransactionError::TransactionExpired);
                }
            }
            tokio::time::sleep(delay.unwrap_or(DEFAULT_DELAY)).await;
        }

        Err(WaitForTransactionError::Timeout)
    }

    pub async fn batch(
        &self,
        requests: Vec<MethodRequest>,
    ) -> Result<Vec<Result<Response<MethodResponse>>>> {
        self.send_batch(requests).await
    }

    pub async fn request(&self, request: MethodRequest) -> Result<Response<MethodResponse>> {
        let method = request.method();
        let resp: Response<serde_json::Value> = self.send(request).await?;
        resp.and_then(|json| MethodResponse::from_json(method, json).map_err(Error::decode))
    }

    pub async fn submit(&self, txn: &SignedTransaction) -> Result<Response<()>> {
        let request = JsonRpcRequest::new(MethodRequest::submit(txn).map_err(Error::request)?);
        self.send_without_retry(&request, true).await
    }

    pub async fn get_metadata_by_version(&self, version: u64) -> Result<Response<MetadataView>> {
        self.send(MethodRequest::get_metadata_by_version(version))
            .await
    }

    pub async fn get_metadata(&self) -> Result<Response<MetadataView>> {
        self.send(MethodRequest::get_metadata()).await
    }

    pub async fn get_account(
        &self,
        address: AccountAddress,
    ) -> Result<Response<Option<AccountView>>> {
        self.send(MethodRequest::get_account(address)).await
    }

    pub async fn get_account_by_version(
        &self,
        address: AccountAddress,
        version: u64,
    ) -> Result<Response<Option<AccountView>>> {
        self.send(MethodRequest::get_account_by_version(address, version))
            .await
    }

    pub async fn get_transactions(
        &self,
        start_seq: u64,
        limit: u64,
        include_events: bool,
    ) -> Result<Response<Vec<TransactionView>>> {
        self.send(MethodRequest::get_transactions(
            start_seq,
            limit,
            include_events,
        ))
        .await
    }

    pub async fn get_account_transaction(
        &self,
        address: AccountAddress,
        seq: u64,
        include_events: bool,
    ) -> Result<Response<Option<TransactionView>>> {
        self.send(MethodRequest::get_account_transaction(
            address,
            seq,
            include_events,
        ))
        .await
    }

    pub async fn get_account_transactions(
        &self,
        address: AccountAddress,
        start_seq: u64,
        limit: u64,
        include_events: bool,
    ) -> Result<Response<Vec<TransactionView>>> {
        self.send(MethodRequest::get_account_transactions(
            address,
            start_seq,
            limit,
            include_events,
        ))
        .await
    }

    pub async fn get_diem_id_domain_map(&self) -> Result<HashMap<String, AccountAddress>> {
        let mut domain_map = HashMap::new();
        let account = self.get_account(treasury_compliance_account_address()).await?.into_inner();
        if let Some(account) = account {
            if let AccountRoleView::TreasuryCompliance {  diem_id_domain_events_key } = account.role {
                let mut event_index = 0;
                let batch_size = 100;
                if let Some(key) = diem_id_domain_events_key {
                    loop {
                        let domain_events = self.get_events(key, event_index, batch_size).await?.into_inner();
                        for event in domain_events.iter() {
                            if let EventDataView::DiemIdDomain { removed, domain, address, .. } = event.clone().data {
                                if removed {
                                    domain_map.remove(&domain.as_str().to_string());
                                } else {
                                    domain_map.insert(domain.as_str().to_string(), address);
                                }
                            }
                        }
                        if domain_events.len() < batch_size as usize {
                            break;
                        }
                        event_index += batch_size;
                    }
                }
            };
        }
        return Ok(domain_map);
    }

    pub async fn get_events(
        &self,
        key: EventKey,
        start_seq: u64,
        limit: u64,
    ) -> Result<Response<Vec<EventView>>> {
        self.send(MethodRequest::get_events(key, start_seq, limit))
            .await
    }

    pub async fn get_currencies(&self) -> Result<Response<Vec<CurrencyInfoView>>> {
        self.send(MethodRequest::get_currencies()).await
    }

    pub async fn get_network_status(&self) -> Result<Response<u64>> {
        self.send(MethodRequest::get_network_status()).await
    }

    //
    // Experimental APIs
    //

    pub async fn get_state_proof(&self, from_version: u64) -> Result<Response<StateProofView>> {
        self.send(MethodRequest::get_state_proof(from_version))
            .await
    }

    pub async fn get_accumulator_consistency_proof(
        &self,
        client_known_version: Option<u64>,
        ledger_version: Option<u64>,
    ) -> Result<Response<AccumulatorConsistencyProofView>> {
        self.send(MethodRequest::get_accumulator_consistency_proof(
            client_known_version,
            ledger_version,
        ))
        .await
    }

    pub async fn get_account_state_with_proof(
        &self,
        address: AccountAddress,
        from_version: Option<u64>,
        to_version: Option<u64>,
    ) -> Result<Response<AccountStateWithProofView>> {
        self.send(MethodRequest::get_account_state_with_proof(
            address,
            from_version,
            to_version,
        ))
        .await
    }

    pub async fn get_transactions_with_proofs(
        &self,
        start_version: u64,
        limit: u64,
        include_events: bool,
    ) -> Result<Response<Option<TransactionsWithProofsView>>> {
        self.send(MethodRequest::get_transactions_with_proofs(
            start_version,
            limit,
            include_events,
        ))
        .await
    }

    pub async fn get_events_with_proofs(
        &self,
        key: EventKey,
        start_seq: u64,
        limit: u64,
    ) -> Result<Response<Vec<EventWithProofView>>> {
        self.send(MethodRequest::get_events_with_proofs(key, start_seq, limit))
            .await
    }

    /// Return the events of type `T` that have been emitted to `event_key` since `start_seq`, with a max of `limit`
    /// results
    /// Returns an empty vector if there are no such events
    /// The type `T` must match the event types associated with `event_key`
    pub async fn get_deserialized_events<T: MoveStructType + DeserializeOwned>(
        &self,
        event_key: &EventKey,
        start_seq: u64,
        limit: u64,
    ) -> Result<Response<Vec<Event<T>>>> {
        let (events, state) = self
            .get_events_with_proofs(*event_key, start_seq, limit)
            .await?
            .into_parts();
        Ok(Response::new(
            move_deserialize::get_events::<T>(events)?,
            state,
        ))
    }

    /// Deserialize and return the resource value of type `T` stored under `address`
    /// Returns None if there is no such value
    pub async fn get_deserialized_resource<T: MoveResource>(
        &self,
        address: AccountAddress,
    ) -> Result<Response<Option<T>>> {
        let (account, state) = self
            .get_account_state_with_proof(address, None, None)
            .await?
            .into_parts();
        Ok(Response::new(
            move_deserialize::get_resource(account)?,
            state,
        ))
    }

    //
    // Private Helpers
    //

    async fn send<T: DeserializeOwned>(&self, request: MethodRequest) -> Result<Response<T>> {
        let request = JsonRpcRequest::new(request);

        self.retry
            .retry_async(|| async { self.send_without_retry(&request, false).await })
            .await
    }

    async fn send_without_retry<T: DeserializeOwned>(
        &self,
        request: &JsonRpcRequest,
        ignore_stale: bool,
    ) -> Result<Response<T>> {
        let req_state = self.last_known_state();
        let resp: diem_json_rpc_types::response::JsonRpcResponse = self.send_impl(&request).await?;

        let (id, state, result) = validate(&self.state, req_state.as_ref(), &resp, ignore_stale)?;

        if request.id() != id {
            return Err(Error::rpc_response("invalid response id"));
        }

        let inner = serde_json::from_value(result).map_err(Error::decode)?;
        Ok(Response::new(inner, state))
    }

    async fn send_batch(
        &self,
        requests: Vec<MethodRequest>,
    ) -> Result<Vec<Result<Response<MethodResponse>>>> {
        let request: Vec<JsonRpcRequest> = requests.into_iter().map(JsonRpcRequest::new).collect();
        let req_state = self.last_known_state();
        let resp: BatchResponse = self.send_impl(&request).await?;

        let resp = resp.success()?;

        validate_batch(&self.state, req_state.as_ref(), &request, resp)
    }

    async fn send_impl<S: Serialize, T: DeserializeOwned>(&self, payload: &S) -> Result<T> {
        let response = self
            .inner
            .post(&self.url)
            .json(payload)
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .send()
            .await
            .map_err(Error::from_reqwest_error)?;

        if response.status() != 200 {
            return Err(Error::status(response.status().as_u16()));
        }

        response.json().await.map_err(Error::from_reqwest_error)
    }
}
