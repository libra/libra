// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use diem_faucet::mint;
use diem_logger::prelude::info;
use diem_sdk::types::chain_id::ChainId;
use std::fmt;
use structopt::StructOpt;
use warp::Filter;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Diem Faucet",
    author = "The Diem Association",
    about = "Diem Testnet utitlty service for creating test account and minting test coins"
)]
struct Args {
    /// Faucet service listen address
    #[structopt(short = "a", long, default_value = "127.0.0.1")]
    pub address: String,
    /// Faucet service listen port
    #[structopt(short = "p", long, default_value = "80")]
    pub port: u16,
    /// Diem fullnode/validator server URL
    #[structopt(short = "s", long, default_value = "https://testnet.diem.com/v1")]
    pub server_url: String,
    /// Path to the private key for creating test account and minting coins.
    /// To keep Testnet simple, we used one private key for both treasury compliance account and testnet
    /// designated dealer account, hence here we only accept one private key.
    /// To manually generate a keypair, use generate-key:
    /// `cargo run -p generate-keypair -- -o <output_file_path>`
    #[structopt(short = "m", long, default_value = "/opt/diem/etc/mint.key")]
    pub mint_key_file_path: String,
    /// Chain ID of the network this client is connecting to.
    /// For mainnet: \"MAINNET\" or 1, testnet: \"TESTNET\" or 2, devnet: \"DEVNET\" or 3, \
    /// local swarm: \"TESTING\" or 4
    /// Note: Chain ID of 0 is not allowed; Use number if chain id is not predefined.
    #[structopt(short = "c", long, default_value = "2")]
    pub chain_id: ChainId,
}

#[tokio::main]
async fn main() {
    let args = Args::from_args();
    diem_logger::Logger::new().init();

    let address: std::net::SocketAddr = format!("{}:{}", args.address, args.port)
        .parse()
        .expect("invalid address or port number");

    info!(
        "[faucet]: chain id: {}, server url: {}",
        args.chain_id,
        args.server_url.as_str(),
    );
    let service = std::sync::Arc::new(mint::Service::new(
        args.server_url,
        args.chain_id,
        args.mint_key_file_path,
    ));

    info!("[faucet]: running on: {}", address);
    warp::serve(routes(service)).run(address).await;
}

fn routes(
    service: std::sync::Arc<mint::Service>,
) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
    let mint = warp::any()
        .and(warp::post())
        .and(warp::any().map(move || std::sync::Arc::clone(&service)))
        .and(warp::query().map(move |params: mint::MintParams| params))
        .and_then(handle)
        .with(warp::log::custom(|info| {
            info!(
                "{} \"{} {} {:?}\" {} \"{}\" \"{}\" {:?}",
                OptFmt(info.remote_addr()),
                info.method(),
                info.path(),
                info.version(),
                info.status().as_u16(),
                OptFmt(info.referer()),
                OptFmt(info.user_agent()),
                info.elapsed(),
            )
        }))
        .with(warp::cors().allow_any_origin().allow_methods(vec!["POST"]));

    // POST /?amount=25&auth_key=xxx&currency_code=XXX
    let route_root = warp::path::end().and(mint.clone());
    // POST /mint?amount=25&auth_key=xxx&currency_code=XXX
    let route_mint = warp::path::path("mint").and(warp::path::end()).and(mint);

    let health = warp::path!("-" / "healthy").map(|| "diem-faucet:ok");
    health.or(route_mint.or(route_root)).boxed()
}

async fn handle(
    service: std::sync::Arc<mint::Service>,
    params: mint::MintParams,
) -> Result<Box<dyn warp::Reply>, warp::Rejection> {
    match service.process(params).await {
        Ok(body) => Ok(Box::new(body.to_string())),
        Err(err) => Err(warp::reject::custom(ServerInternalError(err.to_string()))),
    }
}

struct OptFmt<T>(Option<T>);

impl<T: fmt::Display> fmt::Display for OptFmt<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(t) = &self.0 {
            fmt::Display::fmt(t, f)
        } else {
            f.write_str("-")
        }
    }
}

#[derive(Debug)]
struct ServerInternalError(String);

impl warp::reject::Reject for ServerInternalError {}

#[cfg(test)]
mod tests {
    use crate::routes;
    use diem_faucet::mint;
    use diem_infallible::RwLock;
    use diem_sdk::{
        transaction_builder::stdlib::{ScriptCall, ScriptFunctionCall},
        types::{
            account_address::AccountAddress,
            chain_id::ChainId,
            diem_id_identifier::DiemIdVaspDomainIdentifier,
            transaction::{
                metadata::{CoinTradeMetadata, Metadata},
                SignedTransaction, TransactionPayload,
                TransactionPayload::Script,
            },
        },
    };
    use std::{collections::HashMap, convert::TryFrom, sync::Arc};
    use warp::Filter;

    fn setup(
        accounts: Arc<RwLock<HashMap<AccountAddress, serde_json::Value>>>,
    ) -> Arc<mint::Service> {
        let f = tempfile::NamedTempFile::new()
            .unwrap()
            .into_temp_path()
            .to_path_buf();
        generate_key::generate_and_save_key(&f);

        let chain_id = ChainId::test();

        let stub = warp::any()
            .and(warp::body::json())
            .map(move |req: serde_json::Value| {
                let resp = handle_request(req, chain_id, Arc::clone(&accounts));
                Ok(warp::reply::json(&resp))
            });
        let port = diem_config::utils::get_available_port();
        let future = warp::serve(stub).bind(([127, 0, 0, 1], port));
        tokio::task::spawn(async move { future.await });

        let service = mint::Service::new(
            format!("http://localhost:{}/v1", port),
            chain_id,
            f.to_str().unwrap().to_owned(),
        );
        Arc::new(service)
    }

    #[tokio::test]
    async fn test_healthy() {
        let accounts = genesis_accounts();
        let service = setup(accounts);
        let filter = routes(service);
        let resp = warp::test::request()
            .method("GET")
            .path("/-/healthy")
            .reply(&filter)
            .await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.body(), "diem-faucet:ok");
    }

    #[tokio::test]
    async fn test_mint() {
        let accounts = genesis_accounts();
        let service = setup(accounts.clone());
        let filter = routes(service);

        // auth_key is outside of the loop for minting same account multiple
        // times, it should success and should not create same account multiple
        // times.
        let auth_key = "459c77a38803bd53f3adee52703810e3a74fd7c46952c497e75afb0a7932586d";
        let amount = 13345;
        for (i, path) in ["/", "/mint"].iter().enumerate() {
            let resp = warp::test::request()
                .method("POST")
                .path(
                    format!(
                        "{}?auth_key={}&amount={}&currency_code=XDX",
                        path, auth_key, amount
                    )
                    .as_str(),
                )
                .reply(&filter)
                .await;
            assert_eq!(resp.body(), (i + 1).to_string().as_str());
            let reader = accounts.read();
            let addr =
                AccountAddress::try_from("a74fd7c46952c497e75afb0a7932586d".to_owned()).unwrap();
            let account = reader.get(&addr).expect("account should be created");
            assert_eq!(account["balances"][0]["amount"], amount);
        }
    }

    #[tokio::test]
    async fn test_mint_with_txns_response() {
        let accounts = genesis_accounts();
        let service = setup(accounts.clone());
        let filter = routes(service);

        let auth_key = "459c77a38803bd53f3adee52703810e3a74fd7c46952c497e75afb0a7932586d";
        let amount = 13345;
        let trade_id = "11111111-1111-1111-1111-111111111111";
        let resp = warp::test::request()
            .method("POST")
            .path(
                format!(
                    "/mint?auth_key={}&amount={}&trade_id={}&currency_code=XDX&return_txns=true",
                    auth_key, amount, trade_id
                )
                .as_str(),
            )
            .reply(&filter)
            .await;
        let body = resp.body();
        let txns: Vec<SignedTransaction> =
            bcs::from_bytes(&hex::decode(body).expect("hex encoded response body"))
                .expect("valid bcs vec");
        assert_eq!(txns.len(), 2);

        // ensure if we provide a trade_id, it will end up in the metadata
        let trade_ids = get_trade_ids_from_payload(txns[1].payload());
        assert_eq!(trade_ids.len(), 1);
        assert_eq!(trade_ids[0], trade_id);

        let reader = accounts.read();
        let addr = AccountAddress::try_from("a74fd7c46952c497e75afb0a7932586d".to_owned()).unwrap();
        let account = reader.get(&addr).expect("account should be created");
        assert_eq!(account["balances"][0]["amount"], amount);
        assert_eq!(account["role"]["type"], "parent_vasp");
    }

    #[tokio::test]
    async fn test_mint_dd_account_with_txns_response() {
        let accounts = genesis_accounts();
        let service = setup(accounts.clone());
        let filter = routes(service);

        let auth_key = "44b8f03f203ec45dbd7484e433752efe54aa533116e934f8a50c28bece06d3ac";
        let amount = 13345;
        let resp = warp::test::request()
            .method("POST")
            .path(
                format!(
                    "/mint?auth_key={}&amount={}&currency_code=XDX&return_txns=true&is_designated_dealer=true",
                    auth_key, amount
                )
                    .as_str(),
            )
            .reply(&filter)
            .await;
        let body = resp.body();
        let txns: Vec<SignedTransaction> =
            bcs::from_bytes(&hex::decode(body).expect("hex encoded response body"))
                .expect("valid bcs vec");
        assert_eq!(txns.len(), 2);

        let reader = accounts.read();
        let addr = AccountAddress::try_from("54aa533116e934f8a50c28bece06d3ac".to_owned()).unwrap();
        let account = reader.get(&addr).expect("account should be created");
        assert_eq!(account["balances"][0]["amount"], amount);
        assert_eq!(account["role"]["type"], "designated_dealer");
    }

    #[tokio::test]
    async fn test_mint_invalid_auth_key() {
        let accounts = genesis_accounts();
        let service = setup(accounts);
        let filter = routes(service);

        let auth_key = "invalid-auth-key";
        let resp = warp::test::request()
            .method("POST")
            .path(
                format!(
                    "/mint?auth_key={}&amount=1000000&currency_code=XDX",
                    auth_key
                )
                .as_str(),
            )
            .reply(&filter)
            .await;
        assert_eq!(resp.body(), "Invalid query string");
    }

    #[tokio::test]
    async fn test_mint_fullnode_error() {
        let accounts = Arc::new(RwLock::new(HashMap::new()));
        let service = setup(accounts);
        let filter = routes(service);

        let auth_key = "459c77a38803bd53f3adee52703810e3a74fd7c46952c497e75afb0a7932586d";
        let resp = warp::test::request()
            .method("POST")
            .path(
                format!(
                    "/mint?auth_key={}&amount=1000000&currency_code=XDX",
                    auth_key
                )
                .as_str(),
            )
            .reply(&filter)
            .await;
        assert_eq!(
            resp.body(),
            "Unhandled rejection: ServerInternalError(\"treasury compliance account not found\")"
        );
    }

    #[tokio::test]
    async fn test_diem_id_domain() {
        let accounts = genesis_accounts();
        let service = setup(accounts.clone());
        let filter = routes(service);

        // auth_key is outside of the loop for minting same account multiple
        // times, it should success and should not create same account multiple
        // times.
        let auth_key = "459c77a38803bd53f3adee52703810e3a74fd7c46952c497e75afb0a7932586d";
        let diem_id_domain = DiemIdVaspDomainIdentifier::new("diem").unwrap();

        // Test adding a domain
        {
            let resp = warp::test::request()
                .method("POST")
                .path(
                    format!(
                        "/mint?auth_key={}&diem_id_domain={}&is_remove_domain={}&amount=1&currency_code=XDX",
                        auth_key, "diem", false,
                    )
                    .as_str(),
                )
                .reply(&filter)
                .await;
            assert_eq!(resp.body(), 1.to_string().as_str());
            let reader = accounts.read();
            let addr =
                AccountAddress::try_from("a74fd7c46952c497e75afb0a7932586d".to_owned()).unwrap();
            let account = reader.get(&addr).expect("account should be created");
            assert_eq!(
                account["role"]["diem_id_domains"][0],
                serde_json::json!(diem_id_domain),
            );
        }

        // Test adding same domain again does not change the account's domain list
        {
            let resp = warp::test::request()
                .method("POST")
                .path(
                    format!(
                        "/mint?auth_key={}&diem_id_domain={}&is_remove_domain={}&amount=1&currency_code=XDX",
                        auth_key, "diem", false,
                    )
                        .as_str(),
                )
                .reply(&filter)
                .await;
            assert_eq!(resp.body(), 2.to_string().as_str());
            let reader = accounts.read();
            let addr =
                AccountAddress::try_from("a74fd7c46952c497e75afb0a7932586d".to_owned()).unwrap();

            let account = reader.get(&addr).expect("account should be created");
            assert_eq!(
                account["role"]["diem_id_domains"].as_array().unwrap().len(),
                1
            );
        }

        // Test removing a domain
        {
            let diem_id_domain_to_remove = "diem";
            let resp = warp::test::request()
                .method("POST")
                .path(
                    format!(
                        "/mint?auth_key={}&diem_id_domain={}&is_remove_domain={}&amount=1&currency_code=XDX",
                        auth_key, diem_id_domain_to_remove, true,
                    )
                        .as_str(),
                )
                .reply(&filter)
                .await;
            assert_eq!(resp.body(), 3.to_string().as_str());
            let reader = accounts.read();
            let addr =
                AccountAddress::try_from("a74fd7c46952c497e75afb0a7932586d".to_owned()).unwrap();
            let account = reader.get(&addr).expect("account should be created");
            assert_eq!(account["role"]["diem_id_domains"], serde_json::json!([]));
        }
    }

    fn get_trade_ids_from_payload(payload: &TransactionPayload) -> Vec<String> {
        match payload {
            Script(script) => match ScriptCall::decode(script) {
                Some(ScriptCall::PeerToPeerWithMetadata { metadata, .. }) => {
                    match bcs::from_bytes(&metadata).expect("should decode metadata") {
                        Metadata::CoinTradeMetadata(CoinTradeMetadata::CoinTradeMetadataV0(
                            coin_trade_metadata,
                        )) => coin_trade_metadata.trade_ids,
                        _ => panic!("unexpected type of transaction metadata"),
                    }
                }
                _ => panic!("unexpected type of script"),
            },
            _ => panic!("unexpected payload type"),
        }
    }

    fn handle_request(
        req: serde_json::Value,
        chain_id: ChainId,
        accounts: Arc<RwLock<HashMap<AccountAddress, serde_json::Value>>>,
    ) -> serde_json::Value {
        if let serde_json::Value::Array(reqs) = req {
            return reqs
                .iter()
                .map(move |req| handle_request(req.clone(), chain_id, Arc::clone(&accounts)))
                .collect();
        }
        match req["method"].as_str() {
            Some("submit") => {
                let raw: &str = req["params"][0].as_str().unwrap();
                let txn: SignedTransaction = bcs::from_bytes(&hex::decode(raw).unwrap()).unwrap();
                assert_eq!(txn.chain_id(), chain_id);
                if let Script(script) = txn.payload() {
                    match ScriptCall::decode(script) {
                        Some(ScriptCall::CreateParentVaspAccount {
                            new_account_address: address,
                            ..
                        }) => {
                            let mut writer = accounts.write();
                            let previous = writer
                                .insert(address, create_vasp_account(&address.to_string(), 0));
                            assert!(previous.is_none(), "should not create account twice");
                        }
                        Some(ScriptCall::CreateDesignatedDealer { addr: address, .. }) => {
                            let mut writer = accounts.write();
                            let previous =
                                writer.insert(address, create_dd_account(&address.to_string(), 0));
                            assert!(previous.is_none(), "should not create account twice");
                        }
                        Some(ScriptCall::PeerToPeerWithMetadata { payee, amount, .. }) => {
                            let mut writer = accounts.write();
                            let account =
                                writer.get_mut(&payee).expect("account should be created");
                            account["balances"][0]["amount"] = serde_json::json!(amount);
                        }
                        _ => panic!("unexpected type of script"),
                    }
                }
                if let Some(script_function) = ScriptFunctionCall::decode(txn.payload()) {
                    match script_function {
                        ScriptFunctionCall::AddDiemIdDomain {
                            address, domain, ..
                        } => {
                            let mut writer = accounts.write();
                            let account =
                                writer.get_mut(&address).expect("account should be created");
                            let domain = DiemIdVaspDomainIdentifier::new(
                                String::from_utf8(domain).unwrap().as_str(),
                            )
                            .unwrap();
                            let json_domain = &serde_json::json!(domain);
                            let index = account["role"]["diem_id_domains"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .position(|x| x == json_domain);
                            if index.is_none() {
                                account["role"]["diem_id_domains"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(serde_json::json!(domain));
                            }
                        }
                        ScriptFunctionCall::RemoveDiemIdDomain {
                            address, domain, ..
                        } => {
                            let mut writer = accounts.write();
                            let domain = DiemIdVaspDomainIdentifier::new(
                                String::from_utf8(domain).unwrap().as_str(),
                            )
                            .unwrap();
                            let json_domain = &serde_json::json!(domain);
                            let account =
                                writer.get_mut(&address).expect("account should be created");

                            let index = account["role"]["diem_id_domains"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .position(|x| x == json_domain)
                                .unwrap();
                            account["role"]["diem_id_domains"]
                                .as_array_mut()
                                .unwrap()
                                .remove(index);
                        }
                        _ => panic!("unexpected type of script"),
                    }
                }
                create_response(&req["id"], chain_id.id(), None)
            }
            Some("get_account") => {
                let address_string: String = req["params"][0].as_str().unwrap().to_owned();
                let reader = accounts.read();
                let address_lookup = AccountAddress::try_from(address_string)
                    .ok()
                    .and_then(|address| reader.get(&address));
                create_response(&req["id"], chain_id.id(), address_lookup)
            }
            _ => panic!("unexpected method"),
        }
    }

    fn create_response(
        id: &serde_json::Value,
        chain_id: u8,
        result: Option<&serde_json::Value>,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "jsonrpc": "2.0",
            "diem_chain_id": chain_id,
            "diem_ledger_timestampusec": 1599670083580598u64,
            "diem_ledger_version": 2052770,
            "result": result
        })
    }

    fn genesis_accounts() -> Arc<RwLock<HashMap<AccountAddress, serde_json::Value>>> {
        let mut accounts: HashMap<AccountAddress, serde_json::Value> = HashMap::new();
        let blessed = "0000000000000000000000000b1e55ed";
        accounts.insert(
            AccountAddress::try_from(blessed.to_owned()).unwrap(),
            create_account(
                blessed,
                serde_json::json!([]),
                serde_json::json!({
                    "type": "treasury_compliance"
                }),
            ),
        );
        let dd = "000000000000000000000000000000dd";
        accounts.insert(
            AccountAddress::try_from(dd.to_owned()).unwrap(),
            create_dd_account(dd, 4611685774556657903u64),
        );
        Arc::new(RwLock::new(accounts))
    }

    fn create_vasp_account(address: &str, amount: u64) -> serde_json::Value {
        create_account(
            address,
            serde_json::json!([{
                "amount": amount,
                "currency": "XDX"
            }]),
            serde_json::json!({
                "type": "parent_vasp",
                "human_name": "No. 0 VASP",
                "base_url": "",
                "expiration_time": 18446744073709551615u64,
                "compliance_key": "",
                "num_children": 0,
                "compliance_key_rotation_events_key": format!("0200000000000000{}", address),
                "base_url_rotation_events_key": format!("0300000000000000{}", address),
                "diem_id_domains": [],
            }),
        )
    }

    fn create_dd_account(address: &str, amount: u64) -> serde_json::Value {
        create_account(
            address,
            serde_json::json!([{
                "amount": amount,
                "currency": "XDX",
            }]),
            serde_json::json!({
                "base_url": "",
                "compliance_key": "",
                "expiration_time": 18446744073709551615u64,
                "human_name": "moneybags",
                "preburn_balances": [{
                    "amount": 0,
                    "currency": "XDX"
                }],
                "preburn_queues": [{
                    "currency": "XDX",
                    "preburns": [],
                }],
                "type": "designated_dealer",
                "compliance_key_rotation_events_key": format!("0200000000000000{}", address),
                "base_url_rotation_events_key": format!("0300000000000000{}", address),
                "received_mint_events_key": format!("0400000000000000{}", address)
            }),
        )
    }

    fn create_account(
        address: &str,
        balances: serde_json::Value,
        role: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "address": address,
            "balances": balances,
            "role": role,
            "authentication_key": format!("{}{}", address, address),
            "sent_events_key": format!("0000000000000000{}", address),
            "received_events_key": format!("0100000000000000{}", address),
            "delegated_key_rotation_capability": false,
            "delegated_withdrawal_capability": false,
            "is_frozen": false,
            "sequence_number": 0
        })
    }
}
