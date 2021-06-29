// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use anyhow::{ensure, format_err, Error, Result};
use diem_crypto::hash::{CryptoHash, HashValue};
use diem_transaction_builder::{error_explain, stdlib::ScriptCall};
use diem_types::{
    account_config::{
        AccountResource, AccountRole, AdminTransactionEvent, BalanceResource, BaseUrlRotationEvent,
        BurnEvent, CancelBurnEvent, ComplianceKeyRotationEvent, CreateAccountEvent,
        CurrencyInfoResource, DesignatedDealerPreburns, DiemIdDomainEvent, FreezingBit, MintEvent,
        NewBlockEvent, NewEpochEvent, PreburnEvent, ReceivedMintEvent, ReceivedPaymentEvent,
        SentPaymentEvent, ToXDXExchangeRateUpdateEvent,
    },
    account_state::AccountState,
    account_state_blob::{AccountStateBlob, AccountStateWithProof},
    contract_event::{ContractEvent, EventWithProof},
    diem_id_identifier::DiemIdVaspDomainIdentifier,
    epoch_change::EpochChangeProof,
    event::EventKey,
    ledger_info::LedgerInfoWithSignatures,
    proof::{
        AccountStateProof, AccumulatorConsistencyProof, SparseMerkleProof,
        TransactionAccumulatorProof, TransactionInfoWithProof, TransactionListProof,
    },
    transaction::{
        Script, ScriptFunction, Transaction, TransactionArgument, TransactionInfo,
        TransactionListWithProof, TransactionPayload,
    },
    vm_status::KeptVMStatus,
};
use hex::FromHex;
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::{StructTag, TypeTag},
    move_resource::MoveStructType,
    vm_status::AbortLocation,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct AmountView {
    pub amount: u64,
    pub currency: String,
}

impl AmountView {
    fn new(amount: u64, currency: &str) -> Self {
        Self {
            amount,
            currency: currency.to_string(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum AccountRoleView {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "child_vasp")]
    ChildVASP { parent_vasp_address: AccountAddress },
    #[serde(rename = "parent_vasp")]
    ParentVASP {
        human_name: String,
        base_url: String,
        expiration_time: u64,
        compliance_key: BytesView,
        num_children: u64,
        compliance_key_rotation_events_key: EventKey,
        base_url_rotation_events_key: EventKey,
        diem_id_domains: Option<Vec<DiemIdVaspDomainIdentifier>>,
    },
    #[serde(rename = "designated_dealer")]
    DesignatedDealer {
        human_name: String,
        base_url: String,
        expiration_time: u64,
        compliance_key: BytesView,
        preburn_balances: Vec<AmountView>,
        received_mint_events_key: EventKey,
        compliance_key_rotation_events_key: EventKey,
        base_url_rotation_events_key: EventKey,
        preburn_queues: Option<Vec<PreburnQueueView>>,
    },
    #[serde(rename = "treasury_compliance")]
    TreasuryCompliance {
        #[serde(skip_serializing_if = "Option::is_none")]
        diem_id_domain_events_key: Option<EventKey>,
    },
}

impl AccountRoleView {
    pub(crate) fn convert_preburn_balances(
        preburn_balances: DesignatedDealerPreburns,
    ) -> (Vec<AmountView>, Option<Vec<PreburnQueueView>>) {
        match preburn_balances {
            DesignatedDealerPreburns::Preburn(preburn_balances) => {
                let preburn_balances: Vec<_> = preburn_balances
                    .iter()
                    .map(|(currency_code, balance)| {
                        AmountView::new(balance.coin(), &currency_code.as_str())
                    })
                    .collect();
                let preburn_queues = preburn_balances
                    .iter()
                    .cloned()
                    .map(|amt_view| {
                        PreburnQueueView::new(
                            amt_view.currency.clone(),
                            vec![PreburnWithMetadataView {
                                preburn: amt_view,
                                metadata: None,
                            }],
                        )
                    })
                    .collect();
                (preburn_balances, Some(preburn_queues))
            }
            DesignatedDealerPreburns::PreburnQueue(preburn_queues) => {
                let preburn_balances = preburn_queues
                    .iter()
                    .map(|(currency_code, preburns)| {
                        let total_balance =
                            preburns.preburns().iter().fold(0, |acc: u64, preburn| {
                                acc.checked_add(preburn.preburn().coin()).unwrap()
                            });
                        AmountView::new(total_balance, &currency_code.as_str())
                    })
                    .collect();
                let preburn_queues = preburn_queues
                    .into_iter()
                    .map(|(currency_code, preburns)| {
                        PreburnQueueView::new(
                            currency_code.to_string(),
                            preburns
                                .preburns()
                                .iter()
                                .map(|preburn| PreburnWithMetadataView {
                                    preburn: AmountView::new(
                                        preburn.preburn().coin(),
                                        &currency_code.as_str(),
                                    ),
                                    metadata: Some(BytesView::new(preburn.metadata())),
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect();
                (preburn_balances, Some(preburn_queues))
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct AccountView {
    pub address: AccountAddress,
    pub balances: Vec<AmountView>,
    pub sequence_number: u64,
    pub authentication_key: BytesView,
    pub sent_events_key: EventKey,
    pub received_events_key: EventKey,
    pub delegated_key_rotation_capability: bool,
    pub delegated_withdrawal_capability: bool,
    pub is_frozen: bool,
    pub role: AccountRoleView,
    // the transaction version of the account data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

impl AccountView {
    pub fn new(
        address: AccountAddress,
        account: &AccountResource,
        balances: BTreeMap<Identifier, BalanceResource>,
        account_role: AccountRole,
        freezing_bit: FreezingBit,
        version: u64,
    ) -> Self {
        Self {
            address,
            balances: balances
                .iter()
                .map(|(currency_code, balance)| {
                    AmountView::new(balance.coin(), &currency_code.as_str())
                })
                .collect(),
            sequence_number: account.sequence_number(),
            authentication_key: BytesView::from(account.authentication_key()),
            sent_events_key: *account.sent_events().key(),
            received_events_key: *account.received_events().key(),
            delegated_key_rotation_capability: account.has_delegated_key_rotation_capability(),
            delegated_withdrawal_capability: account.has_delegated_withdrawal_capability(),
            is_frozen: freezing_bit.is_frozen(),
            role: AccountRoleView::from(account_role),
            version: Some(version),
        }
    }

    pub fn try_from_account_state(
        address: AccountAddress,
        account_state: AccountState,
        version: u64,
    ) -> Result<Self> {
        let account_resource = account_state
            .get_account_resource()?
            .ok_or_else(|| format_err!("invalid account state: no account resource"))?;
        let freezing_bit = account_state
            .get_freezing_bit()?
            .ok_or_else(|| format_err!("invalid account state: no freezing bit"))?;
        let account_role = account_state
            .get_account_role()?
            .ok_or_else(|| format_err!("invalid account state: no account role"))?;
        let balances = account_state.get_balance_resources()?;

        Ok(AccountView::new(
            address,
            &account_resource,
            balances,
            account_role,
            freezing_bit,
            version,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PreburnQueueView {
    pub currency: String,
    pub preburns: Vec<PreburnWithMetadataView>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PreburnWithMetadataView {
    pub preburn: AmountView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BytesView>,
}

impl PreburnQueueView {
    pub fn new(currency: String, preburns: Vec<PreburnWithMetadataView>) -> Self {
        Self { currency, preburns }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EventView {
    pub key: EventKey,
    pub sequence_number: u64,
    pub transaction_version: u64,
    pub data: EventDataView,
}

impl TryFrom<(u64, ContractEvent)> for EventView {
    type Error = Error;

    fn try_from((txn_version, event): (u64, ContractEvent)) -> Result<Self> {
        Ok(EventView {
            key: *event.key(),
            sequence_number: event.sequence_number(),
            transaction_version: txn_version,
            data: event.try_into()?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EventWithProofView {
    pub event_with_proof: BytesView,
}

impl TryFrom<&EventWithProofView> for EventWithProof {
    type Error = Error;

    fn try_from(view: &EventWithProofView) -> Result<Self> {
        Ok(bcs::from_bytes(&view.event_with_proof)?)
    }
}

impl TryFrom<&EventWithProof> for EventWithProofView {
    type Error = Error;

    fn try_from(event: &EventWithProof) -> Result<Self> {
        Ok(Self {
            event_with_proof: BytesView::from(bcs::to_bytes(event)?),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum EventDataView {
    #[serde(rename = "burn")]
    Burn {
        amount: AmountView,
        preburn_address: AccountAddress,
    },
    #[serde(rename = "cancelburn")]
    CancelBurn {
        amount: AmountView,
        preburn_address: AccountAddress,
    },
    #[serde(rename = "mint")]
    Mint { amount: AmountView },
    #[serde(rename = "to_xdx_exchange_rate_update")]
    ToXDXExchangeRateUpdate {
        currency_code: String,
        new_to_xdx_exchange_rate: f32,
    },
    #[serde(rename = "preburn")]
    Preburn {
        amount: AmountView,
        preburn_address: AccountAddress,
    },
    #[serde(rename = "receivedpayment")]
    ReceivedPayment {
        amount: AmountView,
        sender: AccountAddress,
        receiver: AccountAddress,
        metadata: BytesView,
    },
    #[serde(rename = "sentpayment")]
    SentPayment {
        amount: AmountView,
        receiver: AccountAddress,
        sender: AccountAddress,
        metadata: BytesView,
    },
    #[serde(rename = "admintransaction")]
    AdminTransaction { committed_timestamp_secs: u64 },
    #[serde(rename = "newepoch")]
    NewEpoch { epoch: u64 },
    #[serde(rename = "newblock")]
    NewBlock {
        round: u64,
        proposer: AccountAddress,
        proposed_time: u64,
    },
    #[serde(rename = "receivedmint")]
    ReceivedMint {
        amount: AmountView,
        destination_address: AccountAddress,
    },
    #[serde(rename = "compliancekeyrotation")]
    ComplianceKeyRotation {
        new_compliance_public_key: BytesView,
        time_rotated_seconds: u64,
    },
    #[serde(rename = "baseurlrotation")]
    BaseUrlRotation {
        new_base_url: String,
        time_rotated_seconds: u64,
    },
    #[serde(rename = "createaccount")]
    CreateAccount {
        created_address: AccountAddress,
        role_id: u64,
    },
    #[serde(rename = "diemiddomain")]
    DiemIdDomain {
        // Whether a domain was added or removed
        removed: bool,
        // Diem ID Domain string of the account
        domain: DiemIdVaspDomainIdentifier,
        // On-chain account address
        address: AccountAddress,
    },
    #[serde(rename = "unknown")]
    Unknown { bytes: Option<BytesView> },

    // used by client to deserialize server response
    #[serde(other)]
    UnknownToClient,
}

impl TryFrom<ContractEvent> for EventDataView {
    type Error = Error;

    fn try_from(event: ContractEvent) -> Result<Self> {
        let data = if event.type_tag() == &TypeTag::Struct(ReceivedPaymentEvent::struct_tag()) {
            let received_event = ReceivedPaymentEvent::try_from(&event)?;
            let amount_view = AmountView::new(
                received_event.amount(),
                received_event.currency_code().as_str(),
            );
            EventDataView::ReceivedPayment {
                amount: amount_view,
                sender: received_event.sender(),
                receiver: event.key().get_creator_address(),
                metadata: BytesView::from(received_event.metadata()),
            }
        } else if event.type_tag() == &TypeTag::Struct(SentPaymentEvent::struct_tag()) {
            let sent_event = SentPaymentEvent::try_from(&event)?;
            let amount_view =
                AmountView::new(sent_event.amount(), sent_event.currency_code().as_str());
            EventDataView::SentPayment {
                amount: amount_view,
                receiver: sent_event.receiver(),
                sender: event.key().get_creator_address(),
                metadata: BytesView::from(sent_event.metadata()),
            }
        } else if event.type_tag() == &TypeTag::Struct(PreburnEvent::struct_tag()) {
            let preburn_event = PreburnEvent::try_from(&event)?;
            let amount_view = AmountView::new(
                preburn_event.amount(),
                preburn_event.currency_code().as_str(),
            );
            EventDataView::Preburn {
                amount: amount_view,
                preburn_address: preburn_event.preburn_address(),
            }
        } else if event.type_tag() == &TypeTag::Struct(BurnEvent::struct_tag()) {
            let burn_event = BurnEvent::try_from(&event)?;
            let amount_view =
                AmountView::new(burn_event.amount(), burn_event.currency_code().as_str());
            EventDataView::Burn {
                amount: amount_view,
                preburn_address: burn_event.preburn_address(),
            }
        } else if event.type_tag() == &TypeTag::Struct(CancelBurnEvent::struct_tag()) {
            let cancel_burn_event = CancelBurnEvent::try_from(&event)?;
            let amount_view = AmountView::new(
                cancel_burn_event.amount(),
                cancel_burn_event.currency_code().as_str(),
            );
            EventDataView::CancelBurn {
                amount: amount_view,
                preburn_address: cancel_burn_event.preburn_address(),
            }
        } else if event.type_tag() == &TypeTag::Struct(ToXDXExchangeRateUpdateEvent::struct_tag()) {
            let update_event = ToXDXExchangeRateUpdateEvent::try_from(&event)?;
            EventDataView::ToXDXExchangeRateUpdate {
                currency_code: update_event.currency_code().to_string(),
                new_to_xdx_exchange_rate: update_event.new_to_xdx_exchange_rate(),
            }
        } else if event.type_tag() == &TypeTag::Struct(MintEvent::struct_tag()) {
            let mint_event = MintEvent::try_from(&event)?;
            let amount_view =
                AmountView::new(mint_event.amount(), mint_event.currency_code().as_str());
            EventDataView::Mint {
                amount: amount_view,
            }
        } else if event.type_tag() == &TypeTag::Struct(ReceivedMintEvent::struct_tag()) {
            let received_mint_event = ReceivedMintEvent::try_from(&event)?;
            let amount_view = AmountView::new(
                received_mint_event.amount(),
                received_mint_event.currency_code().as_str(),
            );
            EventDataView::ReceivedMint {
                amount: amount_view,
                destination_address: received_mint_event.destination_address(),
            }
        } else if event.type_tag() == &TypeTag::Struct(ComplianceKeyRotationEvent::struct_tag()) {
            let rotation_event = ComplianceKeyRotationEvent::try_from(&event)?;
            EventDataView::ComplianceKeyRotation {
                new_compliance_public_key: rotation_event.new_compliance_public_key().into(),
                time_rotated_seconds: rotation_event.time_rotated_seconds(),
            }
        } else if event.type_tag() == &TypeTag::Struct(BaseUrlRotationEvent::struct_tag()) {
            let rotation_event = BaseUrlRotationEvent::try_from(&event)?;
            String::from_utf8(rotation_event.new_base_url().to_vec())
                .map(|new_base_url| EventDataView::BaseUrlRotation {
                    new_base_url,
                    time_rotated_seconds: rotation_event.time_rotated_seconds(),
                })
                .map_err(|_| format_err!("Unable to parse BaseUrlRotationEvent"))?
        } else if event.type_tag() == &TypeTag::Struct(NewBlockEvent::struct_tag()) {
            let new_block_event = NewBlockEvent::try_from(&event)?;
            EventDataView::NewBlock {
                proposer: new_block_event.proposer(),
                round: new_block_event.round(),
                proposed_time: new_block_event.proposed_time(),
            }
        } else if event.type_tag() == &TypeTag::Struct(NewEpochEvent::struct_tag()) {
            let new_epoch_event = NewEpochEvent::try_from(&event)?;
            EventDataView::NewEpoch {
                epoch: new_epoch_event.epoch(),
            }
        } else if event.type_tag() == &TypeTag::Struct(CreateAccountEvent::struct_tag()) {
            let create_account_event = CreateAccountEvent::try_from(&event)?;
            let created_address = create_account_event.created();
            let role_id = create_account_event.role_id();
            EventDataView::CreateAccount {
                created_address,
                role_id,
            }
        } else if event.type_tag() == &TypeTag::Struct(AdminTransactionEvent::struct_tag()) {
            let admin_transaction_event = AdminTransactionEvent::try_from(&event)?;
            EventDataView::AdminTransaction {
                committed_timestamp_secs: admin_transaction_event.committed_timestamp_secs(),
            }
        } else if event.type_tag() == &TypeTag::Struct(DiemIdDomainEvent::struct_tag()) {
            let diem_id_domain_event = DiemIdDomainEvent::try_from(&event)?;
            EventDataView::DiemIdDomain {
                removed: diem_id_domain_event.removed(),
                domain: diem_id_domain_event.domain().domain().clone(),
                address: diem_id_domain_event.address(),
            }
        } else {
            EventDataView::Unknown {
                bytes: Some(event.event_data().into()),
            }
        };

        Ok(data)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct MetadataView {
    pub version: u64,
    pub accumulator_root_hash: HashValue,
    pub timestamp: u64,
    pub chain_id: u8,
    pub script_hash_allow_list: Option<Vec<HashValue>>,
    pub module_publishing_allowed: Option<bool>,
    pub diem_version: Option<u64>,
    pub dual_attestation_limit: Option<u64>,
}

#[derive(Clone, PartialEq)]
pub struct BytesView(Box<[u8]>);

impl BytesView {
    pub fn new<T: Into<Box<[u8]>>>(bytes: T) -> Self {
        Self(bytes.into())
    }

    pub fn into_inner(self) -> Box<[u8]> {
        self.0
    }

    pub fn inner(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for BytesView {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::convert::AsRef<[u8]> for BytesView {
    fn as_ref(&self) -> &[u8] {
        self.inner()
    }
}

impl std::fmt::Display for BytesView {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.inner() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for BytesView {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BytesView(\"{}\")", self)
    }
}

impl From<&[u8]> for BytesView {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl From<Vec<u8>> for BytesView {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }
}

impl<'de> Deserialize<'de> for BytesView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        <Vec<u8>>::from_hex(s)
            .map_err(D::Error::custom)
            .map(Into::into)
    }
}

impl Serialize for BytesView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hex::encode(self).serialize(serializer)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct MoveAbortExplanationView {
    pub category: String,
    pub category_description: String,
    pub reason: String,
    pub reason_description: String,
}

impl std::fmt::Display for MoveAbortExplanationView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Error Category: {}", self.category)?;
        writeln!(f, "\tCategory Description: {}", self.category_description)?;
        writeln!(f, "Error Reason: {}", self.reason)?;
        writeln!(f, "\tReason Description: {}", self.reason_description)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum VMStatusView {
    Executed,
    OutOfGas,
    MoveAbort {
        location: String,
        abort_code: u64,
        explanation: Option<MoveAbortExplanationView>,
    },
    ExecutionFailure {
        location: String,
        function_index: u16,
        code_offset: u16,
    },
    MiscellaneousError,
    VerificationError,
    DeserializationError,
    PublishingFailure,
}

impl VMStatusView {
    pub fn is_executed(&self) -> bool {
        matches!(self, Self::Executed)
    }
}

impl std::fmt::Display for VMStatusView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VMStatusView::Executed => write!(f, "Executed"),
            VMStatusView::OutOfGas => write!(f, "Out of Gas"),
            VMStatusView::MoveAbort {
                location,
                abort_code,
                explanation,
            } => {
                write!(f, "Move Abort: {} at {}", abort_code, location)?;
                if let Some(explanation) = explanation {
                    write!(f, "\nExplanation:\n{}", explanation)?
                }
                Ok(())
            }
            VMStatusView::ExecutionFailure {
                location,
                function_index,
                code_offset,
            } => write!(
                f,
                "Execution failure: {} {} {}",
                location, function_index, code_offset
            ),
            VMStatusView::MiscellaneousError => write!(f, "Miscellaneous Error"),
            VMStatusView::VerificationError => write!(f, "Verification Error"),
            VMStatusView::DeserializationError => write!(f, "Deserialization Error"),
            VMStatusView::PublishingFailure => write!(f, "Publishing Failure"),
        }
    }
}

impl From<&KeptVMStatus> for VMStatusView {
    fn from(status: &KeptVMStatus) -> Self {
        match status {
            KeptVMStatus::Executed => VMStatusView::Executed,
            KeptVMStatus::OutOfGas => VMStatusView::OutOfGas,
            KeptVMStatus::MoveAbort(loc, abort_code) => {
                let explanation = if let AbortLocation::Module(module_id) = loc {
                    error_explain::get_explanation(module_id, *abort_code).map(|context| {
                        MoveAbortExplanationView {
                            category: context.category.code_name,
                            category_description: context.category.code_description,
                            reason: context.reason.code_name,
                            reason_description: context.reason.code_description,
                        }
                    })
                } else {
                    None
                };

                VMStatusView::MoveAbort {
                    explanation,
                    location: loc.to_string(),
                    abort_code: *abort_code,
                }
            }
            KeptVMStatus::ExecutionFailure {
                location,
                function,
                code_offset,
            } => VMStatusView::ExecutionFailure {
                location: location.to_string(),
                function_index: *function,
                code_offset: *code_offset,
            },
            KeptVMStatus::MiscellaneousError => VMStatusView::MiscellaneousError,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TransactionView {
    pub version: u64,
    pub transaction: TransactionDataView,
    pub hash: HashValue,
    pub bytes: BytesView,
    pub events: Vec<EventView>,
    pub vm_status: VMStatusView,
    pub gas_used: u64,
}

impl TransactionView {
    pub fn try_from_tx_and_events(
        version: u64,
        tx: Transaction,
        tx_info: TransactionInfo,
        events: Vec<ContractEvent>,
    ) -> Result<Self> {
        let events = events
            .into_iter()
            .map(|event| EventView::try_from((version, event)))
            .collect::<Result<Vec<_>>>()?;

        Ok(TransactionView {
            version,
            hash: tx.hash(),
            bytes: BytesView::new(bcs::to_bytes(&tx)?),
            transaction: TransactionDataView::from(tx),
            events,
            vm_status: VMStatusView::from(tx_info.status()),
            gas_used: tx_info.gas_used(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TransactionListView(pub Vec<TransactionView>);

impl TransactionListView {
    pub fn empty() -> Self {
        Self(Vec::new())
    }
}

impl TryFrom<TransactionListWithProof> for TransactionListView {
    type Error = Error;

    fn try_from(txs: TransactionListWithProof) -> Result<Self, Self::Error> {
        if txs.is_empty() {
            return Ok(Self::empty());
        }
        let start_version = txs
            .first_transaction_version
            .ok_or_else(|| format_err!("expected a start version since tx list non-empty"))?;

        let transactions = txs.transactions;
        let transaction_infos = txs.proof.transaction_infos;

        ensure!(
            transaction_infos.len() == transactions.len(),
            "expected same number of transaction_infos as transactions, \
             received {} transaction_infos and {} transactions",
            transaction_infos.len(),
            transactions.len(),
        );

        let event_lists = if let Some(event_lists) = txs.events {
            ensure!(
                event_lists.len() == transactions.len(),
                "expected same number of event lists as transactions, \
                 received {} event lists and {} transactions",
                event_lists.len(),
                transactions.len(),
            );
            event_lists
        } else {
            vec![Vec::new(); transactions.len()]
        };

        let tx_iter = transactions.into_iter();
        let infos_iter = transaction_infos.into_iter();
        let event_lists_iter = event_lists.into_iter();

        let iter = tx_iter.enumerate().zip(infos_iter).zip(event_lists_iter);

        let tx_list = iter
            .map(|(((offset, tx), tx_info), tx_events)| {
                let version = start_version + offset as u64;
                TransactionView::try_from_tx_and_events(version, tx, tx_info, tx_events)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(TransactionListView(tx_list))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TransactionsWithProofsView {
    pub serialized_transactions: Vec<BytesView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serialized_events: Option<BytesView>,
    pub proofs: TransactionsProofsView,
}

impl TransactionsWithProofsView {
    pub fn try_into_txn_list_with_proof(
        &self,
        start_version: u64,
    ) -> Result<TransactionListWithProof> {
        let transactions = self
            .serialized_transactions
            .iter()
            .map(|tx| bcs::from_bytes::<Transaction>(tx.as_ref()))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        let events = self
            .serialized_events
            .as_ref()
            .map(|events| bcs::from_bytes::<Vec<Vec<ContractEvent>>>(events.as_ref()))
            .transpose()?;

        let first_transaction_version = if !transactions.is_empty() {
            Some(start_version)
        } else {
            None
        };

        Ok(TransactionListWithProof {
            transactions,
            events,
            first_transaction_version,
            proof: TransactionListProof::try_from(&self.proofs)?,
        })
    }
}

impl TryFrom<&TransactionListWithProof> for TransactionsWithProofsView {
    type Error = Error;

    fn try_from(txs: &TransactionListWithProof) -> Result<Self, Self::Error> {
        let serialized_transactions = txs
            .transactions
            .iter()
            .map(|tx| bcs::to_bytes(tx).map(BytesView::new))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        let serialized_events = txs
            .events
            .as_ref()
            .map(|events| bcs::to_bytes(events).map(BytesView::new))
            .transpose()?;

        Ok(TransactionsWithProofsView {
            serialized_transactions,
            serialized_events,
            proofs: TransactionsProofsView::try_from(&txs.proof)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TransactionsProofsView {
    pub ledger_info_to_transaction_infos_proof: BytesView,
    pub transaction_infos: BytesView,
}

impl TryFrom<&TransactionListProof> for TransactionsProofsView {
    type Error = Error;

    fn try_from(proof: &TransactionListProof) -> Result<Self, Self::Error> {
        Ok(TransactionsProofsView {
            ledger_info_to_transaction_infos_proof: BytesView::new(bcs::to_bytes(
                &proof.ledger_info_to_transaction_infos_proof,
            )?),
            transaction_infos: BytesView::new(bcs::to_bytes(&proof.transaction_infos)?),
        })
    }
}

impl TryFrom<&TransactionsProofsView> for TransactionListProof {
    type Error = Error;

    fn try_from(view: &TransactionsProofsView) -> Result<Self, Self::Error> {
        Ok(TransactionListProof {
            ledger_info_to_transaction_infos_proof: bcs::from_bytes(
                &view.ledger_info_to_transaction_infos_proof,
            )?,
            transaction_infos: bcs::from_bytes(&view.transaction_infos)?,
        })
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type")]
pub enum TransactionDataView {
    #[serde(rename = "blockmetadata")]
    BlockMetadata { timestamp_usecs: u64 },
    #[serde(rename = "writeset")]
    WriteSet {},
    #[serde(rename = "user")]
    UserTransaction {
        sender: AccountAddress,
        signature_scheme: String,
        signature: BytesView,
        public_key: BytesView,
        #[serde(skip_serializing_if = "Option::is_none")]
        secondary_signers: Option<Vec<AccountAddress>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        secondary_signature_schemes: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        secondary_signatures: Option<Vec<BytesView>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        secondary_public_keys: Option<Vec<BytesView>>,
        sequence_number: u64,
        chain_id: u8,
        max_gas_amount: u64,
        gas_unit_price: u64,
        gas_currency: String,
        expiration_timestamp_secs: u64,
        script_hash: HashValue,
        script_bytes: BytesView,
        script: ScriptView,
    },
    #[serde(rename = "unknown")]
    UnknownTransaction {},
}

impl From<Transaction> for TransactionDataView {
    fn from(tx: Transaction) -> Self {
        match tx {
            Transaction::BlockMetadata(t) => TransactionDataView::BlockMetadata {
                timestamp_usecs: t.timestamp_usec(),
            },
            Transaction::GenesisTransaction(_) => TransactionDataView::WriteSet {},
            Transaction::UserTransaction(t) => {
                let script_hash = match t.payload() {
                    TransactionPayload::Script(s) => HashValue::sha3_256_of(s.code()),
                    _ => HashValue::zero(),
                };

                let script_bytes: BytesView = match t.payload() {
                    TransactionPayload::Script(s) => bcs::to_bytes(s).unwrap_or_default(),
                    TransactionPayload::ScriptFunction(s) => bcs::to_bytes(s).unwrap_or_default(),
                    _ => vec![],
                }
                .into();

                let script: ScriptView = match t.payload() {
                    TransactionPayload::Script(s) => ScriptView::from(s),
                    TransactionPayload::ScriptFunction(s) => ScriptView::from(s),
                    _ => ScriptView::unknown(),
                };

                TransactionDataView::UserTransaction {
                    sender: t.sender(),
                    signature_scheme: t.authenticator().sender().scheme().to_string(),
                    signature: t.authenticator().sender().signature_bytes().into(),
                    public_key: t.authenticator().sender().public_key_bytes().into(),
                    secondary_signers: Some(t.authenticator().secondary_signer_addreses()),
                    secondary_signature_schemes: Some(
                        t.authenticator()
                            .secondary_signers()
                            .iter()
                            .map(|account_auth| account_auth.scheme().to_string())
                            .collect(),
                    ),
                    secondary_signatures: Some(
                        t.authenticator()
                            .secondary_signers()
                            .iter()
                            .map(|account_auth| account_auth.signature_bytes().into())
                            .collect(),
                    ),
                    secondary_public_keys: Some(
                        t.authenticator()
                            .secondary_signers()
                            .iter()
                            .map(|account_auth| account_auth.public_key_bytes().into())
                            .collect(),
                    ),
                    sequence_number: t.sequence_number(),
                    chain_id: t.chain_id().id(),
                    max_gas_amount: t.max_gas_amount(),
                    gas_unit_price: t.gas_unit_price(),
                    gas_currency: t.gas_currency_code().to_string(),
                    expiration_timestamp_secs: t.expiration_timestamp_secs(),
                    script_hash,
                    script_bytes,
                    script,
                }
            }
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ScriptView {
    // script name / type
    pub r#type: String,

    // script code bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<BytesView>,
    // script arguments, converted into string with type information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    // script function arguments, converted into hex encoded BCS bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments_bcs: Option<Vec<BytesView>>,
    // script type arguments, converted into string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_arguments: Option<Vec<String>>,

    // the following fields are legacy fields: maybe removed in the future
    // please move to use above fields

    // peer_to_peer_transaction, other known script name or unknown
    // because of a bug, we never rendered mint_transaction
    // this is deprecated, please switch to use field `name` which is script name

    // peer_to_peer_transaction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<AccountAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BytesView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_signature: Option<BytesView>,

    // Script functions
    // The address that the module is published under
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_address: Option<AccountAddress>,
    // The name of the module that the called function is defined in
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    // The (unqualified) name of the function being called.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
}

impl ScriptView {
    pub fn unknown() -> Self {
        ScriptView {
            r#type: "unknown".to_string(),
            ..Default::default()
        }
    }
}

impl From<&Script> for ScriptView {
    fn from(script: &Script) -> Self {
        let name = ScriptCall::decode(script)
            .map(|script_call| script_call.name().to_owned())
            .unwrap_or_else(|| "unknown".to_owned());
        let ty_args: Vec<String> = script
            .ty_args()
            .iter()
            .map(|type_tag| match type_tag {
                TypeTag::Struct(StructTag { module, .. }) => module.to_string(),
                tag => format!("{}", tag),
            })
            .collect();
        let mut view = ScriptView {
            r#type: name.clone(),
            code: Some(script.code().into()),
            arguments: Some(
                script
                    .args()
                    .iter()
                    .map(|arg| format!("{:?}", &arg))
                    .collect(),
            ),
            type_arguments: Some(ty_args.clone()),
            ..Default::default()
        };

        // handle legacy fields, backward compatible
        if name == "peer_to_peer_with_metadata" {
            if let [TransactionArgument::Address(receiver), TransactionArgument::U64(amount), TransactionArgument::U8Vector(metadata), TransactionArgument::U8Vector(metadata_signature)] =
                script.args()
            {
                view.receiver = Some(*receiver);
                view.amount = Some(*amount);
                view.currency = Some(
                    ty_args
                        .get(0)
                        .unwrap_or(&"unknown_currency".to_string())
                        .to_string(),
                );
                view.metadata = Some(BytesView::new(metadata.as_ref()));
                view.metadata_signature = Some(BytesView::new(metadata_signature.as_ref()));
            }
        }

        view
    }
}

impl From<&ScriptFunction> for ScriptView {
    fn from(script: &ScriptFunction) -> Self {
        let ty_args: Vec<String> = script
            .ty_args()
            .iter()
            .map(|type_tag| match type_tag {
                TypeTag::Struct(StructTag { module, .. }) => module.to_string(),
                tag => format!("{}", tag),
            })
            .collect();
        ScriptView {
            r#type: "script_function".to_string(),
            module_address: Some(*script.module().address()),
            module_name: Some(script.module().name().to_string()),
            function_name: Some(script.function().to_string()),
            arguments_bcs: Some(
                script
                    .args()
                    .iter()
                    .map(|arg| BytesView::from(arg.as_ref()))
                    .collect(),
            ),
            type_arguments: Some(ty_args),
            ..Default::default()
        }
    }
}

impl From<AccountRole> for AccountRoleView {
    fn from(role: AccountRole) -> Self {
        match role {
            AccountRole::Unknown => AccountRoleView::Unknown,
            AccountRole::ChildVASP(child_vasp) => AccountRoleView::ChildVASP {
                parent_vasp_address: child_vasp.parent_vasp_addr(),
            },
            AccountRole::ParentVASP {
                vasp,
                credential,
                diem_id_domains,
            } => {
                let domains =
                    diem_id_domains.map(|diem_id_domains| diem_id_domains.get_domains_list());
                AccountRoleView::ParentVASP {
                    human_name: credential.human_name().to_string(),
                    base_url: credential.base_url().to_string(),
                    expiration_time: credential.expiration_date(),
                    compliance_key: BytesView::from(credential.compliance_public_key()),
                    num_children: vasp.num_children(),
                    compliance_key_rotation_events_key: *credential
                        .compliance_key_rotation_events()
                        .key(),
                    base_url_rotation_events_key: *credential.base_url_rotation_events().key(),
                    diem_id_domains: domains,
                }
            }
            AccountRole::DesignatedDealer {
                dd_credential,
                preburn_balances,
                designated_dealer,
            } => {
                let (preburn_balances, preburn_queues) =
                    AccountRoleView::convert_preburn_balances(preburn_balances);
                AccountRoleView::DesignatedDealer {
                    human_name: dd_credential.human_name().to_string(),
                    base_url: dd_credential.base_url().to_string(),
                    expiration_time: dd_credential.expiration_date(),
                    compliance_key: BytesView::from(dd_credential.compliance_public_key()),
                    preburn_balances,
                    received_mint_events_key: *designated_dealer.received_mint_events().key(),
                    compliance_key_rotation_events_key: *dd_credential
                        .compliance_key_rotation_events()
                        .key(),
                    base_url_rotation_events_key: *dd_credential.base_url_rotation_events().key(),
                    preburn_queues,
                }
            }
            AccountRole::TreasuryCompliance {
                diem_id_domain_manager,
            } => AccountRoleView::TreasuryCompliance {
                diem_id_domain_events_key: Some(
                    *diem_id_domain_manager.diem_id_domain_events().key(),
                ),
            },
        }
    }
}

impl std::fmt::Display for AccountRoleView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CurrencyInfoView {
    pub code: String,
    pub scaling_factor: u64,
    pub fractional_part: u64,
    pub to_xdx_exchange_rate: f32,
    pub mint_events_key: EventKey,
    pub burn_events_key: EventKey,
    pub preburn_events_key: EventKey,
    pub cancel_burn_events_key: EventKey,
    pub exchange_rate_update_events_key: EventKey,
}

impl From<&CurrencyInfoResource> for CurrencyInfoView {
    fn from(info: &CurrencyInfoResource) -> CurrencyInfoView {
        CurrencyInfoView {
            code: info.currency_code().to_string(),
            scaling_factor: info.scaling_factor(),
            fractional_part: info.fractional_part(),
            to_xdx_exchange_rate: info.exchange_rate(),
            mint_events_key: *info.mint_events().key(),
            burn_events_key: *info.burn_events().key(),
            preburn_events_key: *info.preburn_events().key(),
            cancel_burn_events_key: *info.cancel_burn_events().key(),
            exchange_rate_update_events_key: *info.exchange_rate_update_events().key(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StateProofView {
    pub ledger_info_with_signatures: BytesView,
    pub epoch_change_proof: BytesView,
    pub ledger_consistency_proof: BytesView,
}

impl
    TryFrom<(
        LedgerInfoWithSignatures,
        EpochChangeProof,
        AccumulatorConsistencyProof,
    )> for StateProofView
{
    type Error = Error;

    fn try_from(
        (ledger_info_with_signatures, epoch_change_proof, ledger_consistency_proof): (
            LedgerInfoWithSignatures,
            EpochChangeProof,
            AccumulatorConsistencyProof,
        ),
    ) -> Result<StateProofView, Self::Error> {
        Ok(StateProofView {
            ledger_info_with_signatures: BytesView::new(bcs::to_bytes(
                &ledger_info_with_signatures,
            )?),
            epoch_change_proof: BytesView::new(bcs::to_bytes(&epoch_change_proof)?),
            ledger_consistency_proof: BytesView::new(bcs::to_bytes(&ledger_consistency_proof)?),
        })
    }
}

impl TryFrom<&StateProofView>
    for (
        LedgerInfoWithSignatures,
        EpochChangeProof,
        AccumulatorConsistencyProof,
    )
{
    type Error = Error;

    fn try_from(state_proof_view: &StateProofView) -> Result<Self, Self::Error> {
        Ok((
            bcs::from_bytes(state_proof_view.ledger_info_with_signatures.inner())?,
            bcs::from_bytes(state_proof_view.epoch_change_proof.inner())?,
            bcs::from_bytes(state_proof_view.ledger_consistency_proof.inner())?,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AccumulatorConsistencyProofView {
    pub ledger_consistency_proof: BytesView,
}

impl TryFrom<&AccumulatorConsistencyProof> for AccumulatorConsistencyProofView {
    type Error = Error;

    fn try_from(proof: &AccumulatorConsistencyProof) -> Result<Self, Self::Error> {
        Ok(Self {
            ledger_consistency_proof: BytesView::new(bcs::to_bytes(proof)?),
        })
    }
}

impl TryFrom<&AccumulatorConsistencyProofView> for AccumulatorConsistencyProof {
    type Error = Error;

    fn try_from(view: &AccumulatorConsistencyProofView) -> Result<Self, Self::Error> {
        Ok(bcs::from_bytes(view.ledger_consistency_proof.as_ref())?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AccountStateWithProofView {
    pub version: u64,
    pub blob: Option<BytesView>,
    pub proof: AccountStateProofView,
}

impl TryFrom<AccountStateWithProof> for AccountStateWithProofView {
    type Error = Error;

    fn try_from(
        account_state_with_proof: AccountStateWithProof,
    ) -> Result<AccountStateWithProofView, Error> {
        let blob = if let Some(account_blob) = account_state_with_proof.blob {
            Some(BytesView::new(bcs::to_bytes(&account_blob)?))
        } else {
            None
        };
        Ok(AccountStateWithProofView {
            version: account_state_with_proof.version,
            blob,
            proof: AccountStateProofView::try_from(account_state_with_proof.proof)?,
        })
    }
}

impl TryFrom<&AccountStateWithProofView> for AccountStateWithProof {
    type Error = Error;

    fn try_from(
        account_state_with_proof_view: &AccountStateWithProofView,
    ) -> Result<AccountStateWithProof, Self::Error> {
        let blob = if let Some(blob_view) = &account_state_with_proof_view.blob {
            Some(bcs::from_bytes(blob_view.as_ref())?)
        } else {
            None
        };
        let version = account_state_with_proof_view.version;
        let proof = AccountStateProof::try_from(&account_state_with_proof_view.proof)?;
        Ok(AccountStateWithProof::new(version, blob, proof))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AccountStateProofView {
    pub ledger_info_to_transaction_info_proof: BytesView,
    pub transaction_info: BytesView,
    pub transaction_info_to_account_proof: BytesView,
}

impl TryFrom<AccountStateProof> for AccountStateProofView {
    type Error = Error;

    fn try_from(account_state_proof: AccountStateProof) -> Result<AccountStateProofView, Error> {
        Ok(AccountStateProofView {
            ledger_info_to_transaction_info_proof: BytesView::new(bcs::to_bytes(
                account_state_proof
                    .transaction_info_with_proof()
                    .ledger_info_to_transaction_info_proof(),
            )?),
            transaction_info: BytesView::new(bcs::to_bytes(
                account_state_proof
                    .transaction_info_with_proof()
                    .transaction_info(),
            )?),
            transaction_info_to_account_proof: BytesView::new(bcs::to_bytes(
                account_state_proof.transaction_info_to_account_proof(),
            )?),
        })
    }
}

impl TryFrom<&AccountStateProofView> for AccountStateProof {
    type Error = Error;

    fn try_from(
        account_state_proof_view: &AccountStateProofView,
    ) -> Result<AccountStateProof, Self::Error> {
        let ledger_info_to_transaction_info_proof: TransactionAccumulatorProof = bcs::from_bytes(
            &account_state_proof_view
                .ledger_info_to_transaction_info_proof
                .as_ref(),
        )?;
        let transaction_info: TransactionInfo =
            bcs::from_bytes(&account_state_proof_view.transaction_info.as_ref())?;
        let transaction_info_with_proof =
            TransactionInfoWithProof::new(ledger_info_to_transaction_info_proof, transaction_info);
        let transaction_info_to_account_proof: SparseMerkleProof<AccountStateBlob> =
            bcs::from_bytes(
                &account_state_proof_view
                    .transaction_info_to_account_proof
                    .as_ref(),
            )?;
        Ok(AccountStateProof::new(
            transaction_info_with_proof,
            transaction_info_to_account_proof,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::views::{AmountView, EventDataView, PreburnWithMetadataView};
    use diem_types::{contract_event::ContractEvent, event::EventKey};
    use move_core_types::language_storage::TypeTag;
    use serde_json::json;
    use std::{convert::TryInto, str::FromStr};

    #[test]
    fn test_unknown_event_data() {
        let data = hex::decode("0000000000000000000000000000000000000000000000dd").unwrap();
        let ev = ContractEvent::new(
            EventKey::from_str("0000000000000000000000000000000000000000000000dd").unwrap(),
            0,
            TypeTag::Bool,
            data.clone(),
        );
        if let EventDataView::Unknown { bytes } = ev.try_into().unwrap() {
            assert_eq!(bytes.unwrap(), data.into());
        } else {
            panic!("expect unknown event data");
        }
    }

    #[test]
    fn test_serialize_preburn_with_metadata_view() {
        let view = PreburnWithMetadataView {
            preburn: AmountView {
                amount: 1,
                currency: "XUS".to_string(),
            },
            metadata: None,
        };
        let value = serde_json::to_value(&view).unwrap();
        assert_eq!(
            value,
            json!({
                "preburn": {
                    "amount": 1,
                    "currency": "XUS"
                }
            })
        );
    }
}
