// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    counters::*,
    data_cache::StateViewCache,
    diem_transaction_validator::validate_signature_checked_transaction,
    diem_vm::{
        charge_global_write_gas_usage, convert_changeset_and_events, get_transaction_output,
        DiemVMImpl, DiemVMInternals,
    },
    errors::expect_only_successful_execution,
    logging::AdapterLogSchema,
    script_to_script_function,
    system_module_names::*,
    transaction_metadata::TransactionMetadata,
    VMExecutor,
};
use diem_logger::prelude::*;
use diem_state_view::StateView;
use diem_types::access_path::AccessPath;
use diem_types::transaction::TransactionArgument;
use diem_types::write_set::WriteOp;
use diem_types::{
    account_config,
    block_metadata::BlockMetadata,
    transaction::{
        ChangeSet, Module, SignatureCheckedTransaction, Transaction, TransactionOutput,
        TransactionPayload, TransactionStatus, WriteSetPayload,
    },
    vm_status::{KeptVMStatus, StatusCode, VMStatus},
    write_set::{WriteSet, WriteSetMut},
};
use fail::fail_point;
use move_core_types::{
    account_address::AccountAddress,
    gas_schedule::GasAlgebra,
    identifier::IdentStr,
    transaction_argument::convert_txn_args,
    value::{serialize_values, MoveValue},
};
use move_vm_runtime::{data_cache::MoveStorage, logging::LogContext, session::Session};
use move_vm_types::gas_schedule::GasStatus;
use rayon::prelude::*;
use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;
use std::{
    collections::HashSet,
    convert::{AsMut, AsRef},
};

pub struct DiemVM;
pub struct DiemVM_(DiemVMImpl);

impl DiemVM_ {
    pub fn new<S: StateView>(state: &S) -> Self {
        Self(DiemVMImpl::new(state))
    }

    pub fn internals(&self) -> DiemVMInternals {
        DiemVMInternals::new(&self.0)
    }

    /// Generates a transaction output for a transaction that encountered errors during the
    /// execution process. This is public for now only for tests.
    pub fn failed_transaction_cleanup<S: MoveStorage>(
        &self,
        error_code: VMStatus,
        gas_status: &mut GasStatus,
        txn_data: &TransactionMetadata,
        storage: &S,
        account_currency_symbol: &IdentStr,
        log_context: &impl LogContext,
    ) -> TransactionOutput {
        self.failed_transaction_cleanup_and_keep_vm_status(
            error_code,
            gas_status,
            txn_data,
            storage,
            account_currency_symbol,
            log_context,
        )
        .1
    }

    fn failed_transaction_cleanup_and_keep_vm_status<S: MoveStorage>(
        &self,
        error_code: VMStatus,
        gas_status: &mut GasStatus,
        txn_data: &TransactionMetadata,
        storage: &S,
        account_currency_symbol: &IdentStr,
        log_context: &impl LogContext,
    ) -> (VMStatus, TransactionOutput) {
        gas_status.set_metering(false);
        let mut session = self.0.new_session(storage);
        match TransactionStatus::from(error_code.clone()) {
            TransactionStatus::Keep(status) => {
                // The transaction should be charged for gas, so run the epilogue to do that.
                // This is running in a new session that drops any side effects from the
                // attempted transaction (e.g., spending funds that were needed to pay for gas),
                // so even if the previous failure occurred while running the epilogue, it
                // should not fail now. If it somehow fails here, there is no choice but to
                // discard the transaction.
                if let Err(e) = self.0.run_failure_epilogue(
                    &mut session,
                    gas_status,
                    txn_data,
                    account_currency_symbol,
                    log_context,
                ) {
                    return discard_error_vm_status(e);
                }
                let txn_output = get_transaction_output(
                    &mut (),
                    session,
                    gas_status.remaining_gas(),
                    txn_data,
                    status,
                )
                .unwrap_or_else(|e| discard_error_vm_status(e).1);
                (error_code, txn_output)
            }
            TransactionStatus::Discard(status) => {
                (VMStatus::Error(status), discard_error_output(status))
            }
            TransactionStatus::Retry => unreachable!(),
        }
    }

    fn success_transaction_cleanup<S: MoveStorage>(
        &self,
        mut session: Session<S>,
        gas_status: &mut GasStatus,
        txn_data: &TransactionMetadata,
        account_currency_symbol: &IdentStr,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput), VMStatus> {
        gas_status.set_metering(false);
        self.0.run_success_epilogue(
            &mut session,
            gas_status,
            txn_data,
            account_currency_symbol,
            log_context,
        )?;

        Ok((
            VMStatus::Executed,
            get_transaction_output(
                &mut (),
                session,
                gas_status.remaining_gas(),
                txn_data,
                KeptVMStatus::Executed,
            )?,
        ))
    }

    fn execute_script_or_script_function<S: MoveStorage>(
        &self,
        mut session: Session<S>,
        gas_status: &mut GasStatus,
        txn_data: &TransactionMetadata,
        payload: &TransactionPayload,
        account_currency_symbol: &IdentStr,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput), VMStatus> {
        fail_point!("move_adapter::execute_script_or_script_function", |_| {
            Err(VMStatus::Error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        });

        // Run the execution logic
        {
            gas_status
                .charge_intrinsic_gas(txn_data.transaction_size())
                .map_err(|e| e.into_vm_status())?;

            match payload {
                TransactionPayload::Script(script) => {
                    let diem_version = self.0.get_diem_version()?;
                    let remapped_script =
                        if diem_version < diem_types::on_chain_config::DIEM_VERSION_2 {
                            None
                        } else {
                            script_to_script_function::remapping(script.code())
                        };
                    match remapped_script {
                        // We are in this case before VERSION_2
                        // or if there is no remapping for the script
                        None => session.execute_script(
                            script.code().to_vec(),
                            script.ty_args().to_vec(),
                            convert_txn_args(script.args()),
                            vec![txn_data.sender()],
                            gas_status,
                            log_context,
                        ),
                        Some((module, function)) => session.execute_script_function(
                            module,
                            function,
                            script.ty_args().to_vec(),
                            convert_txn_args(script.args()),
                            vec![txn_data.sender()],
                            gas_status,
                            log_context,
                        ),
                    }
                }
                TransactionPayload::ScriptFunction(script_fn) => session.execute_script_function(
                    script_fn.module(),
                    script_fn.function(),
                    script_fn.ty_args().to_vec(),
                    script_fn.args().to_vec(),
                    vec![txn_data.sender()],
                    gas_status,
                    log_context,
                ),
                TransactionPayload::Module(_) | TransactionPayload::WriteSet(_) => {
                    return Err(VMStatus::Error(StatusCode::UNREACHABLE));
                }
            }
            .map_err(|e| e.into_vm_status())?;

            charge_global_write_gas_usage(gas_status, &session, &txn_data.sender())?;

            self.success_transaction_cleanup(
                session,
                gas_status,
                txn_data,
                account_currency_symbol,
                log_context,
            )
        }
    }

    fn execute_module<S: MoveStorage>(
        &self,
        mut session: Session<S>,
        gas_status: &mut GasStatus,
        txn_data: &TransactionMetadata,
        module: &Module,
        account_currency_symbol: &IdentStr,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput), VMStatus> {
        fail_point!("move_adapter::execute_module", |_| {
            Err(VMStatus::Error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        });

        // Publish the module
        let module_address = if self.0.publishing_option(log_context)?.is_open_module() {
            txn_data.sender()
        } else {
            account_config::CORE_CODE_ADDRESS
        };

        gas_status
            .charge_intrinsic_gas(txn_data.transaction_size())
            .map_err(|e| e.into_vm_status())?;
        session
            .publish_module(
                module.code().to_vec(),
                module_address,
                gas_status,
                log_context,
            )
            .map_err(|e| e.into_vm_status())?;

        charge_global_write_gas_usage(gas_status, &session, &txn_data.sender())?;

        self.success_transaction_cleanup(
            session,
            gas_status,
            txn_data,
            account_currency_symbol,
            log_context,
        )
    }

    fn execute_user_transaction<S: MoveStorage>(
        &self,
        storage: &S,
        txn: &SignatureCheckedTransaction,
        log_context: &impl LogContext,
    ) -> (VMStatus, TransactionOutput) {
        macro_rules! unwrap_or_discard {
            ($res: expr) => {
                match $res {
                    Ok(s) => s,
                    Err(e) => return discard_error_vm_status(e),
                }
            };
        }

        // Revalidate the transaction.
        let mut session = self.0.new_session(storage);
        let account_currency_symbol = match validate_signature_checked_transaction(
            &self.0,
            &mut session,
            txn,
            storage,
            false,
            log_context,
        ) {
            Ok((_, currency_code)) => currency_code,
            Err(err) => {
                return discard_error_vm_status(err);
            }
        };

        let gas_schedule = unwrap_or_discard!(self.0.get_gas_schedule(log_context));
        let txn_data = TransactionMetadata::new(txn);
        let mut gas_status = GasStatus::new(gas_schedule, txn_data.max_gas_amount());

        let result = match txn.payload() {
            payload @ TransactionPayload::Script(_)
            | payload @ TransactionPayload::ScriptFunction(_) => self
                .execute_script_or_script_function(
                    session,
                    &mut gas_status,
                    &txn_data,
                    payload,
                    &account_currency_symbol,
                    log_context,
                ),
            TransactionPayload::Module(m) => self.execute_module(
                session,
                &mut gas_status,
                &txn_data,
                m,
                &account_currency_symbol,
                log_context,
            ),
            TransactionPayload::WriteSet(_) => {
                return discard_error_vm_status(VMStatus::Error(StatusCode::UNREACHABLE))
            }
        };

        let gas_usage = txn_data
            .max_gas_amount()
            .sub(gas_status.remaining_gas())
            .get();
        TXN_GAS_USAGE.observe(gas_usage as f64);

        match result {
            Ok(output) => output,
            Err(err) => {
                let txn_status = TransactionStatus::from(err.clone());
                if txn_status.is_discarded() {
                    discard_error_vm_status(err)
                } else {
                    self.failed_transaction_cleanup_and_keep_vm_status(
                        err,
                        &mut gas_status,
                        &txn_data,
                        storage,
                        &account_currency_symbol,
                        log_context,
                    )
                }
            }
        }
    }

    fn execute_writeset<S: MoveStorage>(
        &self,
        storage: &S,
        writeset_payload: &WriteSetPayload,
        txn_sender: Option<AccountAddress>,
        log_context: &impl LogContext,
    ) -> Result<ChangeSet, Result<(VMStatus, TransactionOutput), VMStatus>> {
        let mut gas_status = GasStatus::new_unmetered();

        Ok(match writeset_payload {
            WriteSetPayload::Direct(change_set) => change_set.clone(),
            WriteSetPayload::Script { script, execute_as } => {
                let mut tmp_session = self.0.new_session(storage);
                let diem_version = self.0.get_diem_version().map_err(Err)?;
                let senders = match txn_sender {
                    None => vec![*execute_as],
                    Some(sender) => vec![sender, *execute_as],
                };
                let remapped_script = if diem_version < diem_types::on_chain_config::DIEM_VERSION_2
                {
                    None
                } else {
                    script_to_script_function::remapping(script.code())
                };
                let execution_result = match remapped_script {
                    // We are in this case before VERSION_2
                    // or if there is no remapping for the script
                    None => tmp_session.execute_script(
                        script.code().to_vec(),
                        script.ty_args().to_vec(),
                        convert_txn_args(script.args()),
                        senders,
                        &mut gas_status,
                        log_context,
                    ),
                    Some((module, function)) => tmp_session.execute_script_function(
                        module,
                        function,
                        script.ty_args().to_vec(),
                        convert_txn_args(script.args()),
                        senders,
                        &mut gas_status,
                        log_context,
                    ),
                }
                .and_then(|_| tmp_session.finish())
                .map_err(|e| e.into_vm_status());
                match execution_result {
                    Ok((changeset, events)) => {
                        let (cs, events) =
                            convert_changeset_and_events(changeset, events).map_err(Err)?;
                        ChangeSet::new(cs, events)
                    }
                    Err(e) => {
                        return Err(Ok((e, discard_error_output(StatusCode::INVALID_WRITE_SET))))
                    }
                }
            }
        })
    }

    fn read_writeset(
        &self,
        state_view: &dyn StateView,
        write_set: &WriteSet,
    ) -> Result<(), VMStatus> {
        // All Move executions satisfy the read-before-write property. Thus we need to read each
        // access path that the write set is going to update.
        for (ap, _) in write_set.iter() {
            state_view
                .get(ap)
                .map_err(|_| VMStatus::Error(StatusCode::STORAGE_ERROR))?;
        }
        Ok(())
    }

    fn process_waypoint_change_set<S: MoveStorage + StateView>(
        &self,
        storage: &S,
        writeset_payload: WriteSetPayload,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput), VMStatus> {
        let change_set = match self.execute_writeset(storage, &writeset_payload, None, log_context)
        {
            Ok(cs) => cs,
            Err(e) => return e,
        };
        let (write_set, events) = change_set.into_inner();
        self.read_writeset(storage, &write_set)?;
        SYSTEM_TRANSACTIONS_EXECUTED.inc();
        Ok((
            VMStatus::Executed,
            TransactionOutput::new(write_set, events, 0, VMStatus::Executed.into()),
        ))
    }

    fn process_block_prologue<S: MoveStorage>(
        &self,
        storage: &S,
        block_metadata: BlockMetadata,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput), VMStatus> {
        fail_point!("move_adapter::process_block_prologue", |_| {
            Err(VMStatus::Error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        });

        let txn_data = TransactionMetadata {
            sender: account_config::reserved_vm_address(),
            ..Default::default()
        };
        let mut gas_status = GasStatus::new_unmetered();
        let mut session = self.0.new_session(storage);

        let (round, timestamp, previous_vote, proposer) = block_metadata.into_inner();
        let args = serialize_values(&vec![
            MoveValue::Signer(txn_data.sender),
            MoveValue::U64(round),
            MoveValue::U64(timestamp),
            MoveValue::Vector(previous_vote.into_iter().map(MoveValue::Address).collect()),
            MoveValue::Address(proposer),
        ]);
        session
            .execute_function(
                &DIEM_BLOCK_MODULE,
                &BLOCK_PROLOGUE,
                vec![],
                args,
                &mut gas_status,
                log_context,
            )
            .map(|_return_vals| ())
            .or_else(|e| {
                expect_only_successful_execution(e, BLOCK_PROLOGUE.as_str(), log_context)
            })?;
        SYSTEM_TRANSACTIONS_EXECUTED.inc();

        let output = get_transaction_output(
            &mut (),
            session,
            gas_status.remaining_gas(),
            &txn_data,
            KeptVMStatus::Executed,
        )?;
        Ok((VMStatus::Executed, output))
    }

    fn process_writeset_transaction<S: MoveStorage + StateView>(
        &self,
        storage: &S,
        txn: &SignatureCheckedTransaction,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput), VMStatus> {
        fail_point!("move_adapter::process_writeset_transaction", |_| {
            Err(VMStatus::Error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        });

        // Revalidate the transaction.
        let mut session = self.0.new_session(storage);
        if let Err(e) = validate_signature_checked_transaction(
            &self.0,
            &mut session,
            &txn,
            storage,
            false,
            log_context,
        ) {
            return Ok(discard_error_vm_status(e));
        };
        self.execute_writeset_transaction(
            storage,
            match txn.payload() {
                TransactionPayload::WriteSet(writeset_payload) => writeset_payload,
                TransactionPayload::Module(_)
                | TransactionPayload::Script(_)
                | TransactionPayload::ScriptFunction(_) => {
                    log_context.alert();
                    error!(*log_context, "[diem_vm] UNREACHABLE");
                    return Ok(discard_error_vm_status(VMStatus::Error(
                        StatusCode::UNREACHABLE,
                    )));
                }
            },
            TransactionMetadata::new(&txn),
            log_context,
        )
    }

    pub fn execute_writeset_transaction<S: MoveStorage + StateView>(
        &self,
        storage: &S,
        writeset_payload: &WriteSetPayload,
        txn_data: TransactionMetadata,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput), VMStatus> {
        let change_set = match self.execute_writeset(
            storage,
            writeset_payload,
            Some(txn_data.sender()),
            log_context,
        ) {
            Ok(change_set) => change_set,
            Err(e) => return e,
        };

        // Run the epilogue function.
        let mut session = self.0.new_session(storage);
        self.0.run_writeset_epilogue(
            &mut session,
            &txn_data,
            writeset_payload.should_trigger_reconfiguration_by_default(),
            log_context,
        )?;

        if let Err(e) = self.read_writeset(storage, &change_set.write_set()) {
            // Any error at this point would be an invalid writeset
            return Ok((e, discard_error_output(StatusCode::INVALID_WRITE_SET)));
        };

        let (changeset, events) = session.finish().map_err(|e| e.into_vm_status())?;
        let (epilogue_writeset, epilogue_events) = convert_changeset_and_events(changeset, events)?;

        // Make sure epilogue WriteSet doesn't intersect with the writeset in TransactionPayload.
        if !epilogue_writeset
            .iter()
            .map(|(ap, _)| ap)
            .collect::<HashSet<_>>()
            .is_disjoint(
                &change_set
                    .write_set()
                    .iter()
                    .map(|(ap, _)| ap)
                    .collect::<HashSet<_>>(),
            )
        {
            let vm_status = VMStatus::Error(StatusCode::INVALID_WRITE_SET);
            return Ok(discard_error_vm_status(vm_status));
        }
        if !epilogue_events
            .iter()
            .map(|event| event.key())
            .collect::<HashSet<_>>()
            .is_disjoint(
                &change_set
                    .events()
                    .iter()
                    .map(|event| event.key())
                    .collect::<HashSet<_>>(),
            )
        {
            let vm_status = VMStatus::Error(StatusCode::INVALID_WRITE_SET);
            return Ok(discard_error_vm_status(vm_status));
        }

        let write_set = WriteSetMut::new(
            epilogue_writeset
                .iter()
                .chain(change_set.write_set().iter())
                .cloned()
                .collect(),
        )
        .freeze()
        .map_err(|_| VMStatus::Error(StatusCode::INVALID_WRITE_SET))?;
        let events = change_set
            .events()
            .iter()
            .chain(epilogue_events.iter())
            .cloned()
            .collect();
        SYSTEM_TRANSACTIONS_EXECUTED.inc();

        Ok((
            VMStatus::Executed,
            TransactionOutput::new(
                write_set,
                events,
                0,
                TransactionStatus::Keep(KeptVMStatus::Executed),
            ),
        ))
    }

    pub(crate) fn execute_block_impl(
        &mut self,
        transactions: Vec<Transaction>,
        data_cache: &mut StateViewCache,
        parallel: bool,
    ) -> Result<Vec<(VMStatus, TransactionOutput)>, VMStatus> {
        if parallel {
            self.execute_block_impl_parallel(transactions, data_cache)
        } else {
            self.execute_block_impl_sequential(transactions, data_cache)
        }
    }

    pub(crate) fn execute_block_impl_sequential(
        &self,
        transactions: Vec<Transaction>,
        data_cache: &mut StateViewCache,
    ) -> Result<Vec<(VMStatus, TransactionOutput)>, VMStatus> {
        let count = transactions.len();
        let mut result = vec![];
        let mut should_restart = false;

        info!(
            AdapterLogSchema::new(data_cache.id(), 0),
            "Executing block, transaction count: {}",
            transactions.len()
        );

        let signature_verified_block: Vec<PreprocessedTransaction>;
        {
            // Verify the signatures of all the transactions in parallel.
            // This is time consuming so don't wait and do the checking
            // sequentially while executing the transactions.
            signature_verified_block = transactions
                .clone()
                .into_par_iter()
                .map(preprocess_transaction)
                .collect();
        }

        for (idx, txn) in signature_verified_block.into_iter().enumerate() {
            let log_context = AdapterLogSchema::new(data_cache.id(), idx);
            if should_restart {
                let txn_output = TransactionOutput::new(
                    WriteSet::default(),
                    vec![],
                    0,
                    TransactionStatus::Retry,
                );
                result.push((VMStatus::Error(StatusCode::UNKNOWN_STATUS), txn_output));
                debug!(log_context, "Retry after reconfiguration");
                continue;
            };
            let (vm_status, output, sender) =
                self.execute_single_transaction(&txn, data_cache, &log_context)?;
            if !output.status().is_discarded() {
                data_cache.push_write_set(output.write_set());
            } else {
                match sender {
                    Some(s) => trace!(
                        log_context,
                        "Transaction discarded, sender: {}, error: {:?}",
                        s,
                        vm_status,
                    ),
                    None => trace!(log_context, "Transaction malformed, error: {:?}", vm_status,),
                }
            }

            if is_reconfiguration(&output) {
                info!(
                    AdapterLogSchema::new(data_cache.id(), 0),
                    "Reconfiguration occurred: restart required",
                );
                should_restart = true;
            }

            // `result` is initially empty, a single element is pushed per loop iteration and
            // the number of iterations is bound to the max size of `signature_verified_block`
            assume!(result.len() < usize::max_value());
            result.push((vm_status, output))
        }

        // Record the histogram count for transactions per block.
        BLOCK_TRANSACTION_COUNT.observe(count as f64);

        Ok(result)
    }

    pub(crate) fn execute_single_transaction<S: MoveStorage + StateView>(
        &self,
        txn: &PreprocessedTransaction,
        data_cache: &S,
        log_context: &impl LogContext,
    ) -> Result<(VMStatus, TransactionOutput, Option<String>), VMStatus> {
        Ok(match txn {
            PreprocessedTransaction::BlockMetadata(block_metadata) => {
                let (vm_status, output) =
                    self.process_block_prologue(data_cache, block_metadata.clone(), log_context)?;
                (vm_status, output, Some("block_prologue".to_string()))
            }
            PreprocessedTransaction::WaypointWriteSet(write_set_payload) => {
                let (vm_status, output) = self.process_waypoint_change_set(
                    data_cache,
                    write_set_payload.clone(),
                    log_context,
                )?;
                (vm_status, output, Some("waypoint_write_set".to_string()))
            }
            PreprocessedTransaction::UserTransaction(txn) => {
                let sender = txn.sender().to_string();
                let _timer = TXN_TOTAL_SECONDS.start_timer();
                let (vm_status, output) =
                    self.execute_user_transaction(data_cache, txn, log_context);

                // Increment the counter for user transactions executed.
                let counter_label = match output.status() {
                    TransactionStatus::Keep(_) => Some("success"),
                    TransactionStatus::Discard(_) => Some("discarded"),
                    TransactionStatus::Retry => None,
                };
                if let Some(label) = counter_label {
                    USER_TRANSACTIONS_EXECUTED.with_label_values(&[label]).inc();
                }
                (vm_status, output, Some(sender))
            }
            PreprocessedTransaction::WriteSet(txn) => {
                let (vm_status, output) =
                    self.process_writeset_transaction(data_cache, txn, log_context)?;
                (vm_status, output, Some("write_set".to_string()))
            }
            PreprocessedTransaction::InvalidSignature => {
                let (vm_status, output) =
                    discard_error_vm_status(VMStatus::Error(StatusCode::INVALID_SIGNATURE));
                (vm_status, output, None)
            }
        })
    }

    fn dependency_structure_hack(
        &self,
        transactions: &Vec<Transaction>,
        data_cache: &mut StateViewCache,
    ) -> Result<HashMap<Vec<u8>, ScriptReadWriteSet>, ()> {
        // STARTS -- DEPENDENCY INFERENCE HACK / Replace with static analysis of write set
        let mut read_write_infer = HashMap::new();
        for (_idx, txn) in transactions.iter().enumerate() {
            match txn {
                Transaction::UserTransaction(user_txn) => {
                    match user_txn.payload() {
                        TransactionPayload::Script(script) => {
                            // If the transaction is not known, then execute it to infer its read/write logic.
                            if !read_write_infer.contains_key(script.code()) {
                                println!("COMPUTE READ/WRITE SET");
                                let xref = &*data_cache;
                                let local_state_view_cache = StateViewCache::new_recorder(xref);
                                let log_context = AdapterLogSchema::new(xref.id(), 0);
                                // Execute the transaction
                                let verify_txn = preprocess_transaction(txn.clone());
                                if let Ok((vm_status, output, _)) = self.execute_single_transaction(
                                    &verify_txn,
                                    &local_state_view_cache,
                                    &log_context,
                                ) {
                                    if vm_status != VMStatus::Executed {
                                        return Err(());
                                    }
                                    // Record the read-set
                                    let read_set = local_state_view_cache.read_set();

                                    // Create a params list
                                    let mut params = vec![user_txn.sender()];
                                    for arg in script.args() {
                                        match arg {
                                            TransactionArgument::Address(address) => {
                                                params.push(address.clone());
                                            }
                                            _ => {}
                                        };
                                    }

                                    let mut reads = Vec::new();
                                    let mut writes = Vec::new();
                                    let write_set: HashSet<AccessPath> = output
                                        .write_set()
                                        .iter()
                                        .map(|(k, _)| k)
                                        .cloned()
                                        .collect();
                                    // println!("Params: {:?}", params);
                                    for path in read_set {
                                        if write_set.contains(&path) {
                                            reads.push(path.clone());
                                            writes.push(path.clone());
                                            // println!("  -W {}", path);
                                        } else {
                                            reads.push(path.clone());
                                            // println!("  -R {}", path);
                                        }
                                    }

                                    read_write_infer.insert(
                                        script.code().to_vec(),
                                        ScriptReadWriteSet::new(params, reads, writes),
                                    );
                                } else {
                                    panic!("NO LOGIC TO INFER READ/WRITE SET");
                                }
                            }
                        }
                        _ => {
                            println!("NON SCIPT TRANSACTION");
                            return Err(());
                        }
                    }
                }
                Transaction::BlockMetadata(meta) => {
                    let xref = &*data_cache;
                    let local_state_view_cache = StateViewCache::new_recorder(xref);
                    let log_context = AdapterLogSchema::new(xref.id(), 0);
                    // Execute the transaction
                    let verify_txn = preprocess_transaction(txn.clone());
                    if let Ok((_vm_status, output, _)) = self.execute_single_transaction(
                        &verify_txn,
                        &local_state_view_cache,
                        &log_context,
                    ) {
                        // Record the read-set
                        let read_set = local_state_view_cache.read_set();

                        // Create a params list
                        let (_, _, _, proposer) = meta.clone().into_inner();
                        let params = vec![proposer];

                        let mut reads = Vec::new();
                        let mut writes = Vec::new();
                        let write_set: HashSet<AccessPath> =
                            output.write_set().iter().map(|(k, _)| k).cloned().collect();
                        // println!("Params: {:?}", params);
                        for path in read_set {
                            if write_set.contains(&path) {
                                reads.push(path.clone());
                                writes.push(path.clone());
                                // println!("  -W {}", path);
                            } else {
                                reads.push(path.clone());
                                // println!("  -R {}", path);
                            }
                        }

                        read_write_infer
                            .insert(vec![], ScriptReadWriteSet::new(params, reads, writes));
                    }
                }
                _ => {
                    println!("NON USER TRANSACTION");
                    return Err(());
                }
            }
        }
        // ENDS
        Ok(read_write_infer.clone())
    }

    fn execute_block_impl_parallel(
        &mut self,
        transactions: Vec<Transaction>,
        data_cache: &mut StateViewCache,
    ) -> Result<Vec<(VMStatus, TransactionOutput)>, VMStatus> {
        let mut exec_tally: u128 = 0;

        use crate::scheduler_parallel::{
            OutcomeArray, SingleThreadReadCache, VersionedStateView, WriteVersionValue,
            WritesPlaceholder,
        };

        // Count and print the number of transactions.
        let num_txns = transactions.len();
        let cpus = num_cpus::get();
        let chunks = max(1, num_txns / cpus);

        // TODO: deal with execution restarting ...
        let mut _should_restart = false;
        println!("Executing block, transaction count: {}", num_txns);

        // Update the dependency analysis structure. We only do this for blocks that
        // purely consist of UserTransactions (Extending this is a TODO). If non-user
        // transactions are detected this returns and err, and we revert to sequential
        // block processing.
        let execute_start = std::time::Instant::now();
        let infer_result = self.dependency_structure_hack(&transactions, data_cache);
        let read_write_infer = match infer_result {
            Err(_) => return self.execute_block_impl(transactions, data_cache, false),
            Ok(val) => val,
        };
        let execute_time = std::time::Instant::now().duration_since(execute_start);
        println!(
            "Check Dependencies. Execute time: {} ms. TPS: {}.",
            execute_time.as_millis(),
            num_txns as u128 * 1_000_000_000 / execute_time.as_nanos(),
        );
        exec_tally += execute_time.as_millis();

        let execute_start = std::time::Instant::now();
        let mut signature_verified_block: Vec<PreprocessedTransaction> = Vec::new();
        {
            // Verify the signatures of all the transactions in parallel.
            // This is time consuming so don't wait and do the checking
            // sequentially while executing the transactions.
            transactions
                // .clone()
                .into_par_iter()
                .map(preprocess_transaction)
                .collect_into_vec(&mut signature_verified_block);
        }

        let execute_time = std::time::Instant::now().duration_since(execute_start);
        println!(
            "Check Signatures. Execute time: {} ms. TPS: {}.",
            execute_time.as_millis(),
            num_txns as u128 * 1_000_000_000 / execute_time.as_nanos(),
        );
        exec_tally += execute_time.as_millis();

        let execute_start = std::time::Instant::now();

        // Analyse each user script for its write-set and create the placeholder structure
        // that allows for parallel execution.
        let path_version_tuples: Vec<(AccessPath, usize)> = signature_verified_block
            .par_iter()
            .enumerate()
            .with_min_len(chunks)
            .fold(
                || Vec::new(),
                |mut acc, (idx, txn)| {
                    match txn {
                        PreprocessedTransaction::UserTransaction(user_txn) => {
                            match user_txn.payload() {
                                TransactionPayload::Script(script) => {
                                    let mut params = Vec::with_capacity(5);
                                    params.push(user_txn.sender());
                                    for arg in script.args() {
                                        if let TransactionArgument::Address(address) = arg {
                                            params.push(address.clone());
                                        }
                                    }

                                    // Create the dependency structure
                                    let deps = read_write_infer.get(script.code()).unwrap();
                                    acc.extend(deps.writes(&params).map(|w| (w, idx)));
                                }
                                _ => {
                                    unreachable!()
                                }
                            }
                        }
                        PreprocessedTransaction::BlockMetadata(meta) => {
                            let (_, _, _, proposer) = meta.clone().into_inner();
                            let params = vec![proposer];
                            // Create the dependency structure
                            let deps = read_write_infer.get(&vec![]).unwrap();
                            acc.extend(deps.writes(&params).map(|w| (w, idx)));
                        }
                        _ => unreachable!(),
                    }
                    acc
                },
            )
            .flatten()
            .collect();

        let execute_time = std::time::Instant::now().duration_since(execute_start);

        println!(
            "Schedule Parallel. Execute time: {} ms. TPS: {}.",
            execute_time.as_millis(),
            num_txns as u128 * 1_000_000_000 / execute_time.as_nanos(),
        );
        exec_tally += execute_time.as_millis();

        let execute_start = std::time::Instant::now();

        fn split_merge(
            num_cpus: usize,
            num: usize,
            split: Vec<(AccessPath, usize)>,
        ) -> (
            usize,
            HashMap<AccessPath, BTreeMap<usize, WriteVersionValue>>,
        ) {
            if ((2 << num) > num_cpus) || split.len() < 1000 {
                let mut data = HashMap::new();
                let mut max_len = 0;
                for (path, version) in split.into_iter() {
                    let place = data.entry(path).or_insert(BTreeMap::new());
                    place.insert(version, WriteVersionValue::new());
                    max_len = max(max_len, place.len());
                }
                (max_len, data)
            } else {
                let pivot_address = split[split.len() / 2].0.clone();
                let (left, right): (Vec<_>, Vec<_>) =
                    split.into_iter().partition(|(p, _)| *p < pivot_address);
                let ((m0, mut left_map), (m1, right_map)) = rayon::join(
                    || split_merge(num_cpus, num + 1, left),
                    || split_merge(num_cpus, num + 1, right),
                );
                left_map.extend(right_map);
                (max(m0, m1), left_map)
            }
        }

        let ((max_len, data), outcomes) = rayon::join(
            || split_merge(cpus, 0, path_version_tuples),
            || OutcomeArray::new(num_txns),
        );

        let placeholders = WritesPlaceholder::new_from(data);

        let execute_time = std::time::Instant::now().duration_since(execute_start);

        println!(
            "Schedule Reduce. Execute time: {} ms. TPS: {}.",
            execute_time.as_millis(),
            num_txns as u128 * 1_000_000_000 / execute_time.as_nanos(),
        );
        exec_tally += execute_time.as_millis();

        use rayon::scope;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // The advanced scheduler
        let execute_start = std::time::Instant::now();
        let curent_idx = AtomicUsize::new(0);
        let stop_when = signature_verified_block.len();

        use std::collections::VecDeque;

        scope(|s| {
            // How many threads to use?
            let compute_cpus = min(1 + (num_txns / 50), cpus - 1); // Ensure we have at least 50 tx per thread.
            let compute_cpus = min(num_txns / max_len, compute_cpus); // Ensure we do not higher rate of conflict than concurrency.

            println!(
                "Launching {} threads to execute (Max conflict {}) ...",
                compute_cpus, max_len
            );
            for _ in 0..(compute_cpus) {
                s.spawn(|_| {
                    // Make a per thread cache to de-congest mem bus
                    let thread_data_cache = SingleThreadReadCache::new(data_cache);
                    // Make a new VM per thread -- with its own module cache
                    let thread_vm = Self::new(&thread_data_cache);
                    let mut tx_idx_ring_buffer = VecDeque::with_capacity(10);

                    loop {
                        if tx_idx_ring_buffer.len() < 10 {
                            // How many transactions to have in the buffer.

                            let idx = curent_idx.fetch_add(1, Ordering::Relaxed);
                            if idx < stop_when {
                                let txn = &signature_verified_block[idx];

                                let (params, deps) = match txn {
                                    PreprocessedTransaction::UserTransaction(user_txn) => {
                                        match user_txn.payload() {
                                            TransactionPayload::Script(script) => {
                                                let mut params = Vec::with_capacity(5);
                                                params.push(user_txn.sender());
                                                for arg in script.args() {
                                                    if let TransactionArgument::Address(address) =
                                                        arg
                                                    {
                                                        params.push(address.clone());
                                                    }
                                                }

                                                // Create the dependency structure
                                                let deps =
                                                    read_write_infer.get(script.code()).unwrap();
                                                (params, deps)
                                            }
                                            _ => {
                                                unreachable!();
                                            }
                                        }
                                    }
                                    PreprocessedTransaction::BlockMetadata(meta) => {
                                        let (_, _, _, proposer) = meta.clone().into_inner();
                                        let params = vec![proposer];
                                        // Create the dependency structure
                                        let deps = read_write_infer.get(&vec![]).unwrap();
                                        (params, deps)
                                    }
                                    _ => {
                                        unreachable!();
                                    }
                                };

                                tx_idx_ring_buffer.push_back((idx, txn, params, deps));
                            }
                        }

                        if tx_idx_ring_buffer.len() == 0 {
                            break;
                        }

                        let (idx, txn, params, deps) = tx_idx_ring_buffer.pop_front().unwrap(); // safe due to previous check

                        let versioned_state_view =
                            VersionedStateView::new(idx, &thread_data_cache, &placeholders);

                        // Delay and move to next tx if cannot execure now.
                        if deps
                            .reads(&params)
                            .any(|k| versioned_state_view.will_read_block(&k))
                        {
                            // println!("Delay {}", idx);
                            tx_idx_ring_buffer.push_back((idx, txn, params, deps));

                            // This causes a PAUSE on an x64 arch, and takes 140 cycles. Allows other
                            // core to take resources and better HT.
                            ::std::sync::atomic::spin_loop_hint();
                            continue;
                        }

                        // Execute the transaction
                        let log_context = AdapterLogSchema::new(versioned_state_view.id(), idx);
                        let res = thread_vm.execute_single_transaction(
                            txn,
                            &versioned_state_view,
                            &log_context,
                        );
                        match res {
                            Ok((vm_status, output, _)) => {
                                if !output.status().is_discarded() {
                                    for (k, v) in output.write_set() {
                                        let val = match v {
                                            WriteOp::Deletion => None,
                                            WriteOp::Value(data) => Some(data.clone()),
                                        };

                                        placeholders.write(k, idx, val).unwrap();
                                    }

                                    for w in deps.writes(&params) {
                                        placeholders.skip_if_not_set(&w, idx).unwrap();
                                    }

                                    // Commit the results to the data cache
                                    outcomes.set_result(idx, (vm_status, output), true);
                                } else {
                                    for w in deps.writes(&params) {
                                        placeholders.skip(&w, idx).unwrap();
                                    }

                                    outcomes.set_result(idx, (vm_status, output), false);
                                }
                            }
                            Err(_) => {
                                panic!("TODO STOP VM & RETURN ERROR");
                                // return Err(e);
                            }
                        }
                    }
                    // println!("   - Exec thread: wait {} proceed {}", wait_num, proceed_num);
                });
            }
        });

        let execute_time = std::time::Instant::now().duration_since(execute_start);

        println!(
            "Advanced Exec. Execute time: {} ms. TPS: {}.",
            execute_time.as_millis(),
            num_txns as u128 * 1_000_000_000 / execute_time.as_nanos(),
        );
        exec_tally += execute_time.as_millis();
        //
        let execute_start = std::time::Instant::now();
        let (num_success, num_fail) = outcomes.get_stats();
        println!("Block: {} success, {} failures", num_success, num_fail);

        let all_results = outcomes.get_all_results();

        use std::thread;

        // Dropping large structures is expensive -- do this is a separate thread.
        thread::spawn(move || {
            drop(signature_verified_block); // Explicit drops to measure their cost.
            drop(placeholders);
        });

        let execute_time = std::time::Instant::now().duration_since(execute_start);
        println!(
            "Extract results. Execute time: {} ms. TPS: {}.",
            execute_time.as_millis(),
            num_txns as u128 * 1_000_000_000 / execute_time.as_nanos(),
        );
        exec_tally += execute_time.as_millis();
        println!("Exec tally: {}ms", exec_tally);

        all_results
    }

    /// Alternate form of 'execute_block' that keeps the vm_status before it goes into the
    /// `TransactionOutput`
    pub fn execute_block_and_keep_vm_status(
        transactions: Vec<Transaction>,
        state_view: &dyn StateView,
    ) -> Result<Vec<(VMStatus, TransactionOutput)>, VMStatus> {
        let mut state_view_cache = StateViewCache::new(state_view);
        let mut vm = Self::new(&state_view_cache);
        vm.execute_block_impl(transactions, &mut state_view_cache, true)
    }
}

/// Check the signature (if any) of a transaction. If the signature is OK, the result
/// is a PreprocessedTransaction, where a user transaction is translated to a
/// SignatureCheckedTransaction and also categorized into either a UserTransaction
/// or a WriteSet transaction.
pub(crate) fn preprocess_transaction(txn: Transaction) -> PreprocessedTransaction {
    match txn {
        Transaction::BlockMetadata(b) => PreprocessedTransaction::BlockMetadata(b),
        Transaction::GenesisTransaction(ws) => PreprocessedTransaction::WaypointWriteSet(ws),
        Transaction::UserTransaction(txn) => {
            let checked_txn = if let Ok(checked_txn) = txn.check_signature() {
                checked_txn
            } else {
                return PreprocessedTransaction::InvalidSignature;
            };
            if let TransactionPayload::WriteSet(_) = checked_txn.payload() {
                PreprocessedTransaction::WriteSet(Box::new(checked_txn))
            } else {
                PreprocessedTransaction::UserTransaction(Box::new(checked_txn))
            }
        }
    }
}

fn is_reconfiguration(vm_output: &TransactionOutput) -> bool {
    let new_epoch_event_key = diem_types::on_chain_config::new_epoch_event_key();
    vm_output
        .events()
        .iter()
        .any(|event| *event.key() == new_epoch_event_key)
}

/// Transactions after signature checking:
/// Waypoints and BlockPrologues are not signed and are unaffected by signature checking,
/// but a user transaction or writeset transaction is transformed to a SignatureCheckedTransaction.
#[derive(Debug)]
pub(crate) enum PreprocessedTransaction {
    UserTransaction(Box<SignatureCheckedTransaction>),
    WaypointWriteSet(WriteSetPayload),
    BlockMetadata(BlockMetadata),
    WriteSet(Box<SignatureCheckedTransaction>),
    InvalidSignature,
}

// Executor external API
impl VMExecutor for DiemVM {
    /// Execute a block of `transactions`. The output vector will have the exact same length as the
    /// input vector. The discarded transactions will be marked as `TransactionStatus::Discard` and
    /// have an empty `WriteSet`. Also `state_view` is immutable, and does not have interior
    /// mutability. Writes to be applied to the data view are encoded in the write set part of a
    /// transaction output.
    fn execute_block(
        transactions: Vec<Transaction>,
        state_view: &dyn StateView,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        fail_point!("move_adapter::execute_block", |_| {
            Err(VMStatus::Error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
            ))
        });

        let output = DiemVM_::execute_block_and_keep_vm_status(transactions, state_view)?;
        Ok(output
            .into_iter()
            .map(|(_vm_status, txn_output)| txn_output)
            .collect())
    }
}

pub(crate) fn discard_error_vm_status(err: VMStatus) -> (VMStatus, TransactionOutput) {
    let vm_status = err.clone();
    let error_code = match err.keep_or_discard() {
        Ok(_) => {
            debug_assert!(false, "discarding non-discardable error: {:?}", vm_status);
            vm_status.status_code()
        }
        Err(code) => code,
    };
    (vm_status, discard_error_output(error_code))
}

pub(crate) fn discard_error_output(err: StatusCode) -> TransactionOutput {
    // Since this transaction will be discarded, no writeset will be included.
    TransactionOutput::new(
        WriteSet::default(),
        vec![],
        0,
        TransactionStatus::Discard(err),
    )
}

impl AsRef<DiemVMImpl> for DiemVM_ {
    fn as_ref(&self) -> &DiemVMImpl {
        &self.0
    }
}

impl AsMut<DiemVMImpl> for DiemVM_ {
    fn as_mut(&mut self) -> &mut DiemVMImpl {
        &mut self.0
    }
}

// Structure that holds infered read/write sets
#[derive(Clone)]
enum ScriptReadWriteSetVar {
    Const,
    Param(usize),
}

#[derive(Clone)]
pub struct ScriptReadWriteSet {
    reads: Vec<(ScriptReadWriteSetVar, AccessPath)>,
    writes: Vec<(ScriptReadWriteSetVar, AccessPath)>,
}

impl ScriptReadWriteSet {
    // Given a set of address parameters, by convention [Sender, Address, Address, ...], and some read and write
    // access paths, it infers which are static and which dynamic, stores the structure to allow inference about others.
    pub fn new(
        params: Vec<AccountAddress>,
        reads: Vec<AccessPath>,
        writes: Vec<AccessPath>,
    ) -> ScriptReadWriteSet {
        ScriptReadWriteSet {
            reads: reads
                .into_iter()
                .map(|path| {
                    let var = match params.iter().position(|&x| x == path.address) {
                        None => ScriptReadWriteSetVar::Const,
                        Some(i) => ScriptReadWriteSetVar::Param(i),
                    };
                    (var, path)
                })
                .collect(),
            writes: writes
                .into_iter()
                .map(|path| {
                    let var = match params.iter().position(|&x| x == path.address) {
                        None => ScriptReadWriteSetVar::Const,
                        Some(i) => ScriptReadWriteSetVar::Param(i),
                    };
                    (var, path)
                })
                .collect(),
        }
    }

    // Return the read access paths specialized for these parameters
    // TODO: return a result in case the params are not long enough.
    pub fn reads<'a>(&'a self, params: &'a Vec<AccountAddress>) -> ScriptReadWriteSetVarIter {
        return ScriptReadWriteSetVarIter::new(&self.reads, params);
    }

    // Return the write access paths specialized for these parameters
    // TODO: return a result in case the params are not long enough.
    pub fn writes<'a>(&'a self, params: &'a Vec<AccountAddress>) -> ScriptReadWriteSetVarIter<'a> {
        return ScriptReadWriteSetVarIter::new(&self.writes, params);
    }
}

pub struct ScriptReadWriteSetVarIter<'a> {
    // A link to the array we iterate over
    array: &'a Vec<(ScriptReadWriteSetVar, AccessPath)>,
    // The parameters we use to popular the read-write set
    params: &'a Vec<AccountAddress>,
    // the position we are in the array.
    seq: usize,
}

impl<'a> ScriptReadWriteSetVarIter<'a> {
    fn new(
        array: &'a Vec<(ScriptReadWriteSetVar, AccessPath)>,
        params: &'a Vec<AccountAddress>,
    ) -> ScriptReadWriteSetVarIter<'a> {
        ScriptReadWriteSetVarIter {
            array,
            params,
            seq: 0,
        }
    }
}

impl<'a> Iterator for ScriptReadWriteSetVarIter<'a> {
    // we will be counting with usize
    type Item = AccessPath;

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        if self.seq < self.array.len() {
            let (v, p) = &self.array[self.seq];
            let current_item = match v {
                ScriptReadWriteSetVar::Const => p.clone(),
                ScriptReadWriteSetVar::Param(i) => {
                    let mut p = p.clone();
                    p.address = self.params[*i];
                    p
                }
            };
            self.seq += 1;
            Some(current_item)
        } else {
            None
        }
    }
}
