// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    data_cache::{MoveStorage, TransactionDataCache},
    interpreter::Interpreter,
    loader::Loader,
    native_functions::{NativeFunction, NativeFunctions},
    session::Session,
};
use move_binary_format::{
    access::ModuleAccess,
    compatibility::Compatibility,
    errors::{verification_error, Location, PartialVMError, PartialVMResult, VMResult},
    file_format_common::VERSION_1,
    normalized, CompiledModule, IndexKind,
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, TypeTag},
    value::{MoveTypeLayout, MoveValue},
    vm_status::StatusCode,
};
use move_vm_types::{
    data_store::DataStore, gas_schedule::GasStatus, loaded_data::runtime_types::Type, values::Value,
};
use std::collections::BTreeSet;
use tracing::warn;

/// An instantiation of the MoveVM.
pub(crate) struct VMRuntime {
    loader: Loader,
}

// signer helper closure
fn is_signer_reference(s: &Type) -> bool {
    match s {
        Type::Reference(ty) => matches!(&**ty, Type::Signer),
        _ => false,
    }
}

impl VMRuntime {
    pub(crate) fn new<I>(natives: I) -> PartialVMResult<Self>
    where
        I: IntoIterator<Item = (AccountAddress, Identifier, Identifier, NativeFunction)>,
    {
        Ok(VMRuntime {
            loader: Loader::new(NativeFunctions::new(natives)?),
        })
    }

    pub fn new_session<'r, S: MoveStorage>(&self, remote: &'r S) -> Session<'r, '_, S> {
        Session {
            runtime: self,
            data_cache: TransactionDataCache::new(remote, &self.loader),
        }
    }

    pub(crate) fn publish_module_bundle(
        &self,
        modules: Vec<Vec<u8>>,
        sender: AccountAddress,
        data_store: &mut impl DataStore,
        _gas_status: &mut GasStatus,
    ) -> VMResult<()> {
        // deserialize the modules. Perform bounds check. After this indexes can be
        // used with the `[]` operator
        let compiled_modules = match modules
            .iter()
            .map(|blob| CompiledModule::deserialize(blob))
            .collect::<PartialVMResult<Vec<_>>>()
        {
            Ok(modules) => modules,
            Err(err) => {
                warn!("[VM] module deserialization failed {:?}", err);
                return Err(err.finish(Location::Undefined));
            }
        };

        // Make sure all modules' self addresses matches the transaction sender. The self address is
        // where the module will actually be published. If we did not check this, the sender could
        // publish a module under anyone's account.
        for module in &compiled_modules {
            if module.address() != &sender {
                return Err(verification_error(
                    StatusCode::MODULE_ADDRESS_DOES_NOT_MATCH_SENDER,
                    IndexKind::AddressIdentifier,
                    module.self_handle_idx().0,
                )
                .finish(Location::Undefined));
            }
        }

        // Collect ids for modules that are published together
        let mut bundle_unverified = BTreeSet::new();

        // For now, we assume that all modules can be republished, as long as the new module is
        // backward compatible with the old module.
        //
        // TODO: in the future, we may want to add restrictions on module republishing, possibly by
        // changing the bytecode format to include an `is_upgradable` flag in the CompiledModule.
        for module in &compiled_modules {
            let module_id = module.self_id();
            if data_store.exists_module(&module_id)? {
                let old_module_ref = self
                    .loader
                    .load_module_expect_not_missing(&module_id, data_store)?;
                let old_module = old_module_ref.module();
                let old_m = normalized::Module::new(old_module);
                let new_m = normalized::Module::new(&module);
                let compat = Compatibility::check(&old_m, &new_m);
                if !compat.is_fully_compatible() {
                    return Err(PartialVMError::new(
                        StatusCode::BACKWARD_INCOMPATIBLE_MODULE_UPDATE,
                    )
                    .finish(Location::Undefined));
                }
            }
            if !bundle_unverified.insert(module_id) {
                return Err(PartialVMError::new(StatusCode::DUPLICATE_MODULE_NAME)
                    .finish(Location::Undefined));
            }
        }

        // Perform bytecode and loading verification. Modules must be sorted in topological order.
        self.loader
            .verify_module_bundle_for_publication(&compiled_modules, data_store)?;

        // NOTE: we want to (informally) argue that all modules pass the linking check before being
        // published to the data store.
        //
        // The linking check consists of two checks actually
        // - dependencies::verify_module(module, all_imm_deps)
        // - cyclic_dependencies::verify_module(module, fn_imm_deps, fn_imm_friends)
        //
        // [Claim 1]
        // We show that the `dependencies::verify_module` check is always satisfied whenever a
        // module M is published or updated and the `all_imm_deps` contains the actual modules
        // required by M.
        //
        // Suppose M depends on D, and we now consider the following scenarios:
        // 1) D does not appear in the bundle together with M
        // -- In this case, D must be either in the code cache or in the data store which can be
        //    loaded into the code cache (and pass all checks on D).
        //    - If D is missing, the linking will fail and return an error.
        //    - If D exists, D will be added to the `all_imm_deps` arg when checking M.
        //
        // 2) D appears in the bundle *before* M
        // -- In this case, regardless of whether D is in code cache or not, D will be put into the
        //    `bundle_verified` argument and modules in `bundle_verified` will be prioritized before
        //    returning a module in code cache.
        //
        // 3) D appears in the bundle *after* M
        // -- This technically should be discouraged but this is user input so we cannot have this
        //    assumption here. But nevertheless, we can still make the claim 1 even in this case.
        //    When M is verified, flow 1) is effectively activated, which means:
        //    - If the code cache or the data store does not contain a D' which has the same name
        //      with D, then the linking will fail and return an error.
        //    - If D' exists, and M links against D', then when verifying D in a later time point,
        //      a compatibility check will be invoked to ensure that D is compatible with D',
        //      meaning, whichever module that links against D' will have to link against D as well.
        //
        // [Claim 2]
        // We show that the `cyclic_dependencies::verify_module` check is always satisfied whenever
        // a module M is published or updated and the dep/friend modules returned by the transitive
        // dependency closure functions are valid.
        //
        // Currently, the code is written in a way that, from the view point of the
        // `cyclic_dependencies::verify_module` check, modules checked prior to module M in the same
        // bundle looks as if they have already been published and loaded to the code cache.
        //
        // Therefore, if M forms a cyclic dependency with module A in the same bundle that is
        // checked prior to M, such an error will be detected. However, if M forms a cyclic
        // dependency with a module X that appears in the same bundle *after* M. The cyclic
        // dependency can only be caught when X is verified.
        //
        // In summary: the code is written in a way that, certain checks are skipped while checking
        // each individual module in the bundle in order. But if every module in the bundle pass
        // all the checks, then the whole bundle can be published/upgraded together. Otherwise,
        // none of the module can be published/updated.

        // All modules verified, publish them to data cache
        for (module, blob) in compiled_modules.into_iter().zip(modules.into_iter()) {
            data_store.publish_module(&module.self_id(), blob)?;
        }
        Ok(())
    }

    fn deserialize_args(
        &self,
        _file_format_version: u32,
        tys: &[Type],
        args: Vec<Vec<u8>>,
    ) -> PartialVMResult<Vec<Value>> {
        if tys.len() != args.len() {
            return Err(
                PartialVMError::new(StatusCode::NUMBER_OF_ARGUMENTS_MISMATCH).with_message(
                    format!(
                        "argument length mismatch: expected {} got {}",
                        tys.len(),
                        args.len()
                    ),
                ),
            );
        }

        // Deserialize arguments. This operation will fail if the parameter type is not deserializable.
        //
        // Special rule: `&signer` can be created from data with the layout of `signer`.
        let mut vals = vec![];
        for (ty, arg) in tys.iter().zip(args.into_iter()) {
            let val = if is_signer_reference(ty) {
                // TODO signer_reference should be version gated
                match MoveValue::simple_deserialize(&arg, &MoveTypeLayout::Signer) {
                    Ok(MoveValue::Signer(addr)) => Value::signer_reference(addr),
                    Ok(_) | Err(_) => {
                        warn!("[VM] failed to deserialize argument");
                        return Err(PartialVMError::new(
                            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
                        ));
                    }
                }
            } else {
                let layout = match self.loader.type_to_type_layout(ty) {
                    Ok(layout) => layout,
                    Err(_err) => {
                        warn!("[VM] failed to get layout from type");
                        return Err(PartialVMError::new(
                            StatusCode::INVALID_PARAM_TYPE_FOR_DESERIALIZATION,
                        ));
                    }
                };

                match Value::simple_deserialize(&arg, &layout) {
                    Some(val) => val,
                    None => {
                        warn!("[VM] failed to deserialize argument");
                        return Err(PartialVMError::new(
                            StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
                        ));
                    }
                }
            };
            vals.push(val)
        }

        Ok(vals)
    }

    fn create_signers_and_arguments(
        &self,
        file_format_version: u32,
        tys: &[Type],
        senders: Vec<AccountAddress>,
        args: Vec<Vec<u8>>,
    ) -> PartialVMResult<Vec<Value>> {
        fn number_of_signer_params(file_format_version: u32, tys: &[Type]) -> usize {
            let is_signer = if file_format_version <= VERSION_1 {
                |ty: &Type| matches!(ty, Type::Reference(inner) if matches!(&**inner, Type::Signer))
            } else {
                |ty: &Type| matches!(ty, Type::Signer)
            };
            for (i, ty) in tys.iter().enumerate() {
                if !is_signer(ty) {
                    return i;
                }
            }
            tys.len()
        }

        // Build the arguments list and check the arguments are of restricted types.
        // Signers are built up from left-to-right. Either all signer arguments are used, or no
        // signer arguments can be be used by a script.
        let n_signer_params = number_of_signer_params(file_format_version, tys);

        let args = if n_signer_params == 0 {
            self.deserialize_args(file_format_version, &tys, args)?
        } else {
            let n_signers = senders.len();
            if n_signer_params != n_signers {
                return Err(
                    PartialVMError::new(StatusCode::NUMBER_OF_SIGNER_ARGUMENTS_MISMATCH)
                        .with_message(format!(
                            "Expected {} signer args got {}",
                            n_signer_params, n_signers
                        )),
                );
            }
            let make_signer = if file_format_version <= VERSION_1 {
                Value::signer_reference
            } else {
                Value::signer
            };
            let mut vals: Vec<Value> = senders.into_iter().map(make_signer).collect();
            vals.extend(self.deserialize_args(file_format_version, &tys[n_signers..], args)?);
            vals
        };

        Ok(args)
    }

    // See Session::execute_script for what contracts to follow.
    pub(crate) fn execute_script(
        &self,
        script: Vec<u8>,
        ty_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
        senders: Vec<AccountAddress>,
        data_store: &mut impl DataStore,
        gas_status: &mut GasStatus,
    ) -> VMResult<()> {
        // load the script, perform verification
        let (main, ty_args, params) = self.loader.load_script(&script, &ty_args, data_store)?;

        let signers_and_args = self
            .create_signers_and_arguments(main.file_format_version(), &params, senders, args)
            .map_err(|err| err.finish(Location::Undefined))?;
        // run the script
        let return_vals = Interpreter::entrypoint(
            main,
            ty_args,
            signers_and_args,
            data_store,
            gas_status,
            &self.loader,
        )?;

        if !return_vals.is_empty() {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(
                        "scripts cannot have return values -- this should not happen".to_string(),
                    )
                    .finish(Location::Undefined),
            );
        }

        Ok(())
    }

    fn execute_function_impl<F>(
        &self,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        make_args: F,
        is_script_execution: bool,
        data_store: &mut impl DataStore,
        gas_status: &mut GasStatus,
    ) -> VMResult<Vec<Vec<u8>>>
    where
        F: FnOnce(&VMRuntime, u32, &[Type]) -> PartialVMResult<Vec<Value>>,
    {
        let (func, ty_args, params, return_tys) = self.loader.load_function(
            function_name,
            module,
            &ty_args,
            is_script_execution,
            data_store,
        )?;

        let return_layouts = return_tys
            .iter()
            .map(|ty| {
                self.loader.type_to_type_layout(ty).map_err(|_err| {
                    PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR)
                        .with_message(
                            "cannot be called with non-serializable return type".to_string(),
                        )
                        .finish(Location::Undefined)
                })
            })
            .collect::<VMResult<Vec<_>>>()?;

        let params = params
            .into_iter()
            .map(|ty| ty.subst(&ty_args))
            .collect::<PartialVMResult<Vec<_>>>()
            .map_err(|err| err.finish(Location::Undefined))?;

        let args = make_args(self, func.file_format_version(), &params)
            .map_err(|err| err.finish(Location::Undefined))?;

        let return_vals =
            Interpreter::entrypoint(func, ty_args, args, data_store, gas_status, &self.loader)?;

        if return_layouts.len() != return_vals.len() {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(format!(
                        "declared {} return types, but got {} return values",
                        return_layouts.len(),
                        return_vals.len()
                    ))
                    .finish(Location::Undefined),
            );
        }

        let mut serialized_vals = vec![];
        for (val, layout) in return_vals.into_iter().zip(return_layouts.iter()) {
            serialized_vals.push(val.simple_serialize(&layout).ok_or_else(|| {
                PartialVMError::new(StatusCode::INTERNAL_TYPE_ERROR)
                    .with_message("failed to serialize return values".to_string())
                    .finish(Location::Undefined)
            })?)
        }

        Ok(serialized_vals)
    }

    // See Session::execute_script_function for what contracts to follow.
    pub(crate) fn execute_script_function(
        &self,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
        senders: Vec<AccountAddress>,
        data_store: &mut impl DataStore,
        gas_status: &mut GasStatus,
    ) -> VMResult<()> {
        let return_vals = self.execute_function_impl(
            module,
            function_name,
            ty_args,
            move |runtime, version, params| {
                runtime.create_signers_and_arguments(version, params, senders, args)
            },
            true,
            data_store,
            gas_status,
        )?;

        // A script function that serves as the entry point of execution cannot have return values,
        // this is checked dynamically when the function is loaded. Hence, if the execution ever
        // reaches here, it is an invariant violation
        if !return_vals.is_empty() {
            return Err(
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(
                        "script functions that serve as execution entry points cannot have \
                        return values -- this should not happen"
                            .to_string(),
                    )
                    .finish(Location::Undefined),
            );
        }

        Ok(())
    }

    // See Session::execute_function for what contracts to follow.
    pub(crate) fn execute_function(
        &self,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
        data_store: &mut impl DataStore,
        gas_status: &mut GasStatus,
    ) -> VMResult<Vec<Vec<u8>>> {
        self.execute_function_impl(
            module,
            function_name,
            ty_args,
            move |runtime, version, params| runtime.deserialize_args(version, params, args),
            false,
            data_store,
            gas_status,
        )
    }
}
