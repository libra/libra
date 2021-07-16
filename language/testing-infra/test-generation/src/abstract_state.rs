// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{borrow_graph::BorrowGraph, error::VMError};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{
        empty_module, Ability, AbilitySet, CompiledModule, FieldInstantiation,
        FieldInstantiationIndex, FunctionHandleIndex, FunctionInstantiation,
        FunctionInstantiationIndex, Signature, SignatureIndex, SignatureToken,
        StructDefInstantiation, StructDefInstantiationIndex, StructDefinitionIndex, TableIndex,
    },
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

/// The BorrowState denotes whether a local is `Available` or
/// has been moved and is `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BorrowState {
    Available,
    Unavailable,
}

/// This models a value on the stack or in the locals
#[derive(Debug, Clone, PartialEq)]
pub struct AbstractValue {
    /// Represents the type of the value
    pub token: SignatureToken,

    /// Represents the abilities of the value
    pub abilities: AbilitySet,
}

/// This models the mutability of a reference
#[derive(Debug, Clone, PartialEq)]
pub enum Mutability {
    /// Represents a mutable reference
    Mutable,

    /// Represents an immutable reference
    Immutable,

    /// When we don't need to specify whether
    /// the reference is mutable or immutable
    Either,
}

impl AbstractValue {
    /// Create a new primitive `AbstractValue` given its type; the kind will be `Copyable`
    pub fn new_primitive(token: SignatureToken) -> AbstractValue {
        checked_precondition!(
            match token {
                SignatureToken::Struct(_)
                | SignatureToken::StructInstantiation(_, _)
                | SignatureToken::Reference(_)
                | SignatureToken::MutableReference(_)
                | SignatureToken::Signer
                | SignatureToken::Vector(_)
                | SignatureToken::TypeParameter(_) => false,
                SignatureToken::Bool
                | SignatureToken::Address
                | SignatureToken::U8
                | SignatureToken::U64
                | SignatureToken::U128 => true,
            },
            "AbstractValue::new_primitive must be applied with primitive type"
        );
        AbstractValue {
            token,
            abilities: AbilitySet::PRIMITIVES,
        }
    }

    /// Create a new reference `AbstractValue` given its type and kind
    pub fn new_reference(token: SignatureToken, abilities: AbilitySet) -> AbstractValue {
        checked_precondition!(
            matches!(
                token,
                SignatureToken::Reference(_) | SignatureToken::MutableReference(_)
            ),
            "AbstractValue::new_reference must be applied with a reference type"
        );
        AbstractValue { token, abilities }
    }

    /// Create a new struct `AbstractValue` given its type and kind
    pub fn new_struct(token: SignatureToken, abilities: AbilitySet) -> AbstractValue {
        checked_precondition!(
            matches!(token, SignatureToken::Struct(_)),
            "AbstractValue::new_struct must be applied with a struct type"
        );
        AbstractValue { token, abilities }
    }

    pub fn new_value(token: SignatureToken, abilities: AbilitySet) -> AbstractValue {
        AbstractValue { token, abilities }
    }

    /// Predicate on whether the type of the abstract value is generic -- it is if it contains a
    /// type parameter.
    pub fn is_generic(&self) -> bool {
        Self::is_generic_token(&self.token)
    }

    fn is_generic_token(token: &SignatureToken) -> bool {
        match token {
            SignatureToken::TypeParameter(_) => true,
            SignatureToken::StructInstantiation(_, _) => true,
            SignatureToken::Reference(tok) | SignatureToken::MutableReference(tok) => {
                Self::is_generic_token(tok)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallGraph {
    calls: HashMap<FunctionHandleIndex, HashSet<FunctionHandleIndex>>,
    max_function_handle_index: usize,
}

impl CallGraph {
    pub fn new(max_function_handle_index: usize) -> Self {
        Self {
            calls: HashMap::new(),
            max_function_handle_index,
        }
    }

    pub fn add_call(&mut self, caller: FunctionHandleIndex, callee: FunctionHandleIndex) {
        self.calls
            .entry(caller)
            .or_insert_with(HashSet::new)
            .insert(callee);
    }

    pub fn can_call(&self, my_index: FunctionHandleIndex) -> Vec<FunctionHandleIndex> {
        // We want the set of function handles that don't lead to a recursive call-graph
        (0..self.max_function_handle_index)
            .filter(|index| {
                self.call_depth(my_index, FunctionHandleIndex(*index as TableIndex))
                    .is_some()
            })
            .map(|i| FunctionHandleIndex(i as TableIndex))
            .collect()
    }

    pub fn max_calling_depth(&self, index: FunctionHandleIndex) -> usize {
        let mut instantiation_depth = 0;
        for (caller, callees) in self.calls.iter() {
            for callee in callees.iter() {
                if *callee == index {
                    let depth = self.max_calling_depth(*caller) + 1;
                    instantiation_depth = std::cmp::max(depth, instantiation_depth);
                }
            }
        }
        instantiation_depth
    }

    /// None if recursive, Some(index) if non-recursive, and index is the length of the maximal call
    /// graph path originating at caller, and calling through callee.
    pub fn call_depth(
        &self,
        caller: FunctionHandleIndex,
        callee: FunctionHandleIndex,
    ) -> Option<usize> {
        if caller == callee {
            return None;
        }
        match self.calls.get(&callee) {
            None => Some(1),
            Some(callee_callees) => {
                if callee_callees.contains(&caller) {
                    return None;
                }
                let call_depths = callee_callees
                    .iter()
                    .filter_map(|callee_callee| self.call_depth(caller, *callee_callee))
                    .collect::<Vec<_>>();
                if call_depths.len() < callee_callees.len() {
                    // We found a recursive call
                    None
                } else {
                    let max = call_depths.iter().max().unwrap();
                    Some(max + 1)
                }
            }
        }
    }
}

/// During the generation of a bytecode sequence, specific instantiations may need to be made, that
/// may not yet exist in the underlying module. Instead of mutating the underlying module in order to record these instantiations in the
/// locals signature table, we instead build wrapper around the underlying module containing the
/// type instantiations, and at the end materialize this updated signature pool into a module. We
/// also need the ability to quickly determine if an instantiation has already been created, and if
/// so, at which index. So this also keeps a reverse lookup table of instantiation to
/// SignatureIndex.
#[derive(Debug, Clone)]
pub struct InstantiableModule {
    // A reverse lookup table for instantiations.
    sig_instance_for_offset: Vec<Vec<SignatureToken>>,
    instantiations: HashMap<Vec<SignatureToken>, SignatureIndex>,

    struct_instance_for_offset: Vec<StructDefInstantiation>,
    struct_instantiations: HashMap<StructDefInstantiation, StructDefInstantiationIndex>,

    func_instance_for_offset: Vec<FunctionInstantiation>,
    function_instantiations: HashMap<FunctionInstantiation, FunctionInstantiationIndex>,

    field_instance_for_offset: Vec<FieldInstantiation>,
    field_instantiations: HashMap<FieldInstantiation, FieldInstantiationIndex>,

    pub module: CompiledModule,
}

impl InstantiableModule {
    pub fn new(module: CompiledModule) -> Self {
        Self {
            instantiations: module
                .signatures()
                .iter()
                .enumerate()
                .map(|(index, sig)| (sig.0.clone(), SignatureIndex(index as TableIndex)))
                .collect::<HashMap<_, _>>(),
            sig_instance_for_offset: module
                .signatures()
                .iter()
                .map(|loc_sig| loc_sig.0.clone())
                .collect(),

            struct_instantiations: module
                .struct_instantiations()
                .iter()
                .enumerate()
                .map(|(index, si)| (si.clone(), StructDefInstantiationIndex(index as TableIndex)))
                .collect::<HashMap<_, _>>(),
            struct_instance_for_offset: module.struct_instantiations().to_vec(),

            function_instantiations: module
                .function_instantiations()
                .iter()
                .enumerate()
                .map(|(index, fi)| (fi.clone(), FunctionInstantiationIndex(index as TableIndex)))
                .collect::<HashMap<_, _>>(),
            func_instance_for_offset: module.function_instantiations().to_vec(),

            field_instantiations: module
                .field_instantiations()
                .iter()
                .enumerate()
                .map(|(index, fi)| (fi.clone(), FieldInstantiationIndex(index as TableIndex)))
                .collect::<HashMap<_, _>>(),
            field_instance_for_offset: module.field_instantiations().to_vec(),
            module,
        }
    }

    /// If the `instantiant` is not in the `instantiations` table, this adds the instantiant to the
    /// `instance_for_offset` for table, and adds the index to the reverse lookup table. Returns
    /// the SignatureIndex for the `instantiant`.
    pub fn add_instantiation(&mut self, instantiant: Vec<SignatureToken>) -> SignatureIndex {
        match self.instantiations.get(&instantiant) {
            Some(index) => *index,
            None => {
                let current_index =
                    SignatureIndex(self.sig_instance_for_offset.len() as TableIndex);
                self.instantiations
                    .insert(instantiant.clone(), current_index);
                self.sig_instance_for_offset.push(instantiant);
                current_index
            }
        }
    }

    /// If the `instantiant` is not in the `struct_instantiations` table, this adds the
    /// instantiant to the `struct_instance_for_offset` for table, and adds the index to the
    /// reverse lookup table.
    /// Returns the SignatureIndex for the `instantiant`.
    pub fn add_struct_instantiation(
        &mut self,
        instantiant: StructDefInstantiation,
    ) -> StructDefInstantiationIndex {
        match self.struct_instantiations.get(&instantiant) {
            Some(index) => *index,
            None => {
                let current_index = StructDefInstantiationIndex(
                    self.struct_instance_for_offset.len() as TableIndex,
                );
                self.struct_instantiations
                    .insert(instantiant.clone(), current_index);
                self.struct_instance_for_offset.push(instantiant);
                current_index
            }
        }
    }

    /// If the `instantiant` is not in the `function_instantiations` table, this adds the
    /// instantiant to the `func_instance_for_offset` for table, and adds the index to the
    /// reverse lookup table.
    /// Returns the SignatureIndex for the `instantiant`.
    pub fn add_function_instantiation(
        &mut self,
        instantiant: FunctionInstantiation,
    ) -> FunctionInstantiationIndex {
        match self.function_instantiations.get(&instantiant) {
            Some(index) => *index,
            None => {
                let current_index =
                    FunctionInstantiationIndex(self.func_instance_for_offset.len() as TableIndex);
                self.function_instantiations
                    .insert(instantiant.clone(), current_index);
                self.func_instance_for_offset.push(instantiant);
                current_index
            }
        }
    }

    /// If the `instantiant` is not in the `field_instantiations` table, this adds the
    /// instantiant to the `field_instance_for_offset` for table, and adds the index to the
    /// reverse lookup table.
    /// Returns the SignatureIndex for the `instantiant`.
    pub fn add_field_instantiation(
        &mut self,
        instantiant: FieldInstantiation,
    ) -> FieldInstantiationIndex {
        match self.field_instantiations.get(&instantiant) {
            Some(index) => *index,
            None => {
                let current_index =
                    FieldInstantiationIndex(self.field_instance_for_offset.len() as TableIndex);
                self.field_instantiations
                    .insert(instantiant.clone(), current_index);
                self.field_instance_for_offset.push(instantiant);
                current_index
            }
        }
    }

    /// Returns the type instantiation at `index`. Errors if the instantiation does not exist.
    pub fn instantiantiation_at(&self, index: SignatureIndex) -> &Vec<SignatureToken> {
        match self.sig_instance_for_offset.get(index.0 as usize) {
            Some(vec) => vec,
            None => {
                panic!("Unable to get instantiation at offset: {:#?}", index);
            }
        }
    }

    /// Returns the struct instantiation at `index`. Errors if the instantiation does not exist.
    pub fn struct_instantiantiation_at(
        &self,
        index: StructDefInstantiationIndex,
    ) -> &StructDefInstantiation {
        match self.struct_instance_for_offset.get(index.0 as usize) {
            Some(struct_inst) => struct_inst,
            None => {
                panic!("Unable to get instantiation at offset: {:#?}", index);
            }
        }
    }

    /// Returns the struct instantiation at `index`. Errors if the instantiation does not exist.
    pub fn function_instantiantiation_at(
        &self,
        index: FunctionInstantiationIndex,
    ) -> &FunctionInstantiation {
        match self.func_instance_for_offset.get(index.0 as usize) {
            Some(func_inst) => func_inst,
            None => {
                panic!("Unable to get instantiation at offset: {:#?}", index);
            }
        }
    }

    /// Returns the struct instantiation at `index`. Errors if the instantiation does not exist.
    pub fn field_instantiantiation_at(
        &self,
        index: FieldInstantiationIndex,
    ) -> &FieldInstantiation {
        match self.field_instance_for_offset.get(index.0 as usize) {
            Some(field_inst) => field_inst,
            None => {
                panic!("Unable to get instantiation at offset: {:#?}", index);
            }
        }
    }

    /// Consumes self, and adds the instantiations that have been built up to the underlying
    /// module, and returns the resultant compiled module.
    pub fn instantiate(self) -> CompiledModule {
        let mut module = self.module;
        module.signatures = self
            .sig_instance_for_offset
            .into_iter()
            .map(Signature)
            .collect();
        module.struct_def_instantiations = self.struct_instance_for_offset;
        module.function_instantiations = self.func_instance_for_offset;
        module.field_instantiations = self.field_instance_for_offset;
        module
    }
}

/// An AbstractState represents an abstract view of the execution of the
/// Move VM. Rather than considering values of items on the stack or in
/// the locals, we only consider their type, represented by a `AbstractValue`
/// and their availibility, represented by the `BorrowState`.
#[derive(Debug, Clone)]
pub struct AbstractState {
    /// A Vector of `AbstractValue`s representing the VM value stack
    stack: Vec<AbstractValue>,

    /// A vector of type kinds for any generic function type parameters of the function that we are
    /// in.
    pub instantiation: Vec<AbilitySet>,

    /// A HashMap mapping local indicies to `AbstractValue`s and `BorrowState`s
    locals: HashMap<usize, (AbstractValue, BorrowState)>,

    /// Temporary location for storing the results of instruction effects for
    /// access by subsequent instructions' effects
    register: Option<AbstractValue>,

    /// The module state
    pub module: InstantiableModule,

    /// The global resources acquired by the function corresponding to this abstract state
    pub acquires_global_resources: Vec<StructDefinitionIndex>,

    /// This flag is set when applying an instruction that should result in an error
    /// in the VM runtime.
    aborted: bool,

    /// This flag controls whether or not control flow operators are allowed to be applied to the
    /// abstract state.
    control_flow_allowed: bool,

    /// This graph stores borrow information needed to ensure that bytecode instructions
    /// are memory safe
    borrow_graph: BorrowGraph,

    pub call_graph: CallGraph,
}

impl AbstractState {
    /// Create a new AbstractState with empty stack, locals, and register
    pub fn new() -> AbstractState {
        let compiled_module = empty_module();
        AbstractState {
            stack: Vec::new(),
            instantiation: Vec::new(),
            locals: HashMap::new(),
            register: None,
            module: InstantiableModule::new(compiled_module),
            acquires_global_resources: Vec::new(),
            aborted: false,
            control_flow_allowed: false,
            borrow_graph: BorrowGraph::new(0),
            call_graph: CallGraph::new(0),
        }
    }

    /// Create a new AbstractState given a list of `SignatureTokens` that will be
    /// the (available) locals that the state will have, as well as the module state
    pub fn from_locals(
        module: CompiledModule,
        locals: HashMap<usize, (AbstractValue, BorrowState)>,
        instantiation: Vec<AbilitySet>,
        acquires_global_resources: Vec<StructDefinitionIndex>,
        call_graph: CallGraph,
    ) -> AbstractState {
        let locals_len = locals.len();
        let module = InstantiableModule::new(module);
        AbstractState {
            stack: Vec::new(),
            instantiation,
            locals,
            module,
            register: None,
            acquires_global_resources,
            aborted: false,
            control_flow_allowed: false,
            borrow_graph: BorrowGraph::new(locals_len as u8),
            call_graph,
        }
    }

    /// Get the register value
    pub fn register_copy(&self) -> Option<AbstractValue> {
        self.register.clone()
    }

    /// Get the register value and set it to `None`
    pub fn register_move(&mut self) -> Option<AbstractValue> {
        let value = self.register.clone();
        self.register = None;
        value
    }

    /// Set the register value and set it to `None`
    pub fn register_set(&mut self, value: AbstractValue) {
        self.register = Some(value);
    }

    /// Add a `AbstractValue` to the stack
    pub fn stack_push(&mut self, item: AbstractValue) {
        // Programs that are large enough to exceed this bound
        // will not be generated
        assume!(self.stack.len() < usize::max_value());
        self.stack.push(item);
    }

    /// Add a `AbstractValue` to the stack from the register
    /// If the register is `None` return a `VMError`
    pub fn stack_push_register(&mut self) -> Result<(), VMError> {
        if let Some(abstract_value) = self.register_move() {
            // Programs that are large enough to exceed this bound
            // will not be generated
            assume!(self.stack.len() < usize::max_value());
            self.stack.push(abstract_value);
            Ok(())
        } else {
            Err(VMError::new("Error: No value in register".to_string()))
        }
    }

    /// Remove an `AbstractValue` from the stack if it exists to the register
    /// If it does not exist return a `VMError`.
    pub fn stack_pop(&mut self) -> Result<(), VMError> {
        if self.stack.is_empty() {
            Err(VMError::new("Pop attempted on empty stack".to_string()))
        } else {
            self.register = self.stack.pop();
            Ok(())
        }
    }

    /// Get the `AbstractValue` at index `index` on the stack if it exists.
    /// Index 0 is the top of the stack.
    pub fn stack_peek(&self, index: usize) -> Option<AbstractValue> {
        if index < self.stack.len() {
            Some(self.stack[self.stack.len() - 1 - index].clone())
        } else {
            None
        }
    }

    /// Get the length of the stack.
    pub fn stack_len(&self) -> usize {
        self.stack.len()
    }

    /// Check if the local at index `i` exists
    pub fn local_exists(&self, i: usize) -> bool {
        self.locals.get(&i).is_some()
    }

    /// Get the local at index `i` if it exists
    pub fn local_get(&self, i: usize) -> Option<&(AbstractValue, BorrowState)> {
        self.locals.get(&i)
    }

    /// Place the local at index `i` if it exists into the register
    /// If it does not exist return a `VMError`.
    pub fn local_take(&mut self, i: usize) -> Result<(), VMError> {
        if let Some((abstract_value, _)) = self.locals.get(&i) {
            self.register = Some(abstract_value.clone());
            Ok(())
        } else {
            Err(VMError::new(format!("Local does not exist at index {}", i)))
        }
    }

    /// Place a reference to the local at index `i` if it exists into the register
    /// If it does not exist return a `VMError`.
    pub fn local_take_borrow(&mut self, i: usize, mutability: Mutability) -> Result<(), VMError> {
        if let Some((abstract_value, _)) = self.locals.get(&i) {
            let ref_token = match mutability {
                Mutability::Mutable => {
                    SignatureToken::MutableReference(Box::new(abstract_value.token.clone()))
                }
                Mutability::Immutable => {
                    SignatureToken::Reference(Box::new(abstract_value.token.clone()))
                }
                Mutability::Either => {
                    return Err(VMError::new("Mutability cannot be Either".to_string()))
                }
            };
            self.register = Some(AbstractValue::new_reference(
                ref_token,
                abstract_value.abilities,
            ));
            Ok(())
        } else {
            Err(VMError::new(format!("Local does not exist at index {}", i)))
        }
    }

    /// Set the availability of the local at index `i`
    /// If it does not exist return a `VMError`.
    pub fn local_set(&mut self, i: usize, availability: BorrowState) -> Result<(), VMError> {
        if let Some((abstract_value, _)) = self.locals.clone().get(&i) {
            self.locals
                .insert(i, (abstract_value.clone(), availability));
            Ok(())
        } else {
            Err(VMError::new(format!("Local does not exist at index {}", i)))
        }
    }

    /// Check whether a local is in a particular `BorrowState`
    /// If the local does not exist return a `VMError`.
    pub fn local_availability_is(
        &self,
        i: usize,
        availability: BorrowState,
    ) -> Result<bool, VMError> {
        if let Some((_, availability1)) = self.locals.get(&i) {
            Ok(availability == *availability1)
        } else {
            Err(VMError::new(format!("Local does not exist at index {}", i)))
        }
    }

    /// Check whether a local has a particular `Ability`
    /// If the local does not exist return a `VMError`.
    pub fn local_has_ability(&self, i: usize, ability: Ability) -> Result<bool, VMError> {
        if let Some((abstract_value, _)) = self.locals.get(&i) {
            Ok(abstract_value.abilities.has_ability(ability))
        } else {
            Err(VMError::new(format!("Local does not exist at index {}", i)))
        }
    }

    /// Insert a local at index `i` as `Available`
    pub fn local_insert(
        &mut self,
        i: usize,
        abstract_value: AbstractValue,
        availability: BorrowState,
    ) {
        self.locals.insert(i, (abstract_value, availability));
    }

    /// Insert a local at index `i` as `Available` from the register
    /// If the register value is `None` return a `VMError`.
    pub fn local_place(&mut self, i: usize) -> Result<(), VMError> {
        if let Some(abstract_value) = self.register_move() {
            self.locals
                .insert(i, (abstract_value, BorrowState::Available));
            Ok(())
        } else {
            Err(VMError::new(
                "Could not insert local, register is empty".to_string(),
            ))
        }
    }

    /// Get all of the locals
    pub fn get_locals(&self) -> &HashMap<usize, (AbstractValue, BorrowState)> {
        &self.locals
    }

    /// Set the abstract state to be `aborted` when a precondition of an instruction
    /// fails. (This will happen if `NEGATE_PRECONDITIONs` is true).
    pub fn abort(&mut self) {
        self.aborted = true;
    }

    /// Whether the state is aborted
    pub fn has_aborted(&self) -> bool {
        self.aborted
    }

    /// Set the abstract state to allow generation of control flow operations.
    pub fn allow_control_flow(&mut self) {
        self.control_flow_allowed = true;
    }

    /// Predicate determining if control flow instructions can be generated.
    pub fn is_control_flow_allowed(&self) -> bool {
        self.control_flow_allowed
    }

    /// The final state is one where the stack is empty
    pub fn is_final(&self) -> bool {
        self.stack.is_empty()
    }
}

impl fmt::Display for AbstractState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Stack: {:?} | Locals: {:?} | Instantiation: {:?}",
            self.stack, self.locals, self.instantiation
        )
    }
}

impl Default for AbstractState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AbstractValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:?}: {:?})", self.token, self.abilities)
    }
}
