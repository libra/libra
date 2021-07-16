// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Provides a model for a set of Move modules (and scripts, which
//! are handled like modules). The model allows to access many different aspects of the Move
//! code: all declared functions and types, their associated bytecode, their source location,
//! their source text, and the specification fragments.
//!
//! The environment is nested into a hierarchy:
//!
//! - A `GlobalEnv` which gives access to all modules plus other information on global level,
//!   and is the owner of all related data.
//! - A `ModuleEnv` which is a reference to the data of some module in the environment.
//! - A `StructEnv` which is a reference to the data of some struct in a module.
//! - A `FunctionEnv` which is a reference to the data of some function in a module.

use std::{
    any::{Any, TypeId},
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt::{self, Formatter},
    rc::Rc,
};

use codespan::{
    ByteIndex, ByteOffset, ColumnOffset, FileId, Files, LineOffset, Location, Span,
    SpanOutOfBoundsError,
};
use codespan_reporting::{
    diagnostic::{Diagnostic, Label, Severity},
    term::{emit, termcolor::WriteColor, Config},
};
use itertools::Itertools;
#[allow(unused_imports)]
use log::{info, warn};
use num::{BigUint, One, ToPrimitive};
use serde::{Deserialize, Serialize};

use bytecode_source_map::{mapping::SourceMapping, source_map::SourceMap};
use disassembler::disassembler::{Disassembler, DisassemblerOptions};
use move_binary_format::{
    access::ModuleAccess,
    binary_views::BinaryIndexedView,
    file_format::{
        AddressIdentifierIndex, Bytecode, Constant as VMConstant, ConstantPoolIndex,
        FunctionDefinitionIndex, FunctionHandleIndex, SignatureIndex, SignatureToken,
        StructDefinitionIndex, StructFieldInformation, StructHandleIndex, Visibility,
    },
    views::{
        FieldDefinitionView, FunctionDefinitionView, FunctionHandleView, SignatureTokenView,
        StructDefinitionView, StructHandleView,
    },
    CompiledModule,
};
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, language_storage, value::MoveValue,
};

use crate::{
    ast::{
        ConditionKind, ExpData, GlobalInvariant, ModuleName, PropertyBag, PropertyValue, Spec,
        SpecBlockInfo, SpecFunDecl, SpecVarDecl, Value,
    },
    pragmas::{
        DELEGATE_INVARIANTS_TO_CALLER_PRAGMA, DISABLE_INVARIANTS_IN_BODY_PRAGMA, FRIEND_PRAGMA,
        INTRINSIC_PRAGMA, OPAQUE_PRAGMA, VERIFY_PRAGMA,
    },
    symbol::{Symbol, SymbolPool},
    ty::{PrimitiveType, Type, TypeDisplayContext},
};

// import and re-expose symbols
use crate::ast::Exp;
pub use move_binary_format::file_format::{AbilitySet, Visibility as FunctionVisibility};

// =================================================================================================
/// # Constants

/// A name we use to represent a script as a module.
pub const SCRIPT_MODULE_NAME: &str = "<SELF>";

/// Names used in the bytecode/AST to represent the main function of a script
pub const SCRIPT_BYTECODE_FUN_NAME: &str = "<SELF>";

// =================================================================================================
/// # Locations

/// A location, consisting of a FileId and a span in this file.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Loc {
    file_id: FileId,
    span: Span,
}

impl Loc {
    pub fn new(file_id: FileId, span: Span) -> Loc {
        Loc { file_id, span }
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    // Delivers a location pointing to the end of this one.
    pub fn at_end(&self) -> Loc {
        if self.span.end() > ByteIndex(0) {
            Loc::new(
                self.file_id,
                Span::new(self.span.end() - ByteOffset(1), self.span.end()),
            )
        } else {
            self.clone()
        }
    }

    // Delivers a location pointing to the start of this one.
    pub fn at_start(&self) -> Loc {
        Loc::new(
            self.file_id,
            Span::new(self.span.start(), self.span.start() + ByteOffset(1)),
        )
    }

    /// Creates a location which encloses all the locations in the provided slice,
    /// which must not be empty. All locations are expected to be in the same file.
    pub fn enclosing(locs: &[&Loc]) -> Loc {
        assert!(!locs.is_empty());
        let loc = locs[0];
        let mut start = loc.span.start();
        let mut end = loc.span.end();
        for l in locs.iter().skip(1) {
            if l.file_id() == loc.file_id() {
                start = std::cmp::min(start, l.span().start());
                end = std::cmp::max(end, l.span().end());
            }
        }
        Loc::new(loc.file_id(), Span::new(start, end))
    }
}

impl Default for Loc {
    fn default() -> Self {
        let mut files = Files::new();
        let dummy_id = files.add(String::new(), String::new());
        Loc::new(dummy_id, Span::default())
    }
}

/// Alias for the Loc variant of MoveIR. This uses a `&static str` instead of `FileId` for the
/// file name.
pub type MoveIrLoc = move_ir_types::location::Loc;

// =================================================================================================
/// # Identifiers
///
/// Identifiers are opaque values used to reference entities in the environment.
///
/// We have two kinds of ids: those based on an index, and those based on a symbol. We use
/// the symbol based ids where we do not have control of the definition index order in bytecode
/// (i.e. we do not know in which order move-lang enters functions and structs into file format),
/// and index based ids where we do have control (for modules, SpecFun and SpecVar).
///
/// In any case, ids are opaque in the sense that if someone has a StructId or similar in hand,
/// it is known to be defined in the environment, as it has been obtained also from the environment.

/// Raw index type used in ids. 16 bits are sufficient currently.
pub type RawIndex = u16;

/// Identifier for a module.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct ModuleId(RawIndex);

/// Identifier for a named constant, relative to module.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct NamedConstantId(Symbol);

/// Identifier for a structure/resource, relative to module.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct StructId(Symbol);

/// Identifier for a field of a structure, relative to struct.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct FieldId(Symbol);

/// Identifier for a Move function, relative to module.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct FunId(Symbol);

/// Identifier for a schema.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SchemaId(Symbol);

/// Identifier for a specification function, relative to module.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SpecFunId(RawIndex);

/// Identifier for a specification variable, relative to module.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SpecVarId(RawIndex);

/// Identifier for a node in the AST, relative to a module. This is used to associate attributes
/// with the node, like source location and type.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct NodeId(usize);

/// A global id. Instances of this type represent unique identifiers relative to `GlobalEnv`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct GlobalId(usize);

/// Some identifier qualified by a module.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct QualifiedId<Id> {
    pub module_id: ModuleId,
    pub id: Id,
}

/// Some identifier qualified by a module and a type instantiation.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct QualifiedInstId<Id> {
    pub module_id: ModuleId,
    pub inst: Vec<Type>,
    pub id: Id,
}

impl NamedConstantId {
    pub fn new(sym: Symbol) -> Self {
        Self(sym)
    }

    pub fn symbol(self) -> Symbol {
        self.0
    }
}

impl FunId {
    pub fn new(sym: Symbol) -> Self {
        Self(sym)
    }

    pub fn symbol(self) -> Symbol {
        self.0
    }
}

impl SchemaId {
    pub fn new(sym: Symbol) -> Self {
        Self(sym)
    }

    pub fn symbol(self) -> Symbol {
        self.0
    }
}

impl StructId {
    pub fn new(sym: Symbol) -> Self {
        Self(sym)
    }

    pub fn symbol(self) -> Symbol {
        self.0
    }
}

impl FieldId {
    pub fn new(sym: Symbol) -> Self {
        Self(sym)
    }

    pub fn symbol(self) -> Symbol {
        self.0
    }
}

impl SpecFunId {
    pub fn new(idx: usize) -> Self {
        Self(idx as RawIndex)
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl SpecVarId {
    pub fn new(idx: usize) -> Self {
        Self(idx as RawIndex)
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl NodeId {
    pub fn new(idx: usize) -> Self {
        Self(idx)
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl ModuleId {
    pub fn new(idx: usize) -> Self {
        Self(idx as RawIndex)
    }

    pub fn to_usize(self) -> usize {
        self.0 as usize
    }
}

impl GlobalId {
    pub fn new(idx: usize) -> Self {
        Self(idx)
    }

    pub fn as_usize(self) -> usize {
        self.0
    }
}

impl ModuleId {
    pub fn qualified<Id>(self, id: Id) -> QualifiedId<Id> {
        QualifiedId {
            module_id: self,
            id,
        }
    }

    pub fn qualified_inst<Id>(self, id: Id, inst: Vec<Type>) -> QualifiedInstId<Id> {
        QualifiedInstId {
            module_id: self,
            inst,
            id,
        }
    }
}

impl<Id: Clone> QualifiedId<Id> {
    pub fn instantiate(self, inst: Vec<Type>) -> QualifiedInstId<Id> {
        let QualifiedId { module_id, id } = self;
        QualifiedInstId {
            module_id,
            inst,
            id,
        }
    }
}

impl<Id: Clone> QualifiedInstId<Id> {
    pub fn instantiate(self, params: &[Type]) -> Self {
        if params.is_empty() {
            self
        } else {
            let Self {
                module_id,
                inst,
                id,
            } = self;
            Self {
                module_id,
                inst: Type::instantiate_vec(inst, params),
                id,
            }
        }
    }

    pub fn instantiate_ref(&self, params: &[Type]) -> Self {
        let res = self.clone();
        res.instantiate(params)
    }

    pub fn to_qualified_id(&self) -> QualifiedId<Id> {
        let Self { module_id, id, .. } = self;
        module_id.qualified(id.to_owned())
    }
}

impl QualifiedInstId<StructId> {
    pub fn to_type(&self) -> Type {
        Type::Struct(self.module_id, self.id, self.inst.to_owned())
    }
}

// =================================================================================================
/// # Verification Scope

/// Defines what functions to verify.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationScope {
    /// Verify only public functions.
    Public,
    /// Verify all functions.
    All,
    /// Verify only one function.
    Only(String),
    /// Verify only functions from the given module.
    OnlyModule(String),
    /// Verify no functions
    None,
}

impl Default for VerificationScope {
    fn default() -> Self {
        Self::Public
    }
}

impl VerificationScope {
    /// Whether verification is exclusive to only one function or module. If set, this overrides
    /// all implicitly included verification targets via invariants and friends.
    pub fn is_exclusive(&self) -> bool {
        matches!(
            self,
            VerificationScope::Only(_) | VerificationScope::OnlyModule(_)
        )
    }

    /// Returns the target function if verification is exclusive to one function.
    pub fn get_exclusive_verify_function_name(&self) -> Option<&String> {
        match self {
            VerificationScope::Only(s) => Some(s),
            _ => None,
        }
    }
}

// =================================================================================================
/// # Global Environment

/// Global environment for a set of modules.
#[derive(Debug)]
pub struct GlobalEnv {
    /// A Files database for the codespan crate which supports diagnostics.
    source_files: Files<String>,
    /// A map of FileId in the Files database to information about documentation comments in a file.
    /// The comments are represented as map from ByteIndex into string, where the index is the
    /// start position of the associated language item in the source.
    doc_comments: BTreeMap<FileId, BTreeMap<ByteIndex, String>>,
    /// A mapping from file names to associated FileId. Though this information is
    /// already in `source_files`, we can't get it out of there so need to book keep here.
    file_name_map: BTreeMap<String, FileId>,
    /// Bijective mapping between FileId and a plain int. FileId's are themselves wrappers around
    /// ints, but the inner representation is opaque and cannot be accessed. This is used so we
    /// can emit FileId's to generated code and read them back.
    file_id_to_idx: BTreeMap<FileId, u16>,
    file_idx_to_id: BTreeMap<u16, FileId>,
    /// A set indicating whether a file id is a target or a dependency.
    file_id_is_dep: BTreeSet<FileId>,
    /// A special constant location representing an unknown location.
    /// This uses a pseudo entry in `source_files` to be safely represented.
    unknown_loc: Loc,
    /// An equivalent of the MoveIrLoc to the above location. Used to map back and force between
    /// them.
    unknown_move_ir_loc: MoveIrLoc,
    /// A special constant location representing an opaque location.
    /// In difference to an `unknown_loc`, this is a well-known but undisclosed location.
    internal_loc: Loc,
    /// Accumulated diagnosis. In a RefCell so we can add to it without needing a mutable GlobalEnv.
    /// The boolean indicates whether the diag was reported.
    diags: RefCell<Vec<(Diagnostic, bool)>>,
    /// Pool of symbols -- internalized strings.
    symbol_pool: SymbolPool,
    /// A counter for allocating node ids.
    next_free_node_id: RefCell<usize>,
    /// A map from node id to associated location.
    loc_map: RefCell<BTreeMap<NodeId, Loc>>,
    /// A map from node id to associated type.
    type_map: RefCell<BTreeMap<NodeId, Type>>,
    /// A map from node id to associated instantiation of type parameters.
    instantiation_map: RefCell<BTreeMap<NodeId, Vec<Type>>>,
    /// List of loaded modules, in order they have been provided using `add`.
    pub module_data: Vec<ModuleData>,
    /// A counter for issuing global ids.
    global_id_counter: RefCell<usize>,
    /// A map of global invariants.
    global_invariants: BTreeMap<GlobalId, GlobalInvariant>,
    /// A map from spec vars to global invariants which refer to them.
    global_invariants_for_spec_var: BTreeMap<QualifiedInstId<SpecVarId>, BTreeSet<GlobalId>>,
    /// A map from global memories to global invariants which refer to them.
    global_invariants_for_memory: BTreeMap<QualifiedInstId<StructId>, BTreeSet<GlobalId>>,
    /// A set containing spec functions which are called/used in specs. Note that these
    /// are represented without type instantiation because we assume the backend can handle
    /// generics in the expression language.
    pub used_spec_funs: BTreeSet<QualifiedId<SpecFunId>>,
    /// A type-indexed container for storing extension data in the environment.
    extensions: RefCell<BTreeMap<TypeId, Box<dyn Any>>>,
}

/// Struct a helper type for implementing fmt::Display depending on GlobalEnv
pub struct EnvDisplay<'a, T> {
    pub env: &'a GlobalEnv,
    pub val: &'a T,
}

impl GlobalEnv {
    /// Creates a new environment.
    pub fn new() -> Self {
        let mut source_files = Files::new();
        let mut file_name_map = BTreeMap::new();
        let mut file_id_to_idx = BTreeMap::new();
        let mut file_idx_to_id = BTreeMap::new();
        let mut fake_loc = |content: &str| {
            let file_id = source_files.add(content, content.to_string());
            file_name_map.insert(content.to_string(), file_id);
            let file_idx = file_id_to_idx.len() as u16;
            file_id_to_idx.insert(file_id, file_idx);
            file_idx_to_id.insert(file_idx, file_id);
            Loc::new(
                file_id,
                Span::from(ByteIndex(0_u32)..ByteIndex(content.len() as u32)),
            )
        };
        let unknown_loc = fake_loc("<unknown>");
        let unknown_move_ir_loc = MoveIrLoc::new("<unknown>", Span::default());
        let internal_loc = fake_loc("<internal>");
        GlobalEnv {
            source_files,
            doc_comments: Default::default(),
            unknown_loc,
            unknown_move_ir_loc,
            internal_loc,
            file_name_map,
            file_id_to_idx,
            file_idx_to_id,
            file_id_is_dep: BTreeSet::new(),
            diags: RefCell::new(vec![]),
            symbol_pool: SymbolPool::new(),
            next_free_node_id: Default::default(),
            loc_map: Default::default(),
            type_map: Default::default(),
            instantiation_map: Default::default(),
            module_data: vec![],
            global_id_counter: RefCell::new(0),
            global_invariants: Default::default(),
            global_invariants_for_memory: Default::default(),
            global_invariants_for_spec_var: Default::default(),
            used_spec_funs: BTreeSet::new(),
            extensions: Default::default(),
        }
    }

    /// Creates a display container for the given value. There must be an implementation
    /// of fmt::Display for an instance to work in formatting.
    pub fn display<'a, T>(&'a self, val: &'a T) -> EnvDisplay<'a, T> {
        EnvDisplay { env: self, val }
    }

    /// Stores extension data in the environment. This can be arbitrary data which is
    /// indexed by type. Used by tools which want to store their own data in the environment,
    /// like a set of tool dependent options/flags. This can also be used to update
    /// extension data.
    pub fn set_extension<T: Any>(&self, x: T) {
        let id = TypeId::of::<T>();
        self.extensions
            .borrow_mut()
            .insert(id, Box::new(Rc::new(x)));
    }

    /// Retrieves extension data from the environment. Use as in `env.get_extension::<T>()`.
    /// An Rc<T> is returned because extension data is stored in a RefCell and we can't use
    /// lifetimes (`&'a T`) to control borrowing.
    pub fn get_extension<T: Any>(&self) -> Option<Rc<T>> {
        let id = TypeId::of::<T>();
        self.extensions
            .borrow()
            .get(&id)
            .and_then(|d| d.downcast_ref::<Rc<T>>().cloned())
    }

    /// Updates extension data. If they are no outstanding references to this extension it
    /// is updated in place, otherwise it will be cloned before the update.
    pub fn update_extension<T: Any + Clone>(&self, f: impl FnOnce(&mut T)) {
        let id = TypeId::of::<T>();
        let d = self
            .extensions
            .borrow_mut()
            .remove(&id)
            .expect("extension defined")
            .downcast_ref::<Rc<T>>()
            .cloned()
            .unwrap();
        let mut curr = Rc::try_unwrap(d).unwrap_or_else(|d| d.as_ref().clone());
        f(&mut curr);
        self.set_extension(curr);
    }

    /// Checks whether there is an extension of type `T`.
    pub fn has_extension<T: Any>(&self) -> bool {
        let id = TypeId::of::<T>();
        self.extensions.borrow().contains_key(&id)
    }

    /// Clear extension data from the environment (return the data if it is previously set).
    /// Use as in `env.clear_extension::<T>()` and an `Rc<T>` is returned if the extension data is
    /// previously stored in the environment.
    pub fn clear_extension<T: Any>(&self) -> Option<Rc<T>> {
        let id = TypeId::of::<T>();
        self.extensions
            .borrow_mut()
            .remove(&id)
            .and_then(|d| d.downcast::<Rc<T>>().ok())
            .map(|boxed| *boxed)
    }

    /// Create a new global id unique to this environment.
    pub fn new_global_id(&self) -> GlobalId {
        let mut counter = self.global_id_counter.borrow_mut();
        let id = GlobalId::new(*counter);
        *counter += 1;
        id
    }

    /// Returns a reference to the symbol pool owned by this environment.
    pub fn symbol_pool(&self) -> &SymbolPool {
        &self.symbol_pool
    }

    /// Adds a source to this environment, returning a FileId for it.
    pub fn add_source(&mut self, file_name: &str, source: &str, is_dep: bool) -> FileId {
        let file_id = self.source_files.add(file_name, source.to_string());
        self.file_name_map.insert(file_name.to_string(), file_id);
        let file_idx = self.file_id_to_idx.len() as u16;
        self.file_id_to_idx.insert(file_id, file_idx);
        self.file_idx_to_id.insert(file_idx, file_id);
        if is_dep {
            self.file_id_is_dep.insert(file_id);
        }
        file_id
    }

    /// Find all target modules and return in a vector
    pub fn get_target_modules(&self) -> Vec<ModuleEnv> {
        let mut target_modules: Vec<ModuleEnv> = vec![];
        for module_env in self.get_modules() {
            if module_env.is_target() {
                target_modules.push(module_env);
            }
        }
        target_modules
    }

    /// Adds documentation for a file.
    pub fn add_documentation(&mut self, file_id: FileId, docs: BTreeMap<ByteIndex, String>) {
        self.doc_comments.insert(file_id, docs);
    }

    /// Adds diagnostic to the environment.
    pub fn add_diag(&self, diag: Diagnostic) {
        self.diags.borrow_mut().push((diag, false));
    }

    /// Adds an error to this environment, without notes.
    pub fn error(&self, loc: &Loc, msg: &str) {
        self.diag(Severity::Error, loc, msg)
    }

    /// Adds an error to this environment, with notes.
    pub fn error_with_notes(&self, loc: &Loc, msg: &str, notes: Vec<String>) {
        self.diag_with_notes(Severity::Error, loc, msg, notes)
    }

    /// Adds a diagnostic of given severity to this environment.
    pub fn diag(&self, severity: Severity, loc: &Loc, msg: &str) {
        let diag = Diagnostic::new(severity, msg, Label::new(loc.file_id, loc.span, ""));
        self.add_diag(diag);
    }

    /// Adds a diagnostic of given severity to this environment, with notes.
    pub fn diag_with_notes(&self, severity: Severity, loc: &Loc, msg: &str, notes: Vec<String>) {
        let diag = Diagnostic::new(severity, msg, Label::new(loc.file_id, loc.span, ""));
        let diag = diag.with_notes(notes);
        self.add_diag(diag);
    }

    /// Adds a diagnostic of given severity to this environment, with secondary labels.
    pub fn diag_with_labels(
        &self,
        severity: Severity,
        loc: &Loc,
        msg: &str,
        labels: Vec<(Loc, String)>,
    ) {
        let mut diag = Diagnostic::new(severity, msg, Label::new(loc.file_id, loc.span, ""));
        let labels = labels
            .into_iter()
            .map(|(l, m)| Label::new(l.file_id, l.span, m))
            .collect_vec();
        diag.secondary_labels = labels;
        self.add_diag(diag);
    }

    /// Checks whether any of the diagnostics contains string.
    pub fn has_diag(&self, pattern: &str) -> bool {
        self.diags
            .borrow()
            .iter()
            .any(|(d, _)| d.message.contains(pattern))
    }

    /// Clear all accumulated diagnosis.
    pub fn clear_diag(&self) {
        self.diags.borrow_mut().clear();
    }

    /// Returns the unknown location.
    pub fn unknown_loc(&self) -> Loc {
        self.unknown_loc.clone()
    }

    /// Returns a Move IR version of the unknown location which is guaranteed to map to the
    /// regular unknown location via `to_loc`.
    pub fn unknown_move_ir_loc(&self) -> MoveIrLoc {
        self.unknown_move_ir_loc
    }

    /// Returns the internal location.
    pub fn internal_loc(&self) -> Loc {
        self.internal_loc.clone()
    }

    /// Converts a Loc as used by the move-lang compiler to the one we are using here.
    /// TODO: move-lang should use FileId as well so we don't need this here. There is already
    /// a todo in their code to remove the current use of `&'static str` for file names in Loc.
    pub fn to_loc(&self, loc: &MoveIrLoc) -> Loc {
        let file_id = self.get_file_id(loc.file()).unwrap_or_else(|| {
            panic!(
                "Unable to find source file '{}' in the environment",
                loc.file()
            )
        });
        Loc {
            file_id,
            span: loc.span(),
        }
    }

    /// Returns the file id for a file name, if defined.
    pub fn get_file_id(&self, fname: &str) -> Option<FileId> {
        self.file_name_map.get(fname).cloned()
    }

    /// Maps a FileId to an index which can be mapped back to a FileId.
    pub fn file_id_to_idx(&self, file_id: FileId) -> u16 {
        *self
            .file_id_to_idx
            .get(&file_id)
            .expect("file_id undefined")
    }

    /// Maps a an index which was obtained by `file_id_to_idx` back to a FileId.
    pub fn file_idx_to_id(&self, file_idx: u16) -> FileId {
        *self
            .file_idx_to_id
            .get(&file_idx)
            .expect("file_idx undefined")
    }

    /// Returns file name and line/column position for a location, if available.
    pub fn get_file_and_location(&self, loc: &Loc) -> Option<(String, Location)> {
        self.get_location(loc).map(|line_column| {
            (
                self.source_files
                    .name(loc.file_id())
                    .to_string_lossy()
                    .to_string(),
                line_column,
            )
        })
    }

    /// Returns line/column position for a location, if available.
    pub fn get_location(&self, loc: &Loc) -> Option<Location> {
        self.source_files
            .location(loc.file_id(), loc.span().start())
            .ok()
    }

    /// Return the source text for the given location.
    pub fn get_source(&self, loc: &Loc) -> Result<&str, SpanOutOfBoundsError> {
        self.source_files.source_slice(loc.file_id, loc.span)
    }

    /// Return the source file names.
    pub fn get_source_file_names(&self) -> Vec<String> {
        self.file_name_map
            .iter()
            .filter_map(|(k, _)| {
                if k.eq("<internal>") || k.eq("<unknown>") {
                    None
                } else {
                    Some(k.clone())
                }
            })
            .collect()
    }

    // Gets the number of source files in this environment.
    pub fn get_file_count(&self) -> usize {
        self.file_name_map.len()
    }

    /// Returns true if diagnostics have error severity or worse.
    pub fn has_errors(&self) -> bool {
        self.error_count() > 0
    }

    /// Returns the number of diagnostics.
    pub fn diag_count(&self, min_severity: Severity) -> usize {
        self.diags
            .borrow()
            .iter()
            .filter(|(d, _)| d.severity >= min_severity)
            .count()
    }

    /// Returns the number of errors.
    pub fn error_count(&self) -> usize {
        self.diag_count(Severity::Error)
    }

    /// Returns true if diagnostics have warning severity or worse.
    pub fn has_warnings(&self) -> bool {
        self.diags
            .borrow()
            .iter()
            .any(|(d, _)| d.severity >= Severity::Warning)
    }

    /// Writes accumulated diagnostics of given or higher severity.
    pub fn report_diag<W: WriteColor>(&self, writer: &mut W, severity: Severity) {
        let mut shown = BTreeSet::new();
        for (diag, reported) in self
            .diags
            .borrow_mut()
            .iter_mut()
            .filter(|(d, _)| d.severity >= severity)
        {
            if !*reported {
                // Avoid showing the same message twice. This can happen e.g. because of
                // duplication of expressions via schema inclusion.
                if shown.insert(format!("{:?}", diag)) {
                    emit(writer, &Config::default(), &self.source_files, diag)
                        .expect("emit must not fail");
                }
                *reported = true;
            }
        }
    }

    /// Adds a global invariant to this environment.
    pub fn add_global_invariant(&mut self, inv: GlobalInvariant) {
        let id = inv.id;
        for spec_var in &inv.spec_var_usage {
            self.global_invariants_for_spec_var
                .entry(spec_var.clone())
                .or_insert_with(BTreeSet::new)
                .insert(id);
        }
        for memory in &inv.mem_usage {
            self.global_invariants_for_memory
                .entry(memory.clone())
                .or_insert_with(BTreeSet::new)
                .insert(id);
        }
        self.global_invariants.insert(id, inv);
    }

    /// Get global invariant by id.
    pub fn get_global_invariant(&self, id: GlobalId) -> Option<&GlobalInvariant> {
        self.global_invariants.get(&id)
    }

    /// Return the global invariants which refer to the given memory.
    pub fn get_global_invariants_for_memory(
        &self,
        memory: &QualifiedInstId<StructId>,
    ) -> Vec<GlobalId> {
        self.global_invariants_for_memory
            .get(memory)
            .map(|ids| ids.iter().cloned().collect_vec())
            .unwrap_or_else(Default::default)
    }

    /// Given a set of invariants, find the subset that refer to the type in mem.
    pub fn get_subset_invariants_for_memory(
        &self,
        mem: QualifiedInstId<StructId>,
        inv_set_id: &BTreeSet<GlobalId>,
    ) -> BTreeSet<GlobalId> {
        if let Some(modifies_inv_id_set) = self.global_invariants_for_memory.get(&mem) {
            modifies_inv_id_set
                .intersection(inv_set_id)
                .cloned()
                .collect()
        } else {
            BTreeSet::<GlobalId>::new()
        }
    }

    pub fn get_global_invariants_by_module(&self, module_id: ModuleId) -> BTreeSet<GlobalId> {
        self.global_invariants
            .iter()
            .filter(|(_, inv)| inv.declaring_module == module_id)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns true if a spec fun is used in specs.
    pub fn is_spec_fun_used(&self, module_id: ModuleId, spec_fun_id: SpecFunId) -> bool {
        self.used_spec_funs
            .contains(&module_id.qualified(spec_fun_id))
    }

    /// Returns true if the type represents the well-known event handle type.
    pub fn is_wellknown_event_handle_type(&self, ty: &Type) -> bool {
        if let Type::Struct(mid, sid, _) = ty {
            let module_env = self.get_module(*mid);
            let struct_env = module_env.get_struct(*sid);
            let module_name = module_env.get_name();
            module_name.addr() == &BigUint::one()
                && &*self.symbol_pool.string(module_name.name()) == "Event"
                && &*self.symbol_pool.string(struct_env.get_name()) == "EventHandle"
        } else {
            false
        }
    }

    /// Adds a new module to the environment. StructData and FunctionData need to be provided
    /// in definition index order. See `create_function_data` and `create_struct_data` for how
    /// to create them.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        loc: Loc,
        module: CompiledModule,
        source_map: SourceMap<MoveIrLoc>,
        named_constants: BTreeMap<NamedConstantId, NamedConstantData>,
        struct_data: BTreeMap<StructId, StructData>,
        function_data: BTreeMap<FunId, FunctionData>,
        spec_vars: Vec<SpecVarDecl>,
        spec_funs: Vec<SpecFunDecl>,
        module_spec: Spec,
        spec_block_infos: Vec<SpecBlockInfo>,
    ) {
        let idx = self.module_data.len();
        let effective_name = if module.self_id().name().as_str() == SCRIPT_MODULE_NAME {
            // Use the name of the first function in this module.
            function_data
                .iter()
                .next()
                .expect("functions in script")
                .1
                .name
        } else {
            self.symbol_pool.make(module.self_id().name().as_str())
        };
        let name = ModuleName::from_str(&module.self_id().address().to_string(), effective_name);
        let struct_idx_to_id: BTreeMap<StructDefinitionIndex, StructId> = struct_data
            .iter()
            .map(|(id, data)| (data.def_idx, *id))
            .collect();
        let function_idx_to_id: BTreeMap<FunctionDefinitionIndex, FunId> = function_data
            .iter()
            .map(|(id, data)| (data.def_idx, *id))
            .collect();
        let spec_vars: BTreeMap<SpecVarId, SpecVarDecl> = spec_vars
            .into_iter()
            .enumerate()
            .map(|(i, v)| (SpecVarId::new(i), v))
            .collect();
        let spec_funs: BTreeMap<SpecFunId, SpecFunDecl> = spec_funs
            .into_iter()
            .enumerate()
            .map(|(i, v)| (SpecFunId::new(i), v))
            .collect();

        self.module_data.push(ModuleData {
            name,
            id: ModuleId(idx as RawIndex),
            module,
            named_constants,
            struct_data,
            struct_idx_to_id,
            function_data,
            function_idx_to_id,
            spec_vars,
            spec_funs,
            module_spec,
            source_map,
            loc,
            spec_block_infos,
            used_modules: Default::default(),
            friend_modules: Default::default(),
        });
    }

    /// Creates data for a named constant.
    pub fn create_named_constant_data(
        &self,
        name: Symbol,
        loc: Loc,
        typ: Type,
        value: Value,
    ) -> NamedConstantData {
        NamedConstantData {
            name,
            loc,
            typ,
            value,
        }
    }

    /// Creates data for a function, adding any information not contained in bytecode. This is
    /// a helper for adding a new module to the environment.
    pub fn create_function_data(
        &self,
        module: &CompiledModule,
        def_idx: FunctionDefinitionIndex,
        name: Symbol,
        loc: Loc,
        arg_names: Vec<Symbol>,
        type_arg_names: Vec<Symbol>,
        spec: Spec,
    ) -> FunctionData {
        let handle_idx = module.function_def_at(def_idx).function;
        FunctionData {
            name,
            loc,
            def_idx,
            handle_idx,
            arg_names,
            type_arg_names,
            spec,
            called_funs: Default::default(),
            calling_funs: Default::default(),
        }
    }

    /// Creates data for a struct. Currently all information is contained in the byte code. This is
    /// a helper for adding a new module to the environment.
    pub fn create_struct_data(
        &self,
        module: &CompiledModule,
        def_idx: StructDefinitionIndex,
        name: Symbol,
        loc: Loc,
        spec: Spec,
    ) -> StructData {
        let handle_idx = module.struct_def_at(def_idx).struct_handle;
        let field_data = if let StructFieldInformation::Declared(fields) =
            &module.struct_def_at(def_idx).field_information
        {
            let mut map = BTreeMap::new();
            for (offset, field) in fields.iter().enumerate() {
                let name = self
                    .symbol_pool
                    .make(module.identifier_at(field.name).as_str());
                map.insert(
                    FieldId(name),
                    FieldData {
                        name,
                        def_idx,
                        offset,
                    },
                );
            }
            map
        } else {
            BTreeMap::new()
        };
        StructData {
            name,
            loc,
            def_idx,
            handle_idx,
            field_data,
            spec,
        }
    }

    /// Finds a module by name and returns an environment for it.
    pub fn find_module(&self, name: &ModuleName) -> Option<ModuleEnv<'_>> {
        for module_data in &self.module_data {
            let module_env = ModuleEnv {
                env: self,
                data: module_data,
            };
            if module_env.get_name() == name {
                return Some(module_env);
            }
        }
        None
    }

    /// Finds a module by simple name and returns an environment for it.
    /// TODO: we may need to disallow this to support modules of the same simple name but with
    ///    different addresses in one verification session.
    pub fn find_module_by_name(&self, simple_name: Symbol) -> Option<ModuleEnv<'_>> {
        self.get_modules()
            .find(|m| m.get_name().name() == simple_name)
    }

    /// Find a module by its bytecode format ID
    pub fn find_module_by_language_storage_id(
        &self,
        id: &language_storage::ModuleId,
    ) -> Option<ModuleEnv<'_>> {
        self.find_module(&self.to_module_name(id))
    }

    /// Find a function by its bytecode format name and ID
    pub fn find_function_by_language_storage_id_name(
        &self,
        id: &language_storage::ModuleId,
        name: &Identifier,
    ) -> Option<FunctionEnv<'_>> {
        self.find_module_by_language_storage_id(id)
            .map(|menv| menv.find_function(menv.symbol_pool().make(name.as_str())))
            .flatten()
    }

    /// Gets a StructEnv in this module by its `StructTag`
    pub fn find_struct_by_tag(
        &self,
        tag: &language_storage::StructTag,
    ) -> Option<QualifiedId<StructId>> {
        self.find_module(&self.to_module_name(&tag.module_id()))
            .map(|menv| {
                menv.find_struct_by_identifier(tag.name.clone())
                    .map(|sid| menv.get_id().qualified(sid))
            })
            .flatten()
    }

    /// Return the module enclosing this location.
    pub fn get_enclosing_module(&self, loc: &Loc) -> Option<ModuleEnv<'_>> {
        for data in &self.module_data {
            if data.loc.file_id() == loc.file_id()
                && Self::enclosing_span(data.loc.span(), loc.span())
            {
                return Some(ModuleEnv { env: self, data });
            }
        }
        None
    }

    /// Returns the function enclosing this location.
    pub fn get_enclosing_function(&self, loc: &Loc) -> Option<FunctionEnv<'_>> {
        // Currently we do a brute-force linear search, may need to speed this up if it appears
        // to be a bottleneck.
        let module_env = self.get_enclosing_module(loc)?;
        for func_env in module_env.into_functions() {
            if Self::enclosing_span(func_env.get_loc().span(), loc.span()) {
                return Some(func_env.clone());
            }
        }
        None
    }

    /// Returns the struct enclosing this location.
    pub fn get_enclosing_struct(&self, loc: &Loc) -> Option<StructEnv<'_>> {
        let module_env = self.get_enclosing_module(loc)?;
        for struct_env in module_env.into_structs() {
            if Self::enclosing_span(struct_env.get_loc().span(), loc.span()) {
                return Some(struct_env);
            }
        }
        None
    }

    fn enclosing_span(outer: Span, inner: Span) -> bool {
        inner.start() >= outer.start() && inner.end() <= outer.end()
    }

    /// Return the `FunctionEnv` for `fun`
    pub fn get_function(&self, fun: QualifiedId<FunId>) -> FunctionEnv<'_> {
        self.get_module(fun.module_id).into_function(fun.id)
    }

    /// Return the `StructEnv` for `str`
    pub fn get_struct(&self, str: QualifiedId<StructId>) -> StructEnv<'_> {
        self.get_module(str.module_id).into_struct(str.id)
    }

    // Gets the number of modules in this environment.
    pub fn get_module_count(&self) -> usize {
        self.module_data.len()
    }

    /// Gets a module by id.
    pub fn get_module(&self, id: ModuleId) -> ModuleEnv<'_> {
        let module_data = &self.module_data[id.0 as usize];
        ModuleEnv {
            env: self,
            data: module_data,
        }
    }

    /// Gets a struct by qualified id.
    pub fn get_struct_qid(&self, qid: QualifiedId<StructId>) -> StructEnv<'_> {
        self.get_module(qid.module_id).into_struct(qid.id)
    }

    /// Gets a function by qualified id.
    pub fn get_function_qid(&self, qid: QualifiedId<FunId>) -> FunctionEnv<'_> {
        self.get_module(qid.module_id).into_function(qid.id)
    }

    /// Returns an iterator for all modules in the environment.
    pub fn get_modules(&self) -> impl Iterator<Item = ModuleEnv<'_>> {
        self.module_data.iter().map(move |module_data| ModuleEnv {
            env: self,
            data: module_data,
        })
    }

    /// Returns an iterator for all bytecode modules in the environment.
    pub fn get_bytecode_modules(&self) -> impl Iterator<Item = &CompiledModule> {
        self.module_data
            .iter()
            .map(|module_data| &module_data.module)
    }

    /// Returns all structs in all modules which carry invariants.
    pub fn get_all_structs_with_conditions(&self) -> Vec<Type> {
        let mut res = vec![];
        for module_env in self.get_modules() {
            for struct_env in module_env.get_structs() {
                if struct_env.has_conditions() {
                    let formals = struct_env
                        .get_type_parameters()
                        .iter()
                        .enumerate()
                        .map(|(idx, _)| Type::TypeParameter(idx as u16))
                        .collect_vec();
                    res.push(Type::Struct(
                        module_env.get_id(),
                        struct_env.get_id(),
                        formals,
                    ));
                }
            }
        }
        res
    }

    /// Converts a storage module id into an AST module name.
    fn to_module_name(&self, storage_id: &language_storage::ModuleId) -> ModuleName {
        ModuleName::from_str(
            &storage_id.address().to_string(),
            self.symbol_pool.make(storage_id.name().as_str()),
        )
    }

    /// Get documentation associated with an item at Loc.
    pub fn get_doc(&self, loc: &Loc) -> &str {
        self.doc_comments
            .get(&loc.file_id)
            .and_then(|comments| comments.get(&loc.span.start()).map(|s| s.as_str()))
            .unwrap_or("")
    }

    /// Returns true if the boolean property is true.
    pub fn is_property_true(&self, properties: &PropertyBag, name: &str) -> Option<bool> {
        let sym = &self.symbol_pool().make(name);
        if let Some(PropertyValue::Value(Value::Bool(b))) = properties.get(sym) {
            return Some(*b);
        }
        None
    }

    /// Returns the value of a number property.
    pub fn get_num_property(&self, properties: &PropertyBag, name: &str) -> Option<usize> {
        let sym = &self.symbol_pool().make(name);
        if let Some(PropertyValue::Value(Value::Number(n))) = properties.get(sym) {
            return n.to_usize();
        }
        None
    }

    /// Attempt to compute a struct tag for (`mid`, `sid`, `ts`). Returns `Some` if all types in
    /// `ts` are closed, `None` otherwise
    pub fn get_struct_tag(
        &self,
        mid: ModuleId,
        sid: StructId,
        ts: &[Type],
    ) -> Option<language_storage::StructTag> {
        self.get_struct_type(mid, sid, ts)?.to_struct_tag()
    }

    /// Attempt to compute a struct type for (`mid`, `sid`, `ts`).
    pub fn get_struct_type(
        &self,
        mid: ModuleId,
        sid: StructId,
        ts: &[Type],
    ) -> Option<language_storage::StructType> {
            let menv = self.get_module(mid);
            Some(language_storage::StructType {
                address: *menv.self_address(),
                module: menv.get_identifier(),
                name: menv.get_struct(sid).get_identifier(),
                type_params: ts
                    .iter()
                    .map(|t| t.clone().into_type(self).unwrap())
                    .collect(),
            })
    }

    /// Gets the location of the given node.
    pub fn get_node_loc(&self, node_id: NodeId) -> Loc {
        self.loc_map
            .borrow()
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| self.unknown_loc())
    }

    /// Gets the type of the given node.
    pub fn get_node_type(&self, node_id: NodeId) -> Type {
        self.type_map
            .borrow()
            .get(&node_id)
            .cloned()
            .expect("node type defined")
    }

    /// Converts an index into a node id.
    pub fn index_to_node_id(&self, index: usize) -> Option<NodeId> {
        let id = NodeId::new(index);
        if self.loc_map.borrow().get(&id).is_some() {
            Some(id)
        } else {
            None
        }
    }

    /// Gets the type of the given node, if available.
    pub fn get_node_type_opt(&self, node_id: NodeId) -> Option<Type> {
        self.type_map.borrow().get(&node_id).cloned()
    }

    /// Returns the next free node number.
    pub fn next_free_node_number(&self) -> usize {
        *self.next_free_node_id.borrow()
    }

    /// Allocates a new node id.
    pub fn new_node_id(&self) -> NodeId {
        let id = NodeId::new(*self.next_free_node_id.borrow());
        let mut r = self.next_free_node_id.borrow_mut();
        *r = r.checked_add(1).expect("NodeId overflow");
        id
    }

    /// Allocates a new node id and assigns location and type to it.
    pub fn new_node(&self, loc: Loc, ty: Type) -> NodeId {
        let id = self.new_node_id();
        self.loc_map.borrow_mut().insert(id, loc);
        self.type_map.borrow_mut().insert(id, ty);
        id
    }

    /// Sets type for the given node id. Must not have been set before.
    pub fn set_node_type(&self, node_id: NodeId, ty: Type) {
        assert!(self.type_map.borrow_mut().insert(node_id, ty).is_none());
    }

    /// Sets instantiation for the given node id. Must not have been set before.
    pub fn set_node_instantiation(&self, node_id: NodeId, instantiation: Vec<Type>) {
        assert!(self
            .instantiation_map
            .borrow_mut()
            .insert(node_id, instantiation)
            .is_none());
    }

    /// Updates type for the given node id. Must have been set before.
    pub fn update_node_type(&self, node_id: NodeId, ty: Type) {
        assert!(self.type_map.borrow_mut().insert(node_id, ty).is_some());
    }

    /// Updates instantiation for the given node id. Must have been set before.
    pub fn update_node_instantiation(&self, node_id: NodeId, instantiation: Vec<Type>) {
        assert!(self
            .instantiation_map
            .borrow_mut()
            .insert(node_id, instantiation)
            .is_some());
    }

    /// Gets the type parameter instantiation associated with the given node.
    pub fn get_node_instantiation(&self, node_id: NodeId) -> Vec<Type> {
        self.instantiation_map
            .borrow()
            .get(&node_id)
            .cloned()
            .unwrap_or_else(Vec::new)
    }

    /// Gets the type parameter instantiation associated with the given node, if it is available.
    pub fn get_node_instantiation_opt(&self, node_id: NodeId) -> Option<Vec<Type>> {
        self.instantiation_map.borrow().get(&node_id).cloned()
    }
}

impl Default for GlobalEnv {
    fn default() -> Self {
        Self::new()
    }
}

// =================================================================================================
/// # Module Environment

/// Represents data for a module.
#[derive(Debug)]
pub struct ModuleData {
    /// Module name.
    pub name: ModuleName,

    /// Id of this module in the global env.
    pub id: ModuleId,

    /// Module byte code.
    pub module: CompiledModule,

    /// Named constant data
    pub named_constants: BTreeMap<NamedConstantId, NamedConstantData>,

    /// Struct data.
    pub struct_data: BTreeMap<StructId, StructData>,

    /// Mapping from struct definition index to id in above map.
    pub struct_idx_to_id: BTreeMap<StructDefinitionIndex, StructId>,

    /// Function data.
    pub function_data: BTreeMap<FunId, FunctionData>,

    /// Mapping from function definition index to id in above map.
    pub function_idx_to_id: BTreeMap<FunctionDefinitionIndex, FunId>,

    /// Specification variables, in SpecVarId order.
    pub spec_vars: BTreeMap<SpecVarId, SpecVarDecl>,

    /// Specification functions, in SpecFunId order.
    pub spec_funs: BTreeMap<SpecFunId, SpecFunDecl>,

    /// Module level specification.
    pub module_spec: Spec,

    /// Module source location information.
    pub source_map: SourceMap<MoveIrLoc>,

    /// The location of this module.
    pub loc: Loc,

    /// A list of spec block infos, for documentation generation.
    pub spec_block_infos: Vec<SpecBlockInfo>,

    /// A cache for the modules used by this one.
    used_modules: RefCell<BTreeMap<bool, BTreeSet<ModuleId>>>,

    /// A cache for the modules declared as friends by this one.
    friend_modules: RefCell<Option<BTreeSet<ModuleId>>>,
}

impl ModuleData {
    pub fn stub(name: ModuleName, id: ModuleId, module: CompiledModule) -> Self {
        ModuleData {
            name,
            id,
            module,
            named_constants: BTreeMap::new(),
            struct_data: BTreeMap::new(),
            struct_idx_to_id: BTreeMap::new(),
            function_data: BTreeMap::new(),
            function_idx_to_id: BTreeMap::new(),
            // below this line is source/prover specific
            spec_vars: BTreeMap::new(),
            spec_funs: BTreeMap::new(),
            module_spec: Spec::default(),
            source_map: SourceMap::new(None),
            loc: Loc::default(),
            spec_block_infos: vec![],
            used_modules: Default::default(),
            friend_modules: Default::default(),
        }
    }
}

/// Represents a module environment.
#[derive(Debug, Clone)]
pub struct ModuleEnv<'env> {
    /// Reference to the outer env.
    pub env: &'env GlobalEnv,

    /// Reference to the data of the module.
    data: &'env ModuleData,
}

impl<'env> ModuleEnv<'env> {
    /// Returns the id of this module in the global env.
    pub fn get_id(&self) -> ModuleId {
        self.data.id
    }

    /// Returns the name of this module.
    pub fn get_name(&'env self) -> &'env ModuleName {
        &self.data.name
    }

    /// Returns true if either the full name or simple name of this module matches the given string
    pub fn matches_name(&self, name: &str) -> bool {
        self.get_full_name_str() == name
            || self.get_name().display(self.symbol_pool()).to_string() == name
    }

    /// Returns the location of this module.
    pub fn get_loc(&'env self) -> Loc {
        self.data.loc.clone()
    }

    /// Returns full name as a string.
    pub fn get_full_name_str(&self) -> String {
        self.get_name().display_full(self.symbol_pool()).to_string()
    }

    /// Returns the VM identifier for this module
    pub fn get_identifier(&'env self) -> Identifier {
        self.data.module.name().to_owned()
    }

    /// Returns true if this is a module representing a script.
    pub fn is_script_module(&self) -> bool {
        self.data.name.is_script()
    }

    /// Returns true of this module is target of compilation. A non-target module is
    /// a dependency only but not explicitly requested to process.
    pub fn is_target(&self) -> bool {
        let file_id = self.data.loc.file_id;
        !self.env.file_id_is_dep.contains(&file_id)
    }

    /// Returns the path to source file of this module.
    pub fn get_source_path(&self) -> &OsStr {
        let file_id = self.data.loc.file_id;
        self.env.source_files.name(file_id)
    }

    /// Return the set of language storage ModuleId's that this module's bytecode depends on
    /// (including itself), friend modules are excluded from the return result.
    pub fn get_dependencies(&self) -> Vec<language_storage::ModuleId> {
        let compiled_module = &self.data.module;
        let mut deps = compiled_module.immediate_dependencies();
        deps.push(compiled_module.self_id());
        deps
    }

    /// Return the set of language storage ModuleId's that this module declares as friends
    pub fn get_friends(&self) -> Vec<language_storage::ModuleId> {
        self.data.module.immediate_friends()
    }

    /// Returns the set of modules that use this one.
    pub fn get_using_modules(&self, include_specs: bool) -> BTreeSet<ModuleId> {
        self.env
            .get_modules()
            .filter_map(|module_env| {
                if module_env
                    .get_used_modules(include_specs)
                    .contains(&self.data.id)
                {
                    Some(module_env.data.id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the set of modules this one uses.
    pub fn get_used_modules(&self, include_specs: bool) -> BTreeSet<ModuleId> {
        if let Some(usage) = self.data.used_modules.borrow().get(&include_specs) {
            return usage.clone();
        }
        // Determine modules used in bytecode from the compiled module.
        let mut usage: BTreeSet<ModuleId> = self
            .get_dependencies()
            .into_iter()
            .map(|storage_id| self.env.to_module_name(&storage_id))
            .filter_map(|name| self.env.find_module(&name))
            .map(|env| env.get_id())
            .filter(|id| *id != self.get_id())
            .collect();
        if include_specs {
            // Add any usage in specs.
            let add_usage_of_exp = |usage: &mut BTreeSet<ModuleId>, exp: &ExpData| {
                exp.module_usage(usage);
                for node_id in exp.node_ids() {
                    self.env.get_node_type(node_id).module_usage(usage);
                    for ty in self.env.get_node_instantiation(node_id) {
                        ty.module_usage(usage);
                    }
                }
            };
            let add_usage_of_spec = |usage: &mut BTreeSet<ModuleId>, spec: &Spec| {
                for cond in &spec.conditions {
                    add_usage_of_exp(usage, &cond.exp);
                }
            };
            add_usage_of_spec(&mut usage, self.get_spec());
            for struct_env in self.get_structs() {
                add_usage_of_spec(&mut usage, struct_env.get_spec())
            }
            for func_env in self.get_functions() {
                add_usage_of_spec(&mut usage, func_env.get_spec())
            }
            for (_, decl) in self.get_spec_funs() {
                if let Some(def) = &decl.body {
                    add_usage_of_exp(&mut usage, def);
                }
            }
        }
        self.data
            .used_modules
            .borrow_mut()
            .insert(include_specs, usage.clone());
        usage
    }

    /// Returns the set of modules this one declares as friends.
    pub fn get_friend_modules(&self) -> BTreeSet<ModuleId> {
        self.data
            .friend_modules
            .borrow_mut()
            .get_or_insert_with(|| {
                // Determine modules used in bytecode from the compiled module.
                self.get_friends()
                    .into_iter()
                    .map(|storage_id| self.env.to_module_name(&storage_id))
                    .filter_map(|name| self.env.find_module(&name))
                    .map(|env| env.get_id())
                    .collect()
            })
            .clone()
    }

    /// Returns true if the given module is a transitive dependency of this one. The
    /// transitive dependency set contains this module and all directly or indirectly used
    /// modules (without spec usage).
    pub fn is_transitive_dependency(&self, module_id: ModuleId) -> bool {
        if self.get_id() == module_id {
            true
        } else {
            for dep in self.get_used_modules(false) {
                if self.env.get_module(dep).is_transitive_dependency(module_id) {
                    return true;
                }
            }
            false
        }
    }

    /// Returns documentation associated with this module.
    pub fn get_doc(&self) -> &str {
        self.env.get_doc(&self.data.loc)
    }

    /// Returns spec block documentation infos.
    pub fn get_spec_block_infos(&self) -> &[SpecBlockInfo] {
        &self.data.spec_block_infos
    }

    /// Shortcut for accessing the symbol pool.
    pub fn symbol_pool(&self) -> &SymbolPool {
        &self.env.symbol_pool
    }

    /// Gets the underlying bytecode module.
    pub fn get_verified_module(&'env self) -> &'env CompiledModule {
        &self.data.module
    }

    /// Gets a `NamedConstantEnv` in this module by name
    pub fn find_named_constant(&'env self, name: Symbol) -> Option<NamedConstantEnv<'env>> {
        let id = NamedConstantId(name);
        self.data
            .named_constants
            .get(&id)
            .map(|data| NamedConstantEnv {
                module_env: self.clone(),
                data,
            })
    }

    /// Gets a `NamedConstantEnv` in this module by the constant's id
    pub fn get_named_constant(&'env self, id: NamedConstantId) -> NamedConstantEnv<'env> {
        self.clone().into_named_constant(id)
    }

    /// Gets a `NamedConstantEnv` by id
    pub fn into_named_constant(self, id: NamedConstantId) -> NamedConstantEnv<'env> {
        let data = self
            .data
            .named_constants
            .get(&id)
            .expect("NamedConstantId undefined");
        NamedConstantEnv {
            module_env: self,
            data,
        }
    }

    /// Gets the number of named constants in this module.
    pub fn get_named_constant_count(&self) -> usize {
        self.data.named_constants.len()
    }

    /// Returns iterator over `NamedConstantEnv`s in this module.
    pub fn get_named_constants(&'env self) -> impl Iterator<Item = NamedConstantEnv<'env>> {
        self.clone().into_named_constants()
    }

    /// Returns an iterator over `NamedConstantEnv`s in this module.
    pub fn into_named_constants(self) -> impl Iterator<Item = NamedConstantEnv<'env>> {
        self.data
            .named_constants
            .iter()
            .map(move |(_, data)| NamedConstantEnv {
                module_env: self.clone(),
                data,
            })
    }

    /// Gets a FunctionEnv in this module by name.
    pub fn find_function(&self, name: Symbol) -> Option<FunctionEnv<'env>> {
        let id = FunId(name);
        self.data.function_data.get(&id).map(|data| FunctionEnv {
            module_env: self.clone(),
            data,
        })
    }

    /// Gets a FunctionEnv by id.
    pub fn get_function(&'env self, id: FunId) -> FunctionEnv<'env> {
        self.clone().into_function(id)
    }

    /// Gets a FunctionEnv by id.
    pub fn into_function(self, id: FunId) -> FunctionEnv<'env> {
        let data = self.data.function_data.get(&id).expect("FunId undefined");
        FunctionEnv {
            module_env: self,
            data,
        }
    }

    /// Gets the number of functions in this module.
    pub fn get_function_count(&self) -> usize {
        self.data.function_data.len()
    }

    /// Returns iterator over FunctionEnvs in this module.
    pub fn get_functions(&'env self) -> impl Iterator<Item = FunctionEnv<'env>> {
        self.clone().into_functions()
    }

    /// Returns iterator over FunctionEnvs in this module.
    pub fn into_functions(self) -> impl Iterator<Item = FunctionEnv<'env>> {
        self.data
            .function_data
            .iter()
            .map(move |(_, data)| FunctionEnv {
                module_env: self.clone(),
                data,
            })
    }

    /// Gets FunctionEnv for a function used in this module, via the FunctionHandleIndex. The
    /// returned function might be from this or another module.
    pub fn get_used_function(&self, idx: FunctionHandleIndex) -> FunctionEnv<'_> {
        let view =
            FunctionHandleView::new(&self.data.module, self.data.module.function_handle_at(idx));
        let module_name = self.env.to_module_name(&view.module_id());
        let module_env = self
            .env
            .find_module(&module_name)
            .expect("unexpected reference to module not found in global env");
        module_env.into_function(FunId::new(self.env.symbol_pool.make(view.name().as_str())))
    }

    /// Gets the function id from a definition index.
    pub fn try_get_function_id(&self, idx: FunctionDefinitionIndex) -> Option<FunId> {
        self.data.function_idx_to_id.get(&idx).cloned()
    }

    /// Gets the function definition index for the given function id. This is always defined.
    pub fn get_function_def_idx(&self, fun_id: FunId) -> FunctionDefinitionIndex {
        self.data
            .function_data
            .get(&fun_id)
            .expect("function id defined")
            .def_idx
    }

    /// Gets a StructEnv in this module by name.
    pub fn find_struct(&self, name: Symbol) -> Option<StructEnv<'_>> {
        let id = StructId(name);
        self.data.struct_data.get(&id).map(|data| StructEnv {
            module_env: self.clone(),
            data,
        })
    }

    /// Gets a StructEnv in this module by identifier
    pub fn find_struct_by_identifier(&self, identifier: Identifier) -> Option<StructId> {
        for data in self.data.struct_data.values() {
            let senv = StructEnv {
                module_env: self.clone(),
                data,
            };
            if senv.get_identifier() == identifier {
                return Some(senv.get_id());
            }
        }
        None
    }

    /// Gets the struct id from a definition index which must be valid for this environment.
    pub fn get_struct_id(&self, idx: StructDefinitionIndex) -> StructId {
        *self
            .data
            .struct_idx_to_id
            .get(&idx)
            .unwrap_or_else(|| panic!("undefined struct definition index {:?}", idx))
    }

    /// Gets a StructEnv by id.
    pub fn get_struct(&self, id: StructId) -> StructEnv<'_> {
        let data = self.data.struct_data.get(&id).expect("StructId undefined");
        StructEnv {
            module_env: self.clone(),
            data,
        }
    }

    pub fn get_struct_by_def_idx(&self, idx: StructDefinitionIndex) -> StructEnv<'_> {
        self.get_struct(self.get_struct_id(idx))
    }

    /// Gets a StructEnv by id, consuming this module env.
    pub fn into_struct(self, id: StructId) -> StructEnv<'env> {
        let data = self.data.struct_data.get(&id).expect("StructId undefined");
        StructEnv {
            module_env: self,
            data,
        }
    }

    /// Gets the number of structs in this module.
    pub fn get_struct_count(&self) -> usize {
        self.data.struct_data.len()
    }

    /// Returns iterator over structs in this module.
    pub fn get_structs(&'env self) -> impl Iterator<Item = StructEnv<'env>> {
        self.clone().into_structs()
    }

    /// Returns iterator over structs in this module.
    pub fn into_structs(self) -> impl Iterator<Item = StructEnv<'env>> {
        self.data
            .struct_data
            .iter()
            .map(move |(_, data)| StructEnv {
                module_env: self.clone(),
                data,
            })
    }

    /// Globalizes a signature local to this module.
    pub fn globalize_signature(&self, sig: &SignatureToken) -> Type {
        match sig {
            SignatureToken::Bool => Type::Primitive(PrimitiveType::Bool),
            SignatureToken::U8 => Type::Primitive(PrimitiveType::U8),
            SignatureToken::U64 => Type::Primitive(PrimitiveType::U64),
            SignatureToken::U128 => Type::Primitive(PrimitiveType::U128),
            SignatureToken::Address => Type::Primitive(PrimitiveType::Address),
            SignatureToken::Signer => Type::Primitive(PrimitiveType::Signer),
            SignatureToken::Reference(t) => {
                Type::Reference(false, Box::new(self.globalize_signature(&*t)))
            }
            SignatureToken::MutableReference(t) => {
                Type::Reference(true, Box::new(self.globalize_signature(&*t)))
            }
            SignatureToken::TypeParameter(index) => Type::TypeParameter(*index),
            SignatureToken::Vector(bt) => Type::Vector(Box::new(self.globalize_signature(&*bt))),
            SignatureToken::Struct(handle_idx) => {
                let struct_view = StructHandleView::new(
                    &self.data.module,
                    self.data.module.struct_handle_at(*handle_idx),
                );
                let declaring_module_env = self
                    .env
                    .find_module(&self.env.to_module_name(&struct_view.module_id()))
                    .expect("undefined module");
                let struct_env = declaring_module_env
                    .find_struct(self.env.symbol_pool.make(struct_view.name().as_str()))
                    .expect("undefined struct");
                Type::Struct(declaring_module_env.data.id, struct_env.get_id(), vec![])
            }
            SignatureToken::StructInstantiation(handle_idx, args) => {
                let struct_view = StructHandleView::new(
                    &self.data.module,
                    self.data.module.struct_handle_at(*handle_idx),
                );
                let declaring_module_env = self
                    .env
                    .find_module(&self.env.to_module_name(&struct_view.module_id()))
                    .expect("undefined module");
                let struct_env = declaring_module_env
                    .find_struct(self.env.symbol_pool.make(struct_view.name().as_str()))
                    .expect("undefined struct");
                Type::Struct(
                    declaring_module_env.data.id,
                    struct_env.get_id(),
                    self.globalize_signatures(args),
                )
            }
        }
    }

    /// Globalizes a list of signatures.
    pub fn globalize_signatures(&self, sigs: &[SignatureToken]) -> Vec<Type> {
        sigs.iter()
            .map(|s| self.globalize_signature(s))
            .collect_vec()
    }

    /// Gets a list of type actuals associated with the index in the bytecode.
    pub fn get_type_actuals(&self, idx: Option<SignatureIndex>) -> Vec<Type> {
        match idx {
            Some(idx) => {
                let actuals = &self.data.module.signature_at(idx).0;
                self.globalize_signatures(actuals)
            }
            None => vec![],
        }
    }

    /// Retrieve a constant from the pool
    pub fn get_constant(&self, idx: ConstantPoolIndex) -> &VMConstant {
        &self.data.module.constant_pool()[idx.0 as usize]
    }

    /// Converts a constant to the specified type. The type must correspond to the expected
    /// cannonical representation as defined in `move_core_types::values`
    pub fn get_constant_value(&self, constant: &VMConstant) -> MoveValue {
        VMConstant::deserialize_constant(constant).unwrap()
    }

    /// Return the `AccountAdress` of this module
    pub fn self_address(&self) -> &AccountAddress {
        self.data.module.address()
    }

    /// Retrieve an address identifier from the pool
    pub fn get_address_identifier(&self, idx: AddressIdentifierIndex) -> BigUint {
        let addr = &self.data.module.address_identifiers()[idx.0 as usize];
        crate::addr_to_big_uint(addr)
    }

    /// Returns specification variables of this module.
    pub fn get_spec_vars(&'env self) -> impl Iterator<Item = (&'env SpecVarId, &'env SpecVarDecl)> {
        self.data.spec_vars.iter()
    }

    /// Gets spec var by id.
    pub fn get_spec_var(&self, id: SpecVarId) -> &SpecVarDecl {
        self.data.spec_vars.get(&id).expect("spec var id defined")
    }

    /// Find spec var by name.
    pub fn find_spec_var(&self, name: Symbol) -> Option<&SpecVarDecl> {
        self.data
            .spec_vars
            .iter()
            .find(|(_, svar)| svar.name == name)
            .map(|(_, svar)| svar)
    }

    /// Returns specification functions of this module.
    pub fn get_spec_funs(&'env self) -> impl Iterator<Item = (&'env SpecFunId, &'env SpecFunDecl)> {
        self.data.spec_funs.iter()
    }

    /// Gets spec fun by id.
    pub fn get_spec_fun(&self, id: SpecFunId) -> &SpecFunDecl {
        self.data.spec_funs.get(&id).expect("spec fun id defined")
    }

    /// Gets module specification.
    pub fn get_spec(&self) -> &Spec {
        &self.data.module_spec
    }

    /// Returns whether a spec fun is ever called or not.
    pub fn spec_fun_is_used(&self, spec_fun_id: SpecFunId) -> bool {
        self.env
            .used_spec_funs
            .contains(&self.get_id().qualified(spec_fun_id))
    }

    /// Get all spec fun overloads with the given name.
    pub fn get_spec_funs_of_name(
        &self,
        name: Symbol,
    ) -> impl Iterator<Item = (&'env SpecFunId, &'env SpecFunDecl)> {
        self.data
            .spec_funs
            .iter()
            .filter(move |(_, decl)| decl.name == name)
    }

    /// Disassemble the module bytecode
    pub fn disassemble(&self) -> String {
        let disas = Disassembler::new(
            SourceMapping::new(
                self.data.source_map.clone(),
                BinaryIndexedView::Module(self.get_verified_module()),
            ),
            DisassemblerOptions {
                only_externally_visible: false,
                print_code: true,
                print_basic_blocks: true,
                print_locals: true,
            },
        );
        disas
            .disassemble()
            .expect("Failed to disassemble a verified module")
    }
}

// =================================================================================================
/// # Struct Environment

#[derive(Debug)]
pub struct StructData {
    /// The name of this struct.
    name: Symbol,

    /// The location of this struct.
    loc: Loc,

    /// The definition index of this struct in its module.
    def_idx: StructDefinitionIndex,

    /// The handle index of this struct in its module.
    handle_idx: StructHandleIndex,

    /// Field definitions.
    field_data: BTreeMap<FieldId, FieldData>,

    // Associated specification.
    spec: Spec,
}

#[derive(Debug, Clone)]
pub struct StructEnv<'env> {
    /// Reference to enclosing module.
    pub module_env: ModuleEnv<'env>,

    /// Reference to the struct data.
    data: &'env StructData,
}

impl<'env> StructEnv<'env> {
    /// Returns the name of this struct.
    pub fn get_name(&self) -> Symbol {
        self.data.name
    }

    /// Gets full name as string.
    pub fn get_full_name_str(&self) -> String {
        format!(
            "{}::{}",
            self.module_env.get_name().display(self.symbol_pool()),
            self.get_name().display(self.symbol_pool())
        )
    }

    /// Returns the VM identifier for this struct
    pub fn get_identifier(&self) -> Identifier {
        let handle = self
            .module_env
            .data
            .module
            .struct_handle_at(self.data.handle_idx);
        self.module_env
            .data
            .module
            .identifier_at(handle.name)
            .to_owned()
    }

    /// Shortcut for accessing the symbol pool.
    pub fn symbol_pool(&self) -> &SymbolPool {
        self.module_env.symbol_pool()
    }

    /// Returns the location of this struct.
    pub fn get_loc(&self) -> Loc {
        self.data.loc.clone()
    }

    /// Get documentation associated with this struct.
    pub fn get_doc(&self) -> &str {
        self.module_env.env.get_doc(&self.data.loc)
    }

    /// Returns properties from pragmas.
    pub fn get_properties(&self) -> &PropertyBag {
        &self.data.spec.properties
    }

    /// Gets the id associated with this struct.
    pub fn get_id(&self) -> StructId {
        StructId(self.data.name)
    }

    /// Gets the qualified id of this struct.
    pub fn get_qualified_id(&self) -> QualifiedId<StructId> {
        self.module_env.get_id().qualified(self.get_id())
    }

    /// Determines whether this struct is native.
    pub fn is_native(&self) -> bool {
        let def = self.module_env.data.module.struct_def_at(self.data.def_idx);
        def.field_information == StructFieldInformation::Native
    }

    /// Determines whether this struct is the well-known vector type.
    pub fn is_vector(&self) -> bool {
        let name = self
            .module_env
            .env
            .symbol_pool
            .string(self.module_env.get_name().name());
        let addr = self.module_env.get_name().addr();
        name.as_ref() == "Vector" && addr == &BigUint::from(0_u64)
    }

    /// Get the abilities of this struct.
    pub fn get_abilities(&self) -> AbilitySet {
        let def = self.module_env.data.module.struct_def_at(self.data.def_idx);
        let handle = self
            .module_env
            .data
            .module
            .struct_handle_at(def.struct_handle);
        handle.abilities
    }

    /// Determines whether memory-related operations needs to be declared for this struct.
    pub fn has_memory(&self) -> bool {
        self.get_abilities().has_key()
    }

    /// Get an iterator for the fields, ordered by offset.
    pub fn get_fields(&'env self) -> impl Iterator<Item = FieldEnv<'env>> {
        self.data
            .field_data
            .values()
            .sorted_by_key(|data| data.offset)
            .map(move |data| FieldEnv {
                struct_env: self.clone(),
                data,
            })
    }

    /// Return the number of fields in the struct.
    pub fn get_field_count(&self) -> usize {
        self.data.field_data.len()
    }

    /// Gets a field by its id.
    pub fn get_field(&'env self, id: FieldId) -> FieldEnv<'env> {
        let data = self.data.field_data.get(&id).expect("FieldId undefined");
        FieldEnv {
            struct_env: self.clone(),
            data,
        }
    }

    /// Find a field by its name.
    pub fn find_field(&'env self, name: Symbol) -> Option<FieldEnv<'env>> {
        let id = FieldId(name);
        self.data.field_data.get(&id).map(|data| FieldEnv {
            struct_env: self.clone(),
            data,
        })
    }

    /// Gets a field by its offset.
    pub fn get_field_by_offset(&'env self, offset: usize) -> FieldEnv<'env> {
        for data in self.data.field_data.values() {
            if data.offset == offset {
                return FieldEnv {
                    struct_env: self.clone(),
                    data,
                };
            }
        }
        unreachable!("invalid field lookup")
    }

    /// Whether the type parameter at position `idx` is declared as phantom.
    pub fn is_phantom_parameter(&self, idx: usize) -> bool {
        let def = self.module_env.data.module.struct_def_at(self.data.def_idx);
        self.module_env
            .data
            .module
            .struct_handle_at(def.struct_handle)
            .type_parameters[idx]
            .is_phantom
    }

    /// Returns the type parameters associated with this struct.
    pub fn get_type_parameters(&self) -> Vec<TypeParameter> {
        // TODO: we currently do not know the original names of those formals, so we generate them.
        let view = StructDefinitionView::new(
            &self.module_env.data.module,
            self.module_env.data.module.struct_def_at(self.data.def_idx),
        );
        view.type_parameters()
            .iter()
            .enumerate()
            .map(|(i, k)| {
                TypeParameter(
                    self.module_env.env.symbol_pool.make(&format!("$tv{}", i)),
                    AbilityConstraint(k.constraints),
                )
            })
            .collect_vec()
    }

    /// Returns the type parameters associated with this struct, with actual names.
    pub fn get_named_type_parameters(&self) -> Vec<TypeParameter> {
        let view = StructDefinitionView::new(
            &self.module_env.data.module,
            self.module_env.data.module.struct_def_at(self.data.def_idx),
        );
        view.type_parameters()
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let name = self
                    .module_env
                    .data
                    .source_map
                    .get_struct_source_map(self.data.def_idx)
                    .ok()
                    .and_then(|smap| smap.type_parameters.get(i))
                    .map(|(s, _)| s.clone())
                    .unwrap_or_else(|| format!("unknown#{}", i));
                TypeParameter(
                    self.module_env.env.symbol_pool.make(&name),
                    AbilityConstraint(k.constraints),
                )
            })
            .collect_vec()
    }

    /// Returns true if this struct has specifcation conditions.
    pub fn has_conditions(&self) -> bool {
        !self.data.spec.conditions.is_empty()
    }

    /// Returns the data invariants associated with this struct.
    pub fn get_spec(&'env self) -> &'env Spec {
        &self.data.spec
    }

    /// Returns the value of a boolean pragma for this struct. This first looks up a
    /// pragma in this struct, then the enclosing module, and finally uses the provided default.
    /// value
    pub fn is_pragma_true(&self, name: &str, default: impl FnOnce() -> bool) -> bool {
        let env = self.module_env.env;
        if let Some(b) = env.is_property_true(&self.get_spec().properties, name) {
            return b;
        }
        if let Some(b) = env.is_property_true(&self.module_env.get_spec().properties, name) {
            return b;
        }
        default()
    }

    /// Returns true if this struct is native or marked as intrinsic.
    pub fn is_native_or_intrinsic(&self) -> bool {
        self.is_native() || self.is_pragma_true(INTRINSIC_PRAGMA, || false)
    }
}

// =================================================================================================
/// # Field Environment

#[derive(Debug)]
pub struct FieldData {
    /// The name of this field.
    name: Symbol,

    /// The struct definition index of this field in its module.
    def_idx: StructDefinitionIndex,

    /// The offset of this field.
    offset: usize,
}

#[derive(Debug)]
pub struct FieldEnv<'env> {
    /// Reference to enclosing struct.
    pub struct_env: StructEnv<'env>,

    /// Reference to the field data.
    data: &'env FieldData,
}

impl<'env> FieldEnv<'env> {
    /// Gets the name of this field.
    pub fn get_name(&self) -> Symbol {
        self.data.name
    }

    /// Gets the id of this field.
    pub fn get_id(&self) -> FieldId {
        FieldId(self.data.name)
    }

    /// Returns the VM identifier for this field
    pub fn get_identifier(&'env self) -> Identifier {
        let m = &self.struct_env.module_env.data.module;
        let def = m.struct_def_at(self.data.def_idx);
        let offset = self.data.offset;
        FieldDefinitionView::new(m, def.field(offset).expect("Bad field offset"))
            .name()
            .to_owned()
    }

    /// Get documentation associated with this field.
    pub fn get_doc(&self) -> &str {
        if let Ok(smap) = self
            .struct_env
            .module_env
            .data
            .source_map
            .get_struct_source_map(self.data.def_idx)
        {
            let loc = self
                .struct_env
                .module_env
                .env
                .to_loc(&smap.fields[self.data.offset]);
            self.struct_env.module_env.env.get_doc(&loc)
        } else {
            ""
        }
    }

    /// Gets the type of this field.
    pub fn get_type(&self) -> Type {
        let struct_def = self
            .struct_env
            .module_env
            .data
            .module
            .struct_def_at(self.data.def_idx);
        let field = match &struct_def.field_information {
            StructFieldInformation::Declared(fields) => &fields[self.data.offset],
            StructFieldInformation::Native => unreachable!(),
        };
        self.struct_env
            .module_env
            .globalize_signature(&field.signature.0)
    }

    /// Get field offset.
    pub fn get_offset(&self) -> usize {
        self.data.offset
    }
}

// =================================================================================================
/// # Named Constant Environment

#[derive(Debug)]
pub struct NamedConstantData {
    /// The name of this constant
    name: Symbol,

    /// The location of this constant
    loc: Loc,

    /// The type of this constant
    typ: Type,

    /// The value of this constant
    value: Value,
}

#[derive(Debug)]
pub struct NamedConstantEnv<'env> {
    /// Reference to enclosing module.
    pub module_env: ModuleEnv<'env>,

    data: &'env NamedConstantData,
}

impl<'env> NamedConstantEnv<'env> {
    /// Returns the name of this constant
    pub fn get_name(&self) -> Symbol {
        self.data.name
    }

    /// Returns the id of this constant
    pub fn get_id(&self) -> NamedConstantId {
        NamedConstantId(self.data.name)
    }

    /// Returns documentation associated with this constant
    pub fn get_doc(&self) -> &str {
        self.module_env.env.get_doc(&self.data.loc)
    }

    /// Returns the location of this constant
    pub fn get_loc(&self) -> Loc {
        self.data.loc.clone()
    }

    /// Returns the type of the constant
    pub fn get_type(&self) -> Type {
        self.data.typ.clone()
    }

    /// Returns the value of this constant
    pub fn get_value(&self) -> Value {
        self.data.value.clone()
    }
}

// =================================================================================================
/// # Function Environment

/// Represents a type parameter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeParameter(pub Symbol, pub AbilityConstraint);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AbilityConstraint(pub AbilitySet);

/// Represents a parameter.
#[derive(Debug, Clone)]
pub struct Parameter(pub Symbol, pub Type);

#[derive(Debug)]
pub struct FunctionData {
    /// Name of this function.
    name: Symbol,

    /// Location of this function.
    loc: Loc,

    /// The definition index of this function in its module.
    def_idx: FunctionDefinitionIndex,

    /// The handle index of this function in its module.
    handle_idx: FunctionHandleIndex,

    /// List of function argument names. Not in bytecode but obtained from AST.
    arg_names: Vec<Symbol>,

    /// List of type argument names. Not in bytecode but obtained from AST.
    type_arg_names: Vec<Symbol>,

    /// Specification associated with this function.
    spec: Spec,

    /// A cache for the called functions.
    called_funs: RefCell<Option<BTreeSet<QualifiedId<FunId>>>>,

    /// A cache for the calling functions.
    calling_funs: RefCell<Option<BTreeSet<QualifiedId<FunId>>>>,
}

impl FunctionData {
    pub fn stub(
        name: Symbol,
        def_idx: FunctionDefinitionIndex,
        handle_idx: FunctionHandleIndex,
    ) -> Self {
        FunctionData {
            name,
            loc: Loc::default(),
            def_idx,
            handle_idx,
            arg_names: vec![],
            type_arg_names: vec![],
            spec: Spec::default(),
            called_funs: Default::default(),
            calling_funs: Default::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionEnv<'env> {
    /// Reference to enclosing module.
    pub module_env: ModuleEnv<'env>,

    /// Reference to the function data.
    data: &'env FunctionData,
}

impl<'env> FunctionEnv<'env> {
    /// Returns the name of this function.
    pub fn get_name(&self) -> Symbol {
        self.data.name
    }

    /// Gets full name as string.
    pub fn get_full_name_str(&self) -> String {
        format!(
            "{}::{}",
            self.module_env.get_name().display(self.symbol_pool()),
            self.get_name().display(self.symbol_pool())
        )
    }

    /// Returns the VM identifier for this function
    pub fn get_identifier(&'env self) -> Identifier {
        let m = &self.module_env.data.module;
        m.identifier_at(m.function_handle_at(self.data.handle_idx).name)
            .to_owned()
    }

    /// Gets the id of this function.
    pub fn get_id(&self) -> FunId {
        FunId(self.data.name)
    }

    /// Gets the qualified id of this function.
    pub fn get_qualified_id(&self) -> QualifiedId<FunId> {
        self.module_env.get_id().qualified(self.get_id())
    }

    /// Get documentation associated with this function.
    pub fn get_doc(&self) -> &str {
        self.module_env.env.get_doc(&self.data.loc)
    }

    /// Gets the definition index of this function.
    pub fn get_def_idx(&self) -> FunctionDefinitionIndex {
        self.data.def_idx
    }

    /// Shortcut for accessing the symbol pool.
    pub fn symbol_pool(&self) -> &SymbolPool {
        self.module_env.symbol_pool()
    }

    /// Returns the location of this function.
    pub fn get_loc(&self) -> Loc {
        self.data.loc.clone()
    }

    /// Returns the location of the specification block of this function. If the function has
    /// none, returns that of the function itself.
    pub fn get_spec_loc(&self) -> Loc {
        if let Some(loc) = &self.data.spec.loc {
            loc.clone()
        } else {
            self.get_loc()
        }
    }

    /// Returns the location of the bytecode at the given offset.
    pub fn get_bytecode_loc(&self, offset: u16) -> Loc {
        if let Ok(fmap) = self
            .module_env
            .data
            .source_map
            .get_function_source_map(self.data.def_idx)
        {
            if let Some(loc) = fmap.get_code_location(offset) {
                return self.module_env.env.to_loc(&loc);
            }
        }
        self.get_loc()
    }

    /// Returns the bytecode associated with this function.
    pub fn get_bytecode(&self) -> &[Bytecode] {
        let function_definition = self
            .module_env
            .data
            .module
            .function_def_at(self.get_def_idx());
        let function_definition_view =
            FunctionDefinitionView::new(&self.module_env.data.module, function_definition);
        match function_definition_view.code() {
            Some(code) => &code.code,
            None => &[],
        }
    }

    /// Returns the value of a boolean pragma for this function. This first looks up a
    /// pragma in this function, then the enclosing module, and finally uses the provided default.
    /// value
    pub fn is_pragma_true(&self, name: &str, default: impl FnOnce() -> bool) -> bool {
        let env = self.module_env.env;
        if let Some(b) = env.is_property_true(&self.get_spec().properties, name) {
            return b;
        }
        if let Some(b) = env.is_property_true(&self.module_env.get_spec().properties, name) {
            return b;
        }
        default()
    }

    /// Returns true if the value of a boolean pragma for this function is false.
    pub fn is_pragma_false(&self, name: &str) -> bool {
        let env = self.module_env.env;
        if let Some(b) = env.is_property_true(&self.get_spec().properties, name) {
            return !b;
        }
        if let Some(b) = env.is_property_true(&self.module_env.get_spec().properties, name) {
            return !b;
        }
        false
    }

    /// Returns whether the value of a numeric pragma is explicitly set for this function.
    pub fn is_num_pragma_set(&self, name: &str) -> bool {
        let env = self.module_env.env;
        env.get_num_property(&self.get_spec().properties, name)
            .is_some()
            || env
                .get_num_property(&self.module_env.get_spec().properties, name)
                .is_some()
    }

    /// Returns the value of a numeric pragma for this function. This first looks up a
    /// pragma in this function, then the enclosing module, and finally uses the provided default.
    /// value
    pub fn get_num_pragma(&self, name: &str, default: impl FnOnce() -> usize) -> usize {
        let env = self.module_env.env;
        if let Some(n) = env.get_num_property(&self.get_spec().properties, name) {
            return n;
        }
        if let Some(n) = env.get_num_property(&self.module_env.get_spec().properties, name) {
            return n;
        }
        default()
    }

    /// Returns the value of a pragma representing an identifier for this function.
    /// If such pragma is not specified for this function, None is returned.
    pub fn get_ident_pragma(&self, name: &str) -> Option<Rc<String>> {
        let sym = &self.symbol_pool().make(name);
        match self.get_spec().properties.get(&sym) {
            Some(PropertyValue::Symbol(sym)) => Some(self.symbol_pool().string(*sym)),
            Some(PropertyValue::QualifiedSymbol(qsym)) => {
                let module_name = qsym.module_name.display(self.symbol_pool());
                Some(Rc::from(format!(
                    "{}::{}",
                    module_name,
                    self.symbol_pool().string(qsym.symbol)
                )))
            }
            _ => None,
        }
    }

    /// Returns the FunctionEnv of the function identified by the pragma, if the pragma
    /// exists and its value represents a function in the system.
    pub fn get_func_env_from_pragma(&self, name: &str) -> Option<FunctionEnv<'env>> {
        let sym = &self.symbol_pool().make(name);
        match self.get_spec().properties.get(&sym) {
            Some(PropertyValue::Symbol(sym)) => self.module_env.find_function(*sym),
            Some(PropertyValue::QualifiedSymbol(qsym)) => {
                if let Some(module_env) = self.module_env.env.find_module(&qsym.module_name) {
                    module_env.find_function(qsym.symbol)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Returns true if this function is native.
    pub fn is_native(&self) -> bool {
        let view = self.definition_view();
        view.is_native()
    }

    /// Returns true if this function has the pragma intrinsic set to true.
    pub fn is_intrinsic(&self) -> bool {
        self.is_pragma_true(INTRINSIC_PRAGMA, || false)
    }

    pub fn is_native_or_intrinsic(&self) -> bool {
        self.is_native() || self.is_intrinsic()
    }

    /// Returns true if this function is opaque.
    pub fn is_opaque(&self) -> bool {
        self.is_pragma_true(OPAQUE_PRAGMA, || false)
    }

    /// Return the visibility of this function
    pub fn visibility(&self) -> FunctionVisibility {
        self.definition_view().visibility()
    }

    /// Return the visibility string for this function. Useful for formatted printing.
    pub fn visibility_str(&self) -> &str {
        match self.visibility() {
            Visibility::Public => "public ",
            Visibility::Friend => "public(friend) ",
            Visibility::Script => "public(script) ",
            Visibility::Private => "",
        }
    }

    /// Return whether this function is exposed outside of the module.
    pub fn is_exposed(&self) -> bool {
        self.module_env.is_script_module()
            || match self.definition_view().visibility() {
                Visibility::Public | Visibility::Script | Visibility::Friend => true,
                Visibility::Private => false,
            }
    }

    /// Return whether this function is exposed outside of the module.
    pub fn has_unknown_callers(&self) -> bool {
        self.module_env.is_script_module()
            || match self.definition_view().visibility() {
                Visibility::Public | Visibility::Script => true,
                Visibility::Private | Visibility::Friend => false,
            }
    }

    /// Returns true if the function is a script function
    pub fn is_script(&self) -> bool {
        // The main function of a scipt is a script function
        self.module_env.is_script_module()
            || self.definition_view().visibility() == Visibility::Script
    }

    /// Return true if this function is a friend function
    pub fn is_friend(&self) -> bool {
        self.definition_view().visibility() == Visibility::Friend
    }

    /// Returns true if invariants are declared disabled in body of function
    pub fn are_invariants_disabled_in_body(&self) -> bool {
        self.is_pragma_true(DISABLE_INVARIANTS_IN_BODY_PRAGMA, || false)
    }

    /// Returns true if invariants are declared disabled in body of function
    pub fn are_invariants_disabled_at_call(&self) -> bool {
        self.is_pragma_true(DELEGATE_INVARIANTS_TO_CALLER_PRAGMA, || false)
    }

    /// Returns true if this function mutates any references (i.e. has &mut parameters).
    pub fn is_mutating(&self) -> bool {
        self.get_parameters()
            .iter()
            .any(|Parameter(_, ty)| ty.is_mutable_reference())
    }

    /// Returns the name of the friend(the only allowed caller) of this function, if there is one.
    pub fn get_friend_name(&self) -> Option<Rc<String>> {
        self.get_ident_pragma(FRIEND_PRAGMA)
    }

    /// Returns true if a friend is specified for this function.
    pub fn has_friend(&self) -> bool {
        self.get_friend_name().is_some()
    }

    /// Returns the FunctionEnv of the friend function if the friend is specified
    /// and the friend was compiled into the environment.
    pub fn get_friend_env(&self) -> Option<FunctionEnv<'env>> {
        self.get_func_env_from_pragma(FRIEND_PRAGMA)
    }

    /// Returns the FunctionEnv of the transitive friend of the function.
    /// For example, if `f` has a friend `g` and `g` has a friend `h`, then
    /// `f`'s transitive friend is `h`.
    /// If a friend is not specified then the function itself is returned.
    pub fn get_transitive_friend(&self) -> FunctionEnv<'env> {
        if let Some(friend_env) = self.get_friend_env() {
            return friend_env.get_transitive_friend();
        }
        self.clone()
    }

    /// Returns the type parameters associated with this function.
    pub fn get_type_parameters(&self) -> Vec<TypeParameter> {
        // TODO: currently the translation scheme isn't working with using real type
        //   parameter names, so use indices instead.
        let view = self.definition_view();
        view.type_parameters()
            .iter()
            .enumerate()
            .map(|(i, k)| {
                TypeParameter(
                    self.module_env.env.symbol_pool.make(&format!("$tv{}", i)),
                    AbilityConstraint(*k),
                )
            })
            .collect_vec()
    }

    /// Returns the type parameters with the real names.
    pub fn get_named_type_parameters(&self) -> Vec<TypeParameter> {
        let view = self.definition_view();
        view.type_parameters()
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let name = self
                    .module_env
                    .data
                    .source_map
                    .get_function_source_map(self.data.def_idx)
                    .ok()
                    .and_then(|fmap| fmap.type_parameters.get(i))
                    .map(|(s, _)| s.clone())
                    .unwrap_or_else(|| format!("unknown#{}", i));
                TypeParameter(
                    self.module_env.env.symbol_pool.make(&name),
                    AbilityConstraint(*k),
                )
            })
            .collect_vec()
    }

    pub fn get_parameter_count(&self) -> usize {
        let view = self.definition_view();
        view.arg_tokens().count()
    }

    /// Return the number of type parameters for self
    pub fn get_type_parameter_count(&self) -> usize {
        let view = self.definition_view();
        view.type_parameters().len()
    }

    /// Return `true` if idx is a formal parameter index
    pub fn is_parameter(&self, idx: usize) -> bool {
        idx < self.get_parameter_count()
    }

    /// Returns the parameter types associated with this function
    pub fn get_parameter_types(&self) -> Vec<Type> {
        let view = self.definition_view();
        view.arg_tokens()
            .map(|tv: SignatureTokenView<CompiledModule>| {
                self.module_env.globalize_signature(tv.signature_token())
            })
            .collect()
    }

    /// Returns the regular parameters associated with this function.
    pub fn get_parameters(&self) -> Vec<Parameter> {
        let view = self.definition_view();
        view.arg_tokens()
            .map(|tv: SignatureTokenView<CompiledModule>| {
                self.module_env.globalize_signature(tv.signature_token())
            })
            .zip(self.data.arg_names.iter())
            .map(|(s, i)| Parameter(*i, s))
            .collect_vec()
    }

    /// Returns return types of this function.
    pub fn get_return_types(&self) -> Vec<Type> {
        let view = self.definition_view();
        view.return_tokens()
            .map(|tv: SignatureTokenView<CompiledModule>| {
                self.module_env.globalize_signature(tv.signature_token())
            })
            .collect_vec()
    }

    /// Returns return type at given index.
    pub fn get_return_type(&self, idx: usize) -> Type {
        self.get_return_types()[idx].clone()
    }

    /// Returns the number of return values of this function.
    pub fn get_return_count(&self) -> usize {
        let view = self.definition_view();
        view.return_count()
    }

    /// Get the name to be used for a local. If the local is an argument, use that for naming,
    /// otherwise generate a unique name.
    pub fn get_local_name(&self, idx: usize) -> Symbol {
        if idx < self.data.arg_names.len() {
            return self.data.arg_names[idx as usize];
        }
        // Try to obtain name from source map.
        if let Ok(fmap) = self
            .module_env
            .data
            .source_map
            .get_function_source_map(self.data.def_idx)
        {
            if let Some((ident, _)) = fmap.get_parameter_or_local_name(idx as u64) {
                // The Move compiler produces temporary names of the form `<foo>%#<num>`,
                // where <num> seems to be generated non-deterministically.
                // Substitute this by a deterministic name which the backend accepts.
                let clean_ident = if ident.contains("%#") {
                    format!("tmp#${}", idx)
                } else {
                    ident
                };
                return self.module_env.env.symbol_pool.make(clean_ident.as_str());
            }
        }
        self.module_env.env.symbol_pool.make(&format!("$t{}", idx))
    }

    /// Returns true if the index is for a temporary, not user declared local.
    pub fn is_temporary(&self, idx: usize) -> bool {
        if idx >= self.get_local_count() {
            return true;
        }
        let name = self.get_local_name(idx);
        self.symbol_pool().string(name).contains("tmp#$")
    }

    /// Gets the number of proper locals of this function. Those are locals which are declared
    /// by the user and also have a user assigned name which can be discovered via `get_local_name`.
    /// Note we may have more anonymous locals generated e.g by the 'stackless' transformation.
    pub fn get_local_count(&self) -> usize {
        let view = self.definition_view();
        match view.locals_signature() {
            Some(locals_view) => locals_view.len(),
            None => view.parameters().len(),
        }
    }

    /// Gets the type of the local at index. This must use an index in the range as determined by
    /// `get_local_count`.
    pub fn get_local_type(&self, idx: usize) -> Type {
        let view = self.definition_view();
        let parameters = view.parameters();

        if idx < parameters.len() {
            self.module_env.globalize_signature(&parameters.0[idx])
        } else {
            self.module_env.globalize_signature(
                view.locals_signature()
                    .unwrap()
                    .token_at(idx as u8)
                    .signature_token(),
            )
        }
    }

    /// Returns associated specification.
    pub fn get_spec(&'env self) -> &'env Spec {
        &self.data.spec
    }

    /// Returns the acquired global resource types.
    pub fn get_acquires_global_resources(&'env self) -> Vec<StructId> {
        let function_definition = self
            .module_env
            .data
            .module
            .function_def_at(self.get_def_idx());
        function_definition
            .acquires_global_resources
            .iter()
            .map(|x| self.module_env.get_struct_id(*x))
            .collect()
    }

    /// Computes the modified targets of the spec clause, as a map from resource type names to
    /// resource indices (list of types and address).
    pub fn get_modify_targets(&self) -> BTreeMap<QualifiedId<StructId>, Vec<Exp>> {
        // Compute the modify targets from `modifies` conditions.
        let modify_conditions = self.get_spec().filter_kind(ConditionKind::Modifies);
        let mut modify_targets: BTreeMap<QualifiedId<StructId>, Vec<Exp>> = BTreeMap::new();
        for cond in modify_conditions {
            cond.all_exps().for_each(|target| {
                let node_id = target.node_id();
                let rty = &self.module_env.env.get_node_instantiation(node_id)[0];
                let (mid, sid, _) = rty.require_struct();
                let type_name = mid.qualified(sid);
                modify_targets
                    .entry(type_name)
                    .or_insert_with(Vec::new)
                    .push(target.clone());
            });
        }
        modify_targets
    }

    /// Determine whether the function is target of verification.
    pub fn should_verify(&self, default_scope: &VerificationScope) -> bool {
        if let VerificationScope::Only(function_name) = default_scope {
            // Overrides pragmas.
            return self.matches_name(function_name);
        }
        if !self.module_env.is_target() {
            // Don't generate verify method for functions from dependencies.
            return false;
        }

        // We look up the `verify` pragma property first in this function, then in
        // the module, and finally fall back to the value specified by default_scope.
        let default = || match default_scope {
            // By using `is_exposed`, we essentially mark all of Public, Script, Friend to be
            // in the verification scope because they are "exposed" functions in this module.
            // We may want to change `VerificationScope::Public` to `VerificationScope::Exposed` as
            // well for consistency.
            VerificationScope::Public => self.is_exposed(),
            VerificationScope::All => true,
            VerificationScope::Only(_) => unreachable!(),
            VerificationScope::OnlyModule(module_name) => self.module_env.matches_name(module_name),
            VerificationScope::None => false,
        };
        self.is_pragma_true(VERIFY_PRAGMA, default)
    }

    /// Returns true if either the name or simple name of this function matches the given string
    pub fn matches_name(&self, name: &str) -> bool {
        name.eq(&*self.get_simple_name_string()) || name.eq(&*self.get_name_string())
    }

    /// Determine whether this function is explicitly deactivated for verification.
    pub fn is_explicitly_not_verified(&self, scope: &VerificationScope) -> bool {
        !matches!(scope, VerificationScope::Only(..)) && self.is_pragma_false(VERIFY_PRAGMA)
    }

    /// Get the functions that call this one
    pub fn get_calling_functions(&self) -> BTreeSet<QualifiedId<FunId>> {
        if let Some(calling) = &*self.data.calling_funs.borrow() {
            return calling.clone();
        }
        let mut set: BTreeSet<QualifiedId<FunId>> = BTreeSet::new();
        for module_env in self.module_env.env.get_modules() {
            for fun_env in module_env.get_functions() {
                if fun_env
                    .get_called_functions()
                    .contains(&self.get_qualified_id())
                {
                    set.insert(fun_env.get_qualified_id());
                }
            }
        }
        *self.data.calling_funs.borrow_mut() = Some(set.clone());
        set
    }

    /// Get the functions that this one calls
    pub fn get_called_functions(&self) -> BTreeSet<QualifiedId<FunId>> {
        if let Some(called) = &*self.data.called_funs.borrow() {
            return called.clone();
        }
        let called: BTreeSet<_> = self
            .get_bytecode()
            .iter()
            .filter_map(|c| {
                if let Bytecode::Call(i) = c {
                    Some(self.module_env.get_used_function(*i).get_qualified_id())
                } else if let Bytecode::CallGeneric(i) = c {
                    let handle_idx = self
                        .module_env
                        .data
                        .module
                        .function_instantiation_at(*i)
                        .handle;
                    Some(
                        self.module_env
                            .get_used_function(handle_idx)
                            .get_qualified_id(),
                    )
                } else {
                    None
                }
            })
            .collect();
        *self.data.called_funs.borrow_mut() = Some(called.clone());
        called
    }

    /// Returns the function name excluding the address and the module name
    pub fn get_simple_name_string(&self) -> Rc<String> {
        self.symbol_pool().string(self.get_name())
    }

    /// Returns the function name with the module name excluding the address
    pub fn get_name_string(&self) -> Rc<str> {
        if self.module_env.is_script_module() {
            Rc::from(format!("Script::{}", self.get_simple_name_string()))
        } else {
            let module_name = self
                .module_env
                .get_name()
                .display(self.module_env.symbol_pool());
            Rc::from(format!(
                "{}::{}",
                module_name,
                self.get_simple_name_string()
            ))
        }
    }

    fn definition_view(&'env self) -> FunctionDefinitionView<'env, CompiledModule> {
        FunctionDefinitionView::new(
            &self.module_env.data.module,
            self.module_env
                .data
                .module
                .function_def_at(self.data.def_idx),
        )
    }

    /// Produce a TypeDisplayContext to print types within the scope of this env
    pub fn get_type_display_ctxt(&self) -> TypeDisplayContext {
        let type_param_names = self
            .get_type_parameters()
            .iter()
            .map(|param| param.0)
            .collect();
        TypeDisplayContext::WithEnv {
            env: self.module_env.env,
            type_param_names: Some(type_param_names),
        }
    }
}

// =================================================================================================
/// # Formatting

pub struct LocDisplay<'env> {
    loc: &'env Loc,
    env: &'env GlobalEnv,
    only_line: bool,
}

impl Loc {
    pub fn display<'env>(&'env self, env: &'env GlobalEnv) -> LocDisplay<'env> {
        LocDisplay {
            loc: self,
            env,
            only_line: false,
        }
    }

    pub fn display_line_only<'env>(&'env self, env: &'env GlobalEnv) -> LocDisplay<'env> {
        LocDisplay {
            loc: self,
            env,
            only_line: true,
        }
    }
}

impl<'env> fmt::Display for LocDisplay<'env> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some((fname, pos)) = self.env.get_file_and_location(&self.loc) {
            if self.only_line {
                write!(f, "at {}:{}", fname, pos.line + LineOffset(1))
            } else {
                let offset = self.loc.span.end() - self.loc.span.start();
                write!(
                    f,
                    "at {}:{}:{}+{}",
                    fname,
                    pos.line + LineOffset(1),
                    pos.column + ColumnOffset(1),
                    offset,
                )
            }
        } else {
            write!(f, "{:?}", self.loc)
        }
    }
}

pub trait GetNameString {
    fn get_name_for_display(&self, env: &GlobalEnv) -> String;
}

impl GetNameString for QualifiedId<StructId> {
    fn get_name_for_display(&self, env: &GlobalEnv) -> String {
        env.get_struct_qid(*self).get_full_name_str()
    }
}

impl GetNameString for QualifiedId<FunId> {
    fn get_name_for_display(&self, env: &GlobalEnv) -> String {
        env.get_function_qid(*self).get_full_name_str()
    }
}

impl<'a, Id: Clone> fmt::Display for EnvDisplay<'a, QualifiedId<Id>>
where
    QualifiedId<Id>: GetNameString,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.val.get_name_for_display(self.env))
    }
}

impl<'a, Id: Clone> fmt::Display for EnvDisplay<'a, QualifiedInstId<Id>>
where
    QualifiedId<Id>: GetNameString,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.env.display(&self.val.to_qualified_id()))?;
        if !self.val.inst.is_empty() {
            let tctx = TypeDisplayContext::WithEnv {
                env: self.env,
                type_param_names: None,
            };
            write!(f, "<")?;
            let mut sep = "";
            for ty in &self.val.inst {
                write!(f, "{}{}", sep, ty.display(&tctx))?;
                sep = ", ";
            }
            write!(f, ">")?;
        }
        Ok(())
    }
}
