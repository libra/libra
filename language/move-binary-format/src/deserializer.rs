// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{check_bounds::BoundsChecker, errors::*, file_format::*, file_format_common::*};
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, vm_status::StatusCode,
};
use std::{collections::HashSet, convert::TryInto, io::Read};

impl CompiledScript {
    /// Deserializes a &[u8] slice into a `CompiledScript` instance.
    pub fn deserialize(binary: &[u8]) -> BinaryLoaderResult<Self> {
        let script = CompiledScript::deserialize_no_check_bounds(binary)?;
        BoundsChecker::verify_script(&script)?;
        Ok(script)
    }

    // exposed as a public function to enable testing the deserializer
    #[doc(hidden)]
    pub fn deserialize_no_check_bounds(binary: &[u8]) -> BinaryLoaderResult<Self> {
        deserialize_compiled_script(binary)
    }
}

impl CompiledModule {
    /// Deserialize a &[u8] slice into a `CompiledModule` instance.
    pub fn deserialize(binary: &[u8]) -> BinaryLoaderResult<Self> {
        CompiledModule::deserialize_no_check_bounds(binary)?.freeze()
    }

    // exposed as a public function to enable testing the deserializer
    pub fn deserialize_no_check_bounds(binary: &[u8]) -> BinaryLoaderResult<Self> {
        deserialize_compiled_module(binary)
    }
}

/// Table info: table type, offset where the table content starts from, count of bytes for
/// the table content.
#[derive(Clone, Debug)]
struct Table {
    kind: TableType,
    offset: u32,
    count: u32,
}

impl Table {
    fn new(kind: TableType, offset: u32, count: u32) -> Table {
        Table {
            kind,
            offset,
            count,
        }
    }
}

fn read_u64_internal(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u64> {
    let mut u64_bytes = [0; 8];
    cursor
        .read_exact(&mut u64_bytes)
        .map_err(|_| PartialVMError::new(StatusCode::BAD_U64))?;
    Ok(u64::from_le_bytes(u64_bytes))
}

fn read_u128_internal(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u128> {
    let mut u128_bytes = [0; 16];
    cursor
        .read_exact(&mut u128_bytes)
        .map_err(|_| PartialVMError::new(StatusCode::BAD_U128))?;
    Ok(u128::from_le_bytes(u128_bytes))
}

//
// Helpers to read all uleb128 encoded integers.
//
fn read_uleb_internal<T>(cursor: &mut VersionedCursor, max: u64) -> BinaryLoaderResult<T>
where
    u64: TryInto<T>,
{
    let x = cursor.read_uleb128_as_u64().map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED).with_message("Bad Uleb".to_string())
    })?;
    if x > max {
        return Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Uleb greater than max requested".to_string()));
    }

    x.try_into().map_err(|_| {
        // TODO: review this status code.
        let msg = "Failed to convert u64 to target integer type. This should not happen. Is the maximum value correct?".to_string();
        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR).with_message(msg)
    })
}

fn load_signature_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<SignatureIndex> {
    Ok(SignatureIndex(read_uleb_internal(
        cursor,
        SIGNATURE_INDEX_MAX,
    )?))
}

fn load_module_handle_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<ModuleHandleIndex> {
    Ok(ModuleHandleIndex(read_uleb_internal(
        cursor,
        MODULE_HANDLE_INDEX_MAX,
    )?))
}

fn load_identifier_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<IdentifierIndex> {
    Ok(IdentifierIndex(read_uleb_internal(
        cursor,
        IDENTIFIER_INDEX_MAX,
    )?))
}

fn load_struct_handle_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<StructHandleIndex> {
    Ok(StructHandleIndex(read_uleb_internal(
        cursor,
        STRUCT_HANDLE_INDEX_MAX,
    )?))
}

fn load_address_identifier_index(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<AddressIdentifierIndex> {
    Ok(AddressIdentifierIndex(read_uleb_internal(
        cursor,
        ADDRESS_INDEX_MAX,
    )?))
}

fn load_struct_def_index(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<StructDefinitionIndex> {
    Ok(StructDefinitionIndex(read_uleb_internal(
        cursor,
        STRUCT_DEF_INDEX_MAX,
    )?))
}

fn load_function_handle_index(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<FunctionHandleIndex> {
    Ok(FunctionHandleIndex(read_uleb_internal(
        cursor,
        FUNCTION_HANDLE_INDEX_MAX,
    )?))
}

fn load_field_handle_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<FieldHandleIndex> {
    Ok(FieldHandleIndex(read_uleb_internal(
        cursor,
        FIELD_HANDLE_INDEX_MAX,
    )?))
}

fn load_field_inst_index(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<FieldInstantiationIndex> {
    Ok(FieldInstantiationIndex(read_uleb_internal(
        cursor,
        FIELD_INST_INDEX_MAX,
    )?))
}

fn load_function_inst_index(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<FunctionInstantiationIndex> {
    Ok(FunctionInstantiationIndex(read_uleb_internal(
        cursor,
        FUNCTION_INST_INDEX_MAX,
    )?))
}

fn load_struct_def_inst_index(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<StructDefInstantiationIndex> {
    Ok(StructDefInstantiationIndex(read_uleb_internal(
        cursor,
        STRUCT_DEF_INST_INDEX_MAX,
    )?))
}

fn load_constant_pool_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<ConstantPoolIndex> {
    Ok(ConstantPoolIndex(read_uleb_internal(
        cursor,
        CONSTANT_INDEX_MAX,
    )?))
}

fn load_bytecode_count(cursor: &mut VersionedCursor) -> BinaryLoaderResult<usize> {
    read_uleb_internal(cursor, BYTECODE_COUNT_MAX)
}

fn load_bytecode_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u16> {
    read_uleb_internal(cursor, BYTECODE_INDEX_MAX)
}

fn load_acquires_count(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u64> {
    read_uleb_internal(cursor, ACQUIRES_COUNT_MAX)
}

fn load_field_count(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u64> {
    read_uleb_internal(cursor, FIELD_COUNT_MAX)
}

fn load_type_parameter_count(cursor: &mut VersionedCursor) -> BinaryLoaderResult<usize> {
    read_uleb_internal(cursor, TYPE_PARAMETER_COUNT_MAX)
}

fn load_signature_size(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u64> {
    read_uleb_internal(cursor, SIGNATURE_SIZE_MAX)
}

fn load_constant_size(cursor: &mut VersionedCursor) -> BinaryLoaderResult<usize> {
    read_uleb_internal(cursor, CONSTANT_SIZE_MAX)
}

fn load_identifier_size(cursor: &mut VersionedCursor) -> BinaryLoaderResult<usize> {
    read_uleb_internal(cursor, IDENTIFIER_SIZE_MAX)
}

fn load_type_parameter_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u16> {
    read_uleb_internal(cursor, TYPE_PARAMETER_INDEX_MAX)
}

fn load_field_offset(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u16> {
    read_uleb_internal(cursor, FIELD_OFFSET_MAX)
}

fn load_table_count(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u8> {
    read_uleb_internal(cursor, TABLE_COUNT_MAX)
}

fn load_table_offset(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u32> {
    read_uleb_internal(cursor, TABLE_OFFSET_MAX)
}

fn load_table_size(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u32> {
    read_uleb_internal(cursor, TABLE_SIZE_MAX)
}

fn load_local_index(cursor: &mut VersionedCursor) -> BinaryLoaderResult<u8> {
    read_uleb_internal(cursor, LOCAL_INDEX_MAX)
}

/// Module internal function that manages deserialization of transactions.
fn deserialize_compiled_script(binary: &[u8]) -> BinaryLoaderResult<CompiledScript> {
    let binary_len = binary.len();
    let mut cursor = VersionedCursor::new(binary)?;
    let table_count = load_table_count(&mut cursor)?;
    let mut tables: Vec<Table> = Vec::new();
    read_tables(&mut cursor, table_count, &mut tables)?;
    let content_len = check_tables(&mut tables, binary_len)?;

    let mut table_contents_buffer = Vec::new();
    let table_contents = read_table_contents(
        &mut cursor,
        &mut table_contents_buffer,
        content_len as usize,
    )?;

    let mut script = CompiledScript {
        version: cursor.version(),
        type_parameters: load_ability_sets(
            &mut cursor,
            AbilitySetPosition::FunctionTypeParameters,
        )?,
        parameters: load_signature_index(&mut cursor)?,
        code: load_code_unit(&mut cursor)?,
        ..Default::default()
    };

    build_compiled_script(&mut script, &table_contents, &tables)?;
    Ok(script)
}

/// Module internal function that manages deserialization of modules.
fn deserialize_compiled_module(binary: &[u8]) -> BinaryLoaderResult<CompiledModule> {
    let binary_len = binary.len();
    let mut cursor = VersionedCursor::new(binary)?;
    let table_count = load_table_count(&mut cursor)?;
    let mut tables: Vec<Table> = Vec::new();
    read_tables(&mut cursor, table_count, &mut tables)?;
    let content_len = check_tables(&mut tables, binary_len)?;

    let mut table_contents_buffer = Vec::new();
    let table_contents = read_table_contents(
        &mut cursor,
        &mut table_contents_buffer,
        content_len as usize,
    )?;

    let mut module = CompiledModule {
        version: cursor.version(),
        self_module_handle_idx: load_module_handle_index(&mut cursor)?,
        ..Default::default()
    };

    build_compiled_module(&mut module, &table_contents, &tables)?;

    Ok(module)
}

/// Reads all the table headers.
///
/// Return a Vec<Table> that contains all the table headers defined and checked.
fn read_tables(
    cursor: &mut VersionedCursor,
    table_count: u8,
    tables: &mut Vec<Table>,
) -> BinaryLoaderResult<()> {
    for _count in 0..table_count {
        tables.push(read_table(cursor)?);
    }
    Ok(())
}

/// Reads a table from a slice at a given offset.
/// If a table is not recognized an error is returned.
fn read_table(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Table> {
    let kind = match cursor.read_u8() {
        Ok(kind) => kind,
        Err(_) => {
            return Err(PartialVMError::new(StatusCode::MALFORMED)
                .with_message("Error reading table".to_string()))
        }
    };
    let table_offset = load_table_offset(cursor)?;
    let count = load_table_size(cursor)?;
    Ok(Table::new(TableType::from_u8(kind)?, table_offset, count))
}

fn read_table_contents<'a>(
    cursor: &mut VersionedCursor,
    buffer: &'a mut Vec<u8>,
    n: usize,
) -> BinaryLoaderResult<VersionedBinary<'a>> {
    cursor
        .read_new_binary(buffer, n)
        .map_err(|e| e.with_message("Error reading table contents".to_string()))
}

/// Verify correctness of tables.
///
/// Tables cannot have duplicates, must cover the entire blob and must be disjoint.
fn check_tables(tables: &mut Vec<Table>, binary_len: usize) -> BinaryLoaderResult<u32> {
    // there is no real reason to pass a mutable reference but we are sorting next line
    tables.sort_by(|t1, t2| t1.offset.cmp(&t2.offset));

    let mut current_offset: u32 = 0;
    let mut table_types = HashSet::new();
    for table in tables {
        if table.offset != current_offset {
            return Err(PartialVMError::new(StatusCode::BAD_HEADER_TABLE));
        }
        if table.count == 0 {
            return Err(PartialVMError::new(StatusCode::BAD_HEADER_TABLE));
        }
        match current_offset.checked_add(table.count) {
            Some(checked_offset) => current_offset = checked_offset,
            None => return Err(PartialVMError::new(StatusCode::BAD_HEADER_TABLE)),
        }
        if !table_types.insert(table.kind) {
            return Err(PartialVMError::new(StatusCode::DUPLICATE_TABLE));
        }
        if current_offset as usize > binary_len {
            return Err(PartialVMError::new(StatusCode::BAD_HEADER_TABLE));
        }
    }
    Ok(current_offset)
}

//
// Trait to read common tables from CompiledScript or CompiledModule
//

trait CommonTables {
    fn get_module_handles(&mut self) -> &mut Vec<ModuleHandle>;
    fn get_struct_handles(&mut self) -> &mut Vec<StructHandle>;
    fn get_function_handles(&mut self) -> &mut Vec<FunctionHandle>;
    fn get_function_instantiations(&mut self) -> &mut Vec<FunctionInstantiation>;
    fn get_signatures(&mut self) -> &mut SignaturePool;
    fn get_identifiers(&mut self) -> &mut IdentifierPool;
    fn get_address_identifiers(&mut self) -> &mut AddressIdentifierPool;
    fn get_constant_pool(&mut self) -> &mut ConstantPool;
}

impl CommonTables for CompiledScript {
    fn get_module_handles(&mut self) -> &mut Vec<ModuleHandle> {
        &mut self.module_handles
    }

    fn get_struct_handles(&mut self) -> &mut Vec<StructHandle> {
        &mut self.struct_handles
    }

    fn get_function_handles(&mut self) -> &mut Vec<FunctionHandle> {
        &mut self.function_handles
    }

    fn get_function_instantiations(&mut self) -> &mut Vec<FunctionInstantiation> {
        &mut self.function_instantiations
    }

    fn get_signatures(&mut self) -> &mut SignaturePool {
        &mut self.signatures
    }

    fn get_identifiers(&mut self) -> &mut IdentifierPool {
        &mut self.identifiers
    }

    fn get_address_identifiers(&mut self) -> &mut AddressIdentifierPool {
        &mut self.address_identifiers
    }

    fn get_constant_pool(&mut self) -> &mut ConstantPool {
        &mut self.constant_pool
    }
}

impl CommonTables for CompiledModule {
    fn get_module_handles(&mut self) -> &mut Vec<ModuleHandle> {
        &mut self.module_handles
    }

    fn get_struct_handles(&mut self) -> &mut Vec<StructHandle> {
        &mut self.struct_handles
    }

    fn get_function_handles(&mut self) -> &mut Vec<FunctionHandle> {
        &mut self.function_handles
    }

    fn get_function_instantiations(&mut self) -> &mut Vec<FunctionInstantiation> {
        &mut self.function_instantiations
    }

    fn get_signatures(&mut self) -> &mut SignaturePool {
        &mut self.signatures
    }

    fn get_identifiers(&mut self) -> &mut IdentifierPool {
        &mut self.identifiers
    }

    fn get_address_identifiers(&mut self) -> &mut AddressIdentifierPool {
        &mut self.address_identifiers
    }

    fn get_constant_pool(&mut self) -> &mut ConstantPool {
        &mut self.constant_pool
    }
}

/// Builds and returns a `CompiledScript`.
fn build_compiled_script(
    script: &mut CompiledScript,
    binary: &VersionedBinary,
    tables: &[Table],
) -> BinaryLoaderResult<()> {
    build_common_tables(binary, tables, script)?;
    build_script_tables(binary, tables, script)?;
    Ok(())
}

/// Builds and returns a `CompiledModule`.
fn build_compiled_module(
    module: &mut CompiledModule,
    binary: &VersionedBinary,
    tables: &[Table],
) -> BinaryLoaderResult<()> {
    build_common_tables(binary, tables, module)?;
    build_module_tables(binary, tables, module)?;
    Ok(())
}

/// Builds the common tables in a compiled unit.
fn build_common_tables(
    binary: &VersionedBinary,
    tables: &[Table],
    common: &mut impl CommonTables,
) -> BinaryLoaderResult<()> {
    for table in tables {
        match table.kind {
            TableType::MODULE_HANDLES => {
                load_module_handles(binary, table, common.get_module_handles())?;
            }
            TableType::STRUCT_HANDLES => {
                load_struct_handles(binary, table, common.get_struct_handles())?;
            }
            TableType::FUNCTION_HANDLES => {
                load_function_handles(binary, table, common.get_function_handles())?;
            }
            TableType::FUNCTION_INST => {
                load_function_instantiations(binary, table, common.get_function_instantiations())?;
            }
            TableType::SIGNATURES => {
                load_signatures(binary, table, common.get_signatures())?;
            }
            TableType::CONSTANT_POOL => {
                load_constant_pool(binary, table, common.get_constant_pool())?;
            }
            TableType::IDENTIFIERS => {
                load_identifiers(binary, table, common.get_identifiers())?;
            }
            TableType::ADDRESS_IDENTIFIERS => {
                load_address_identifiers(binary, table, common.get_address_identifiers())?;
            }
            TableType::FUNCTION_DEFS
            | TableType::STRUCT_DEFS
            | TableType::STRUCT_DEF_INST
            | TableType::FIELD_HANDLE
            | TableType::FIELD_INST => continue,
            TableType::FRIEND_DECLS => {
                // friend declarations do not exist before VERSION_2
                if binary.version() < VERSION_2 {
                    return Err(PartialVMError::new(StatusCode::MALFORMED).with_message(
                        "Friend declarations not applicable in bytecode version 1".to_string(),
                    ));
                }
                continue;
            }
        }
    }
    Ok(())
}

/// Builds tables related to a `CompiledModule`.
fn build_module_tables(
    binary: &VersionedBinary,
    tables: &[Table],
    module: &mut CompiledModule,
) -> BinaryLoaderResult<()> {
    for table in tables {
        match table.kind {
            TableType::STRUCT_DEFS => {
                load_struct_defs(binary, table, &mut module.struct_defs)?;
            }
            TableType::STRUCT_DEF_INST => {
                load_struct_instantiations(binary, table, &mut module.struct_def_instantiations)?;
            }
            TableType::FUNCTION_DEFS => {
                load_function_defs(binary, table, &mut module.function_defs)?;
            }
            TableType::FIELD_HANDLE => {
                load_field_handles(binary, table, &mut module.field_handles)?;
            }
            TableType::FIELD_INST => {
                load_field_instantiations(binary, table, &mut module.field_instantiations)?;
            }
            TableType::FRIEND_DECLS => {
                load_module_handles(binary, table, &mut module.friend_decls)?;
            }
            TableType::MODULE_HANDLES
            | TableType::STRUCT_HANDLES
            | TableType::FUNCTION_HANDLES
            | TableType::FUNCTION_INST
            | TableType::IDENTIFIERS
            | TableType::ADDRESS_IDENTIFIERS
            | TableType::CONSTANT_POOL
            | TableType::SIGNATURES => {
                continue;
            }
        }
    }
    Ok(())
}

/// Builds tables related to a `CompiledScript`.
fn build_script_tables(
    _binary: &VersionedBinary,
    tables: &[Table],
    _script: &mut CompiledScript,
) -> BinaryLoaderResult<()> {
    for table in tables {
        match table.kind {
            TableType::MODULE_HANDLES
            | TableType::STRUCT_HANDLES
            | TableType::FUNCTION_HANDLES
            | TableType::FUNCTION_INST
            | TableType::SIGNATURES
            | TableType::IDENTIFIERS
            | TableType::ADDRESS_IDENTIFIERS
            | TableType::CONSTANT_POOL => {
                continue;
            }
            TableType::STRUCT_DEFS
            | TableType::STRUCT_DEF_INST
            | TableType::FUNCTION_DEFS
            | TableType::FIELD_INST
            | TableType::FIELD_HANDLE
            | TableType::FRIEND_DECLS => {
                return Err(PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Bad table in Script".to_string()));
            }
        }
    }
    Ok(())
}

/// Builds the `ModuleHandle` table.
fn load_module_handles(
    binary: &VersionedBinary,
    table: &Table,
    module_handles: &mut Vec<ModuleHandle>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < table.count as u64 {
        let address = load_address_identifier_index(&mut cursor)?;
        let name = load_identifier_index(&mut cursor)?;
        module_handles.push(ModuleHandle { address, name });
    }
    Ok(())
}

/// Builds the `StructHandle` table.
fn load_struct_handles(
    binary: &VersionedBinary,
    table: &Table,
    struct_handles: &mut Vec<StructHandle>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < table.count as u64 {
        let module = load_module_handle_index(&mut cursor)?;
        let name = load_identifier_index(&mut cursor)?;
        let abilities = load_ability_set(&mut cursor, AbilitySetPosition::StructHandle)?;
        let type_parameters = load_struct_type_parameters(&mut cursor)?;
        struct_handles.push(StructHandle {
            module,
            name,
            abilities,
            type_parameters,
        });
    }
    Ok(())
}

/// Builds the `FunctionHandle` table.
fn load_function_handles(
    binary: &VersionedBinary,
    table: &Table,
    function_handles: &mut Vec<FunctionHandle>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < table.count as u64 {
        let module = load_module_handle_index(&mut cursor)?;
        let name = load_identifier_index(&mut cursor)?;
        let parameters = load_signature_index(&mut cursor)?;
        let return_ = load_signature_index(&mut cursor)?;
        let type_parameters =
            load_ability_sets(&mut cursor, AbilitySetPosition::FunctionTypeParameters)?;

        function_handles.push(FunctionHandle {
            module,
            name,
            parameters,
            return_,
            type_parameters,
        });
    }
    Ok(())
}

/// Builds the `StructInstantiation` table.
fn load_struct_instantiations(
    binary: &VersionedBinary,
    table: &Table,
    struct_insts: &mut Vec<StructDefInstantiation>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);

    while cursor.position() < table.count as u64 {
        let def = load_struct_def_index(&mut cursor)?;
        let type_parameters = load_signature_index(&mut cursor)?;
        struct_insts.push(StructDefInstantiation {
            def,
            type_parameters,
        });
    }
    Ok(())
}

/// Builds the `FunctionInstantiation` table.
fn load_function_instantiations(
    binary: &VersionedBinary,
    table: &Table,
    func_insts: &mut Vec<FunctionInstantiation>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < table.count as u64 {
        let handle = load_function_handle_index(&mut cursor)?;
        let type_parameters = load_signature_index(&mut cursor)?;
        func_insts.push(FunctionInstantiation {
            handle,
            type_parameters,
        });
    }
    Ok(())
}

/// Builds the `IdentifierPool`.
fn load_identifiers(
    binary: &VersionedBinary,
    table: &Table,
    identifiers: &mut IdentifierPool,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < u64::from(table.count) {
        let size = load_identifier_size(&mut cursor)?;
        let mut buffer: Vec<u8> = vec![0u8; size];
        if let Ok(count) = cursor.read(&mut buffer) {
            if count != size {
                return Err(PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Bad Identifier pool size".to_string()));
            }
            let s = Identifier::from_utf8(buffer).map_err(|_| {
                PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Invalid Identifier".to_string())
            })?;
            identifiers.push(s);
        }
    }
    Ok(())
}

/// Builds the `AddressIdentifierPool`.
fn load_address_identifiers(
    binary: &VersionedBinary,
    table: &Table,
    addresses: &mut AddressIdentifierPool,
) -> BinaryLoaderResult<()> {
    let mut start = table.offset as usize;
    if table.count as usize % AccountAddress::LENGTH != 0 {
        return Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Bad Address Identifier pool size".to_string()));
    }
    for _i in 0..table.count as usize / AccountAddress::LENGTH {
        let end_addr = start + AccountAddress::LENGTH;
        let address = binary.slice(start, end_addr).try_into();
        if address.is_err() {
            return Err(PartialVMError::new(StatusCode::MALFORMED)
                .with_message("Invalid Address format".to_string()));
        }
        start = end_addr;

        addresses.push(address.unwrap());
    }
    Ok(())
}

/// Builds the `ConstantPool`.
fn load_constant_pool(
    binary: &VersionedBinary,
    table: &Table,
    constants: &mut ConstantPool,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < u64::from(table.count) {
        constants.push(load_constant(&mut cursor)?)
    }
    Ok(())
}

/// Build a single `Constant`
fn load_constant(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Constant> {
    let type_ = load_signature_token(cursor)?;
    let size = load_constant_size(cursor)?;
    let mut data: Vec<u8> = vec![0u8; size];
    let count = cursor.read(&mut data).map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Unexpected end of table".to_string())
    })?;
    if count != size {
        return Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Bad Constant data size".to_string()));
    }
    Ok(Constant { type_, data })
}

/// Builds the `SignaturePool`.
fn load_signatures(
    binary: &VersionedBinary,
    table: &Table,
    signatures: &mut SignaturePool,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < u64::from(table.count) {
        signatures.push(Signature(load_signature_tokens(&mut cursor)?));
    }
    Ok(())
}

fn load_signature_tokens(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Vec<SignatureToken>> {
    let len = load_signature_size(cursor)?;
    let mut tokens = vec![];
    for _ in 0..len {
        tokens.push(load_signature_token(cursor)?);
    }
    Ok(tokens)
}

#[cfg(test)]
pub fn load_signature_token_test_entry(
    cursor: std::io::Cursor<&[u8]>,
) -> BinaryLoaderResult<SignatureToken> {
    load_signature_token(&mut VersionedCursor::new_for_test(VERSION_MAX, cursor))
}

/// Deserializes a `SignatureToken`.
fn load_signature_token(cursor: &mut VersionedCursor) -> BinaryLoaderResult<SignatureToken> {
    // The following algorithm works by storing partially constructed types on a stack.
    //
    // Example:
    //
    //     SignatureToken: `Foo<u8, Foo<u64, bool, Bar>, address>`
    //     Byte Stream:    Foo u8 Foo u64 bool Bar address
    //
    // Stack Transitions:
    //     []
    //     [Foo<?, ?, ?>]
    //     [Foo<?, ?, ?>, u8]
    //     [Foo<u8, ?, ?>]
    //     [Foo<u8, ?, ?>, Foo<?, ?, ?>]
    //     [Foo<u8, ?, ?>, Foo<?, ?, ?>, u64]
    //     [Foo<u8, ?, ?>, Foo<u64, ?, ?>]
    //     [Foo<u8, ?, ?>, Foo<u64, ?, ?>, bool]
    //     [Foo<u8, ?, ?>, Foo<u64, bool, ?>]
    //     [Foo<u8, ?, ?>, Foo<u64, bool, ?>, Bar]
    //     [Foo<u8, ?, ?>, Foo<u64, bool, Bar>]
    //     [Foo<u8, Foo<u64, bool, Bar>, ?>]
    //     [Foo<u8, Foo<u64, bool, Bar>, ?>, address]
    //     [Foo<u8, Foo<u64, bool, Bar>, address>]        (done)

    use SerializedType as S;

    enum TypeBuilder {
        Saturated(SignatureToken),
        Vector,
        Reference,
        MutableReference,
        StructInst {
            sh_idx: StructHandleIndex,
            arity: usize,
            ty_args: Vec<SignatureToken>,
        },
    }

    impl TypeBuilder {
        fn apply(self, tok: SignatureToken) -> Self {
            match self {
                T::Vector => T::Saturated(SignatureToken::Vector(Box::new(tok))),
                T::Reference => T::Saturated(SignatureToken::Reference(Box::new(tok))),
                T::MutableReference => {
                    T::Saturated(SignatureToken::MutableReference(Box::new(tok)))
                }
                T::StructInst {
                    sh_idx,
                    arity,
                    mut ty_args,
                } => {
                    ty_args.push(tok);
                    if ty_args.len() >= arity {
                        T::Saturated(SignatureToken::StructInstantiation(sh_idx, ty_args))
                    } else {
                        T::StructInst {
                            sh_idx,
                            arity,
                            ty_args,
                        }
                    }
                }
                _ => unreachable!("invalid type constructor application"),
            }
        }

        fn is_saturated(&self) -> bool {
            matches!(self, T::Saturated(_))
        }

        fn unwrap_saturated(self) -> SignatureToken {
            match self {
                T::Saturated(tok) => tok,
                _ => unreachable!("cannot unwrap unsaturated type constructor"),
            }
        }
    }

    use TypeBuilder as T;

    let mut read_next = || {
        if let Ok(byte) = cursor.read_u8() {
            Ok(match S::from_u8(byte)? {
                S::BOOL => T::Saturated(SignatureToken::Bool),
                S::U8 => T::Saturated(SignatureToken::U8),
                S::U64 => T::Saturated(SignatureToken::U64),
                S::U128 => T::Saturated(SignatureToken::U128),
                S::ADDRESS => T::Saturated(SignatureToken::Address),
                S::SIGNER => T::Saturated(SignatureToken::Signer),
                S::VECTOR => T::Vector,
                S::REFERENCE => T::Reference,
                S::MUTABLE_REFERENCE => T::MutableReference,
                S::STRUCT => {
                    let sh_idx = load_struct_handle_index(cursor)?;
                    T::Saturated(SignatureToken::Struct(sh_idx))
                }
                S::STRUCT_INST => {
                    let sh_idx = load_struct_handle_index(cursor)?;
                    let arity = load_type_parameter_count(cursor)?;
                    T::StructInst {
                        sh_idx,
                        arity,
                        ty_args: vec![],
                    }
                }
                S::TYPE_PARAMETER => {
                    let idx = load_type_parameter_index(cursor)?;
                    T::Saturated(SignatureToken::TypeParameter(idx))
                }
            })
        } else {
            Err(PartialVMError::new(StatusCode::MALFORMED)
                .with_message("Unexpected EOF".to_string()))
        }
    };

    let mut stack = match read_next()? {
        T::Saturated(tok) => return Ok(tok),
        t => vec![t],
    };

    loop {
        if stack.len() > SIGNATURE_TOKEN_DEPTH_MAX {
            return Err(PartialVMError::new(StatusCode::MALFORMED)
                .with_message("Maximum recursion depth reached".to_string()));
        }
        if stack.last().unwrap().is_saturated() {
            let tok = stack.pop().unwrap().unwrap_saturated();
            match stack.pop() {
                Some(t) => stack.push(t.apply(tok)),
                None => return Ok(tok),
            }
        } else {
            stack.push(read_next()?)
        }
    }
}

#[derive(Copy, Clone)]
enum AbilitySetPosition {
    FunctionTypeParameters,
    StructTypeParameters,
    StructHandle,
}

fn load_ability_set(
    cursor: &mut VersionedCursor,
    pos: AbilitySetPosition,
) -> BinaryLoaderResult<AbilitySet> {
    // If the module was on the old kind system:
    // - For struct declarations
    //   - resource kind structs become store+resource structs
    //   - copyable kind structs become store+copy+drop structs
    // - For function type parameter constraints
    //   - all kind becomes store, since it might be used in global storage
    //   - resource kind becomes store+resource
    //   - copyable kind becomes store+copy+drop
    // - For struct type parameter constraints
    //   - all kind becomes empty
    //   - resource kind becomes resource
    //   - copyable kind becomes copy+drop
    // In summary, we do not need store on the struct type parameter case for backwards
    // compatibility because any old code paths or entry points will use them with store types.
    // Any new code paths gain flexibility by being able to use the struct with possibly non-store
    // instantiations
    if cursor.version() < 2 {
        let byte = match cursor.read_u8() {
            Ok(byte) => byte,
            Err(_) => {
                return Err(PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Unexpected EOF".to_string()))
            }
        };
        match pos {
            AbilitySetPosition::StructHandle => {
                Ok(match DeprecatedNominalResourceFlag::from_u8(byte)? {
                    DeprecatedNominalResourceFlag::NOMINAL_RESOURCE => {
                        AbilitySet::EMPTY | Ability::Store | Ability::Key
                    }
                    DeprecatedNominalResourceFlag::NORMAL_STRUCT => {
                        AbilitySet::EMPTY | Ability::Store | Ability::Copy | Ability::Drop
                    }
                })
            }
            AbilitySetPosition::FunctionTypeParameters
            | AbilitySetPosition::StructTypeParameters => {
                let set = match DeprecatedKind::from_u8(byte)? {
                    DeprecatedKind::ALL => AbilitySet::EMPTY,
                    DeprecatedKind::COPYABLE => AbilitySet::EMPTY | Ability::Copy | Ability::Drop,
                    DeprecatedKind::RESOURCE => AbilitySet::EMPTY | Ability::Key,
                };
                Ok(match pos {
                    AbilitySetPosition::StructHandle => unreachable!(),
                    AbilitySetPosition::FunctionTypeParameters => set | Ability::Store,
                    AbilitySetPosition::StructTypeParameters => set,
                })
            }
        }
    } else {
        // The uleb here doesn't really do anything as it is bounded currently to 0xF, but the
        // if we get many more constraints in the future, uleb will be helpful.
        let u = read_uleb_internal(cursor, AbilitySet::ALL.into_u8() as u64)?;
        match AbilitySet::from_u8(u) {
            Some(abilities) => Ok(abilities),
            None => Err(PartialVMError::new(StatusCode::UNKNOWN_ABILITY)),
        }
    }
}

fn load_ability_sets(
    cursor: &mut VersionedCursor,
    pos: AbilitySetPosition,
) -> BinaryLoaderResult<Vec<AbilitySet>> {
    let len = load_type_parameter_count(cursor)?;
    let mut kinds = vec![];
    for _ in 0..len {
        kinds.push(load_ability_set(cursor, pos)?);
    }
    Ok(kinds)
}

fn load_struct_type_parameters(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<Vec<StructTypeParameter>> {
    let len = load_type_parameter_count(cursor)?;
    let mut type_params = Vec::with_capacity(len);
    for _ in 0..len {
        type_params.push(load_struct_type_parameter(cursor)?);
    }
    Ok(type_params)
}

fn load_struct_type_parameter(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<StructTypeParameter> {
    let constraints = load_ability_set(cursor, AbilitySetPosition::StructTypeParameters)?;
    let is_phantom = if cursor.version() < VERSION_3 {
        false
    } else {
        let byte: u8 = read_uleb_internal(cursor, 1)?;
        byte != 0
    };
    Ok(StructTypeParameter {
        constraints,
        is_phantom,
    })
}

/// Builds the `StructDefinition` table.
fn load_struct_defs(
    binary: &VersionedBinary,
    table: &Table,
    struct_defs: &mut Vec<StructDefinition>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < u64::from(table.count) {
        let struct_handle = load_struct_handle_index(&mut cursor)?;
        let field_information_flag = match cursor.read_u8() {
            Ok(byte) => SerializedNativeStructFlag::from_u8(byte)?,
            Err(_) => {
                return Err(PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Invalid field info in struct".to_string()))
            }
        };
        let field_information = match field_information_flag {
            SerializedNativeStructFlag::NATIVE => StructFieldInformation::Native,
            SerializedNativeStructFlag::DECLARED => {
                let fields = load_field_defs(&mut cursor)?;
                StructFieldInformation::Declared(fields)
            }
        };
        struct_defs.push(StructDefinition {
            struct_handle,
            field_information,
        });
    }
    Ok(())
}

fn load_field_defs(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Vec<FieldDefinition>> {
    let mut fields = Vec::new();
    let field_count = load_field_count(cursor)?;
    for _ in 0..field_count {
        fields.push(load_field_def(cursor)?);
    }
    Ok(fields)
}

fn load_field_def(cursor: &mut VersionedCursor) -> BinaryLoaderResult<FieldDefinition> {
    let name = load_identifier_index(cursor)?;
    let signature = load_signature_token(cursor)?;
    Ok(FieldDefinition {
        name,
        signature: TypeSignature(signature),
    })
}

/// Builds the `FunctionDefinition` table.
fn load_function_defs(
    binary: &VersionedBinary,
    table: &Table,
    func_defs: &mut Vec<FunctionDefinition>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    while cursor.position() < u64::from(table.count) {
        let func_def = load_function_def(&mut cursor)?;
        func_defs.push(func_def);
    }
    Ok(())
}

fn load_field_handles(
    binary: &VersionedBinary,
    table: &Table,
    field_handles: &mut Vec<FieldHandle>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    loop {
        if cursor.position() == u64::from(table.count) {
            break;
        }
        let struct_idx = load_struct_def_index(&mut cursor)?;
        let offset = load_field_offset(&mut cursor)?;
        field_handles.push(FieldHandle {
            owner: struct_idx,
            field: offset,
        });
    }
    Ok(())
}

fn load_field_instantiations(
    binary: &VersionedBinary,
    table: &Table,
    field_insts: &mut Vec<FieldInstantiation>,
) -> BinaryLoaderResult<()> {
    let start = table.offset as usize;
    let end = start + table.count as usize;
    let mut cursor = binary.new_cursor(start, end);
    loop {
        if cursor.position() == u64::from(table.count) {
            break;
        }
        let handle = load_field_handle_index(&mut cursor)?;
        let type_parameters = load_signature_index(&mut cursor)?;
        field_insts.push(FieldInstantiation {
            handle,
            type_parameters,
        });
    }
    Ok(())
}

/// Deserializes a `FunctionDefinition`.
fn load_function_def(cursor: &mut VersionedCursor) -> BinaryLoaderResult<FunctionDefinition> {
    let function = load_function_handle_index(cursor)?;

    let mut flags = cursor.read_u8().map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED).with_message("Unexpected EOF".to_string())
    })?;

    let (visibility, mut extra_flags) = match cursor.version() {
        VERSION_1 => {
            let is_public_bit = Visibility::Public as u8;
            let vis = if (flags & is_public_bit) != 0 {
                flags ^= is_public_bit;
                Visibility::Public
            } else {
                Visibility::Private
            };
            (vis, flags)
        }
        VERSION_2 | VERSION_3 => {
            // NOTE: changes compared with VERSION_1
            // - in VERSION_1: the flags is a byte compositing both the visibility info and whether
            //                 the function is a native function
            // - in VERSION_2: the flags only represent the visibility info and we need to advance
            //                 the cursor to read up the next byte as flags
            let vis = flags.try_into().map_err(|_| {
                PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Invalid visibility byte".to_string())
            })?;
            let extra_flags = cursor.read_u8().map_err(|_| {
                PartialVMError::new(StatusCode::MALFORMED)
                    .with_message("Unexpected EOF".to_string())
            })?;
            (vis, extra_flags)
        }
        _ => {
            return Err(PartialVMError::new(StatusCode::UNREACHABLE)
                .with_message(String::from("Invalid bytecode version")))
        }
    };

    let acquires_global_resources = load_struct_definition_indices(cursor)?;
    let code_unit = if (extra_flags & FunctionDefinition::NATIVE) != 0 {
        extra_flags ^= FunctionDefinition::NATIVE;
        None
    } else {
        Some(load_code_unit(cursor)?)
    };

    // check that the bits unused in the flags are not set, otherwise it might cause some trouble
    // if later we decide to assign meaning to these bits.
    if extra_flags != 0 {
        return Err(PartialVMError::new(StatusCode::INVALID_FLAG_BITS));
    }

    Ok(FunctionDefinition {
        function,
        visibility,
        acquires_global_resources,
        code: code_unit,
    })
}

/// Deserializes a `Vec<StructDefinitionIndex>`.
fn load_struct_definition_indices(
    cursor: &mut VersionedCursor,
) -> BinaryLoaderResult<Vec<StructDefinitionIndex>> {
    let len = load_acquires_count(cursor)?;
    let mut indices = vec![];
    for _ in 0..len {
        indices.push(load_struct_def_index(cursor)?);
    }
    Ok(indices)
}

/// Deserializes a `CodeUnit`.
fn load_code_unit(cursor: &mut VersionedCursor) -> BinaryLoaderResult<CodeUnit> {
    let locals = load_signature_index(cursor)?;

    let mut code_unit = CodeUnit {
        locals,
        code: vec![],
    };

    load_code(cursor, &mut code_unit.code)?;
    Ok(code_unit)
}

/// Deserializes a code stream (`Bytecode`s).
fn load_code(cursor: &mut VersionedCursor, code: &mut Vec<Bytecode>) -> BinaryLoaderResult<()> {
    let bytecode_count = load_bytecode_count(cursor)?;

    while code.len() < bytecode_count {
        let byte = cursor.read_u8().map_err(|_| {
            PartialVMError::new(StatusCode::MALFORMED).with_message("Unexpected EOF".to_string())
        })?;
        let bytecode = match Opcodes::from_u8(byte)? {
            Opcodes::POP => Bytecode::Pop,
            Opcodes::RET => Bytecode::Ret,
            Opcodes::BR_TRUE => Bytecode::BrTrue(load_bytecode_index(cursor)?),
            Opcodes::BR_FALSE => Bytecode::BrFalse(load_bytecode_index(cursor)?),
            Opcodes::BRANCH => Bytecode::Branch(load_bytecode_index(cursor)?),
            Opcodes::LD_U8 => {
                let value = cursor.read_u8().map_err(|_| {
                    PartialVMError::new(StatusCode::MALFORMED)
                        .with_message("Unexpected EOF".to_string())
                })?;
                Bytecode::LdU8(value)
            }
            Opcodes::LD_U64 => {
                let value = read_u64_internal(cursor)?;
                Bytecode::LdU64(value)
            }
            Opcodes::LD_U128 => {
                let value = read_u128_internal(cursor)?;
                Bytecode::LdU128(value)
            }
            Opcodes::CAST_U8 => Bytecode::CastU8,
            Opcodes::CAST_U64 => Bytecode::CastU64,
            Opcodes::CAST_U128 => Bytecode::CastU128,
            Opcodes::LD_CONST => Bytecode::LdConst(load_constant_pool_index(cursor)?),
            Opcodes::LD_TRUE => Bytecode::LdTrue,
            Opcodes::LD_FALSE => Bytecode::LdFalse,
            Opcodes::COPY_LOC => Bytecode::CopyLoc(load_local_index(cursor)?),
            Opcodes::MOVE_LOC => Bytecode::MoveLoc(load_local_index(cursor)?),
            Opcodes::ST_LOC => Bytecode::StLoc(load_local_index(cursor)?),
            Opcodes::MUT_BORROW_LOC => Bytecode::MutBorrowLoc(load_local_index(cursor)?),
            Opcodes::IMM_BORROW_LOC => Bytecode::ImmBorrowLoc(load_local_index(cursor)?),
            Opcodes::MUT_BORROW_FIELD => Bytecode::MutBorrowField(load_field_handle_index(cursor)?),
            Opcodes::MUT_BORROW_FIELD_GENERIC => {
                Bytecode::MutBorrowFieldGeneric(load_field_inst_index(cursor)?)
            }
            Opcodes::IMM_BORROW_FIELD => Bytecode::ImmBorrowField(load_field_handle_index(cursor)?),
            Opcodes::IMM_BORROW_FIELD_GENERIC => {
                Bytecode::ImmBorrowFieldGeneric(load_field_inst_index(cursor)?)
            }
            Opcodes::CALL => Bytecode::Call(load_function_handle_index(cursor)?),
            Opcodes::CALL_GENERIC => Bytecode::CallGeneric(load_function_inst_index(cursor)?),
            Opcodes::PACK => Bytecode::Pack(load_struct_def_index(cursor)?),
            Opcodes::PACK_GENERIC => Bytecode::PackGeneric(load_struct_def_inst_index(cursor)?),
            Opcodes::UNPACK => Bytecode::Unpack(load_struct_def_index(cursor)?),
            Opcodes::UNPACK_GENERIC => Bytecode::UnpackGeneric(load_struct_def_inst_index(cursor)?),
            Opcodes::READ_REF => Bytecode::ReadRef,
            Opcodes::WRITE_REF => Bytecode::WriteRef,
            Opcodes::ADD => Bytecode::Add,
            Opcodes::SUB => Bytecode::Sub,
            Opcodes::MUL => Bytecode::Mul,
            Opcodes::MOD => Bytecode::Mod,
            Opcodes::DIV => Bytecode::Div,
            Opcodes::BIT_OR => Bytecode::BitOr,
            Opcodes::BIT_AND => Bytecode::BitAnd,
            Opcodes::XOR => Bytecode::Xor,
            Opcodes::SHL => Bytecode::Shl,
            Opcodes::SHR => Bytecode::Shr,
            Opcodes::OR => Bytecode::Or,
            Opcodes::AND => Bytecode::And,
            Opcodes::NOT => Bytecode::Not,
            Opcodes::EQ => Bytecode::Eq,
            Opcodes::NEQ => Bytecode::Neq,
            Opcodes::LT => Bytecode::Lt,
            Opcodes::GT => Bytecode::Gt,
            Opcodes::LE => Bytecode::Le,
            Opcodes::GE => Bytecode::Ge,
            Opcodes::ABORT => Bytecode::Abort,
            Opcodes::NOP => Bytecode::Nop,
            Opcodes::EXISTS => Bytecode::Exists(load_struct_def_index(cursor)?),
            Opcodes::EXISTS_GENERIC => Bytecode::ExistsGeneric(load_struct_def_inst_index(cursor)?),
            Opcodes::MUT_BORROW_GLOBAL => Bytecode::MutBorrowGlobal(load_struct_def_index(cursor)?),
            Opcodes::MUT_BORROW_GLOBAL_GENERIC => {
                Bytecode::MutBorrowGlobalGeneric(load_struct_def_inst_index(cursor)?)
            }
            Opcodes::IMM_BORROW_GLOBAL => Bytecode::ImmBorrowGlobal(load_struct_def_index(cursor)?),
            Opcodes::IMM_BORROW_GLOBAL_GENERIC => {
                Bytecode::ImmBorrowGlobalGeneric(load_struct_def_inst_index(cursor)?)
            }
            Opcodes::MOVE_FROM => Bytecode::MoveFrom(load_struct_def_index(cursor)?),
            Opcodes::MOVE_FROM_GENERIC => {
                Bytecode::MoveFromGeneric(load_struct_def_inst_index(cursor)?)
            }
            Opcodes::MOVE_TO => Bytecode::MoveTo(load_struct_def_index(cursor)?),
            Opcodes::MOVE_TO_GENERIC => {
                Bytecode::MoveToGeneric(load_struct_def_inst_index(cursor)?)
            }
            Opcodes::FREEZE_REF => Bytecode::FreezeRef,
        };
        code.push(bytecode);
    }
    Ok(())
}

impl TableType {
    fn from_u8(value: u8) -> BinaryLoaderResult<TableType> {
        match value {
            0x1 => Ok(TableType::MODULE_HANDLES),
            0x2 => Ok(TableType::STRUCT_HANDLES),
            0x3 => Ok(TableType::FUNCTION_HANDLES),
            0x4 => Ok(TableType::FUNCTION_INST),
            0x5 => Ok(TableType::SIGNATURES),
            0x6 => Ok(TableType::CONSTANT_POOL),
            0x7 => Ok(TableType::IDENTIFIERS),
            0x8 => Ok(TableType::ADDRESS_IDENTIFIERS),
            0xA => Ok(TableType::STRUCT_DEFS),
            0xB => Ok(TableType::STRUCT_DEF_INST),
            0xC => Ok(TableType::FUNCTION_DEFS),
            0xD => Ok(TableType::FIELD_HANDLE),
            0xE => Ok(TableType::FIELD_INST),
            0xF => Ok(TableType::FRIEND_DECLS),
            _ => Err(PartialVMError::new(StatusCode::UNKNOWN_TABLE_TYPE)),
        }
    }
}

impl SerializedType {
    fn from_u8(value: u8) -> BinaryLoaderResult<SerializedType> {
        match value {
            0x1 => Ok(SerializedType::BOOL),
            0x2 => Ok(SerializedType::U8),
            0x3 => Ok(SerializedType::U64),
            0x4 => Ok(SerializedType::U128),
            0x5 => Ok(SerializedType::ADDRESS),
            0x6 => Ok(SerializedType::REFERENCE),
            0x7 => Ok(SerializedType::MUTABLE_REFERENCE),
            0x8 => Ok(SerializedType::STRUCT),
            0x9 => Ok(SerializedType::TYPE_PARAMETER),
            0xA => Ok(SerializedType::VECTOR),
            0xB => Ok(SerializedType::STRUCT_INST),
            0xC => Ok(SerializedType::SIGNER),
            _ => Err(PartialVMError::new(StatusCode::UNKNOWN_SERIALIZED_TYPE)),
        }
    }
}

#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum DeprecatedNominalResourceFlag {
    NOMINAL_RESOURCE        = 0x1,
    NORMAL_STRUCT           = 0x2,
}

impl DeprecatedNominalResourceFlag {
    fn from_u8(value: u8) -> BinaryLoaderResult<DeprecatedNominalResourceFlag> {
        match value {
            0x1 => Ok(DeprecatedNominalResourceFlag::NOMINAL_RESOURCE),
            0x2 => Ok(DeprecatedNominalResourceFlag::NORMAL_STRUCT),
            _ => Err(PartialVMError::new(StatusCode::UNKNOWN_ABILITY)),
        }
    }
}
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
enum DeprecatedKind {
    ALL                     = 0x1,
    COPYABLE                = 0x2,
    RESOURCE                = 0x3,
}

impl DeprecatedKind {
    fn from_u8(value: u8) -> BinaryLoaderResult<DeprecatedKind> {
        match value {
            0x1 => Ok(DeprecatedKind::ALL),
            0x2 => Ok(DeprecatedKind::COPYABLE),
            0x3 => Ok(DeprecatedKind::RESOURCE),
            _ => Err(PartialVMError::new(StatusCode::UNKNOWN_ABILITY)),
        }
    }
}

impl SerializedNativeStructFlag {
    fn from_u8(value: u8) -> BinaryLoaderResult<SerializedNativeStructFlag> {
        match value {
            0x1 => Ok(SerializedNativeStructFlag::NATIVE),
            0x2 => Ok(SerializedNativeStructFlag::DECLARED),
            _ => Err(PartialVMError::new(StatusCode::UNKNOWN_NATIVE_STRUCT_FLAG)),
        }
    }
}

impl Opcodes {
    fn from_u8(value: u8) -> BinaryLoaderResult<Opcodes> {
        match value {
            0x01 => Ok(Opcodes::POP),
            0x02 => Ok(Opcodes::RET),
            0x03 => Ok(Opcodes::BR_TRUE),
            0x04 => Ok(Opcodes::BR_FALSE),
            0x05 => Ok(Opcodes::BRANCH),
            0x06 => Ok(Opcodes::LD_U64),
            0x07 => Ok(Opcodes::LD_CONST),
            0x08 => Ok(Opcodes::LD_TRUE),
            0x09 => Ok(Opcodes::LD_FALSE),
            0x0A => Ok(Opcodes::COPY_LOC),
            0x0B => Ok(Opcodes::MOVE_LOC),
            0x0C => Ok(Opcodes::ST_LOC),
            0x0D => Ok(Opcodes::MUT_BORROW_LOC),
            0x0E => Ok(Opcodes::IMM_BORROW_LOC),
            0x0F => Ok(Opcodes::MUT_BORROW_FIELD),
            0x10 => Ok(Opcodes::IMM_BORROW_FIELD),
            0x11 => Ok(Opcodes::CALL),
            0x12 => Ok(Opcodes::PACK),
            0x13 => Ok(Opcodes::UNPACK),
            0x14 => Ok(Opcodes::READ_REF),
            0x15 => Ok(Opcodes::WRITE_REF),
            0x16 => Ok(Opcodes::ADD),
            0x17 => Ok(Opcodes::SUB),
            0x18 => Ok(Opcodes::MUL),
            0x19 => Ok(Opcodes::MOD),
            0x1A => Ok(Opcodes::DIV),
            0x1B => Ok(Opcodes::BIT_OR),
            0x1C => Ok(Opcodes::BIT_AND),
            0x1D => Ok(Opcodes::XOR),
            0x1E => Ok(Opcodes::OR),
            0x1F => Ok(Opcodes::AND),
            0x20 => Ok(Opcodes::NOT),
            0x21 => Ok(Opcodes::EQ),
            0x22 => Ok(Opcodes::NEQ),
            0x23 => Ok(Opcodes::LT),
            0x24 => Ok(Opcodes::GT),
            0x25 => Ok(Opcodes::LE),
            0x26 => Ok(Opcodes::GE),
            0x27 => Ok(Opcodes::ABORT),
            0x28 => Ok(Opcodes::NOP),
            0x29 => Ok(Opcodes::EXISTS),
            0x2A => Ok(Opcodes::MUT_BORROW_GLOBAL),
            0x2B => Ok(Opcodes::IMM_BORROW_GLOBAL),
            0x2C => Ok(Opcodes::MOVE_FROM),
            0x2D => Ok(Opcodes::MOVE_TO),
            0x2E => Ok(Opcodes::FREEZE_REF),
            0x2F => Ok(Opcodes::SHL),
            0x30 => Ok(Opcodes::SHR),
            0x31 => Ok(Opcodes::LD_U8),
            0x32 => Ok(Opcodes::LD_U128),
            0x33 => Ok(Opcodes::CAST_U8),
            0x34 => Ok(Opcodes::CAST_U64),
            0x35 => Ok(Opcodes::CAST_U128),
            0x36 => Ok(Opcodes::MUT_BORROW_FIELD_GENERIC),
            0x37 => Ok(Opcodes::IMM_BORROW_FIELD_GENERIC),
            0x38 => Ok(Opcodes::CALL_GENERIC),
            0x39 => Ok(Opcodes::PACK_GENERIC),
            0x3A => Ok(Opcodes::UNPACK_GENERIC),
            0x3B => Ok(Opcodes::EXISTS_GENERIC),
            0x3C => Ok(Opcodes::MUT_BORROW_GLOBAL_GENERIC),
            0x3D => Ok(Opcodes::IMM_BORROW_GLOBAL_GENERIC),
            0x3E => Ok(Opcodes::MOVE_FROM_GENERIC),
            0x3F => Ok(Opcodes::MOVE_TO_GENERIC),
            _ => Err(PartialVMError::new(StatusCode::UNKNOWN_OPCODE)),
        }
    }
}
