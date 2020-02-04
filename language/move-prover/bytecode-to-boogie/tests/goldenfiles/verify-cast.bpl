

// ** structs of module CastBad



// ** functions of module CastBad

procedure {:inline 1} CastBad_aborting_u8_cast_bad (x: Value) returns (__ret0: Value)
requires ExistsTxnSenderAccount(__m, __txn);
ensures old(!(b#Boolean(Boolean(false)))) ==> !__abort_flag;
ensures old(b#Boolean(Boolean(false))) ==> __abort_flag;

{
    // declare local variables
    var __t1: Value; // IntegerType()
    var __t2: Value; // IntegerType()
    var __tmp: Value;
    var __frame: int;
    var __saved_m: Memory;
    var debug#CastBad#aborting_u8_cast_bad#0#x#71: Value;
    var debug#CastBad#aborting_u8_cast_bad#1#__ret#182: Value;

    // initialize function execution
    assume !__abort_flag;
    __saved_m := __m;
    __frame := __local_counter;
    __local_counter := __local_counter + 3;

    // process and type check arguments
    assume IsValidU64(x);
    __m := UpdateLocal(__m, __frame + 0, x);
    assume (debug#CastBad#aborting_u8_cast_bad#0#x#71) == (x);

    // bytecode translation starts here
    call __tmp := CopyOrMoveValue(GetLocal(__m, __frame + 0));
    __m := UpdateLocal(__m, __frame + 1, __tmp);

    call __tmp := CastU8(GetLocal(__m, __frame + 1));
    if (__abort_flag) { goto Label_Abort; }
    __m := UpdateLocal(__m, __frame + 2, __tmp);

    __ret0 := GetLocal(__m, __frame + 2);
    assume (debug#CastBad#aborting_u8_cast_bad#1#__ret#182) == (__ret0);
    return;

Label_Abort:
    __abort_flag := true;
    __m := __saved_m;
    __ret0 := DefaultValue;
}

procedure CastBad_aborting_u8_cast_bad_verify (x: Value) returns (__ret0: Value)
{
    call InitVerification();
    call __ret0 := CastBad_aborting_u8_cast_bad(x);
}

procedure {:inline 1} CastBad_aborting_u8_cast_ok (x: Value) returns (__ret0: Value)
requires ExistsTxnSenderAccount(__m, __txn);
ensures old(!(b#Boolean(Boolean(i#Integer(x) > i#Integer(Integer(255)))))) ==> !__abort_flag;
ensures old(b#Boolean(Boolean(i#Integer(x) > i#Integer(Integer(255))))) ==> __abort_flag;

{
    // declare local variables
    var __t1: Value; // IntegerType()
    var __t2: Value; // IntegerType()
    var __tmp: Value;
    var __frame: int;
    var __saved_m: Memory;
    var debug#CastBad#aborting_u8_cast_ok#0#x#261: Value;
    var debug#CastBad#aborting_u8_cast_ok#1#__ret#350: Value;

    // initialize function execution
    assume !__abort_flag;
    __saved_m := __m;
    __frame := __local_counter;
    __local_counter := __local_counter + 3;

    // process and type check arguments
    assume IsValidU64(x);
    __m := UpdateLocal(__m, __frame + 0, x);
    assume (debug#CastBad#aborting_u8_cast_ok#0#x#261) == (x);

    // bytecode translation starts here
    call __tmp := CopyOrMoveValue(GetLocal(__m, __frame + 0));
    __m := UpdateLocal(__m, __frame + 1, __tmp);

    call __tmp := CastU8(GetLocal(__m, __frame + 1));
    if (__abort_flag) { goto Label_Abort; }
    __m := UpdateLocal(__m, __frame + 2, __tmp);

    __ret0 := GetLocal(__m, __frame + 2);
    assume (debug#CastBad#aborting_u8_cast_ok#1#__ret#350) == (__ret0);
    return;

Label_Abort:
    __abort_flag := true;
    __m := __saved_m;
    __ret0 := DefaultValue;
}

procedure CastBad_aborting_u8_cast_ok_verify (x: Value) returns (__ret0: Value)
{
    call InitVerification();
    call __ret0 := CastBad_aborting_u8_cast_ok(x);
}

procedure {:inline 1} CastBad_aborting_u64_cast_bad (x: Value) returns (__ret0: Value)
requires ExistsTxnSenderAccount(__m, __txn);
ensures old(!(b#Boolean(Boolean(false)))) ==> !__abort_flag;
ensures old(b#Boolean(Boolean(false))) ==> __abort_flag;

{
    // declare local variables
    var __t1: Value; // IntegerType()
    var __t2: Value; // IntegerType()
    var __tmp: Value;
    var __frame: int;
    var __saved_m: Memory;
    var debug#CastBad#aborting_u64_cast_bad#0#x#433: Value;
    var debug#CastBad#aborting_u64_cast_bad#1#__ret#547: Value;

    // initialize function execution
    assume !__abort_flag;
    __saved_m := __m;
    __frame := __local_counter;
    __local_counter := __local_counter + 3;

    // process and type check arguments
    assume IsValidU128(x);
    __m := UpdateLocal(__m, __frame + 0, x);
    assume (debug#CastBad#aborting_u64_cast_bad#0#x#433) == (x);

    // bytecode translation starts here
    call __tmp := CopyOrMoveValue(GetLocal(__m, __frame + 0));
    __m := UpdateLocal(__m, __frame + 1, __tmp);

    call __tmp := CastU64(GetLocal(__m, __frame + 1));
    if (__abort_flag) { goto Label_Abort; }
    __m := UpdateLocal(__m, __frame + 2, __tmp);

    __ret0 := GetLocal(__m, __frame + 2);
    assume (debug#CastBad#aborting_u64_cast_bad#1#__ret#547) == (__ret0);
    return;

Label_Abort:
    __abort_flag := true;
    __m := __saved_m;
    __ret0 := DefaultValue;
}

procedure CastBad_aborting_u64_cast_bad_verify (x: Value) returns (__ret0: Value)
{
    call InitVerification();
    call __ret0 := CastBad_aborting_u64_cast_bad(x);
}

procedure {:inline 1} CastBad_aborting_u64_cast_ok (x: Value) returns (__ret0: Value)
requires ExistsTxnSenderAccount(__m, __txn);
ensures old(!(b#Boolean(Boolean(i#Integer(x) > i#Integer(Integer(9223372036854775807)))))) ==> !__abort_flag;
ensures old(b#Boolean(Boolean(i#Integer(x) > i#Integer(Integer(9223372036854775807))))) ==> __abort_flag;

{
    // declare local variables
    var __t1: Value; // IntegerType()
    var __t2: Value; // IntegerType()
    var __tmp: Value;
    var __frame: int;
    var __saved_m: Memory;
    var debug#CastBad#aborting_u64_cast_ok#0#x#627: Value;
    var debug#CastBad#aborting_u64_cast_ok#1#__ret#755: Value;

    // initialize function execution
    assume !__abort_flag;
    __saved_m := __m;
    __frame := __local_counter;
    __local_counter := __local_counter + 3;

    // process and type check arguments
    assume IsValidU128(x);
    __m := UpdateLocal(__m, __frame + 0, x);
    assume (debug#CastBad#aborting_u64_cast_ok#0#x#627) == (x);

    // bytecode translation starts here
    call __tmp := CopyOrMoveValue(GetLocal(__m, __frame + 0));
    __m := UpdateLocal(__m, __frame + 1, __tmp);

    call __tmp := CastU64(GetLocal(__m, __frame + 1));
    if (__abort_flag) { goto Label_Abort; }
    __m := UpdateLocal(__m, __frame + 2, __tmp);

    __ret0 := GetLocal(__m, __frame + 2);
    assume (debug#CastBad#aborting_u64_cast_ok#1#__ret#755) == (__ret0);
    return;

Label_Abort:
    __abort_flag := true;
    __m := __saved_m;
    __ret0 := DefaultValue;
}

procedure CastBad_aborting_u64_cast_ok_verify (x: Value) returns (__ret0: Value)
{
    call InitVerification();
    call __ret0 := CastBad_aborting_u64_cast_ok(x);
}
