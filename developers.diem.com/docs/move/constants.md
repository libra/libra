---
id: move-constants
title: Constants
sidebar_label: Constants
---

Constants are a way of giving a name to shared, static values inside of a `module` or `script`.

The constant's must be known at compilation. The constant's value is stored in the compiled module or script. And each time the constant is used, a new copy of that value is made.

## Declaration

Constant declarations begin with the `const` keyword, followed by a name, a type, and a value. They can exist in either a script or module
```
const <name>: <type> = <expression>;
```
For example
```rust=
script {

    const MY_ERROR_CODE: u64 = 0;

    fun main(input: u64) {
        assert(input > 0, MY_ERROR_CODE);
    }

}

address 0x42 {
module Example {

    const MY_ADDRESS: address = 0x42;

    public fun permissioned(s: &signer) {
        assert(0x1::Signer::address_of(s) == MY_ADDRESS, 0);
    }

}
}
```

## Naming

Constants must start with a capital letter `A` to `Z`. After the first letter, constant names can contain underscores `_`, letters `a` to `z`, letters `A` to `Z`, or digits `0` to `9`.
```rust
const FLAG: bool = false;
const MY_ERROR_CODE: u64 = 0;
const ADDRESS_42: address = 0x42;
```
Even though you can use letters `a` to `z` in a constant. The  [general style guidelines](/GSiO5fHXTlK7E8kBZf50IQ) are to use just uppercase letters `A` to `Z`, with underscores `_` between each word.


This naming restriction of starting with `A` to `Z` is in place to give room for future language features. It may or may not be removed later.


## Visibility

`public` constants are not currently supported. `const` values can be used only in the declaring module.


## Valid Expressions

Currently, constants are limited to the primitive types `bool`, `u8`, `u64`, `u128`, `address`, and `vector<u8>`. Future support for other `vector` values (besides the "string"-style literals) will come later.

### Values

Commonly, `const`s are assigned a simple value, or literal, of their type.
For example
```rust
const MY_BOOL: bool = false;
const MY_ADDRESS: address = 0x70DD;
const BYTES: vector<u8> = b"hello world";
const HEX_BYTES: vector<u8> = x"DEADBEEF";
```

### Complex Expressions

In addition to literals, constants can include more complex expressions, as long as the compiler is able to reduce the expression to a value at compile time.

Currently, equality operations, all boolean operations, all bitwise operations, and all arithmetic operations can be used.
```rust
const RULE: bool = true && false;
const CAP: u64 = 10 * 100 + 1;
const SHIFTY: u8 = {
  (1 << 1) * (1 << 2) * (1 << 3) * (1 << 4)
};
const HALF_MAX: u128 = 340282366920938463463374607431768211455 / 2;
const EQUAL: bool = 1 == 1;
```
If the operation would result in a runtime exception, the compiler will give an error that it is unable to generate the constant's value
```rust
const DIV_BY_ZERO: u64 = 1 / 0; // error!
const SHIFT_BY_A_LOT: u64 = 1 << 100; // error!
const NEGATIVE_U64: u64 = 0 - 1; // error!
```

Note that constants cannot currently refer to other constants. This feature, along with support for other expressions, will be added in the future.
