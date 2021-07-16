---
id: move-standard-library
title: Standard Library
sidebar_label: Standard Library
---

The Move standard library exposes interfaces that implement the following functionality:
* [Basic operations on vectors](#vector).
* [Option types and operations on`Option` types](#option).
* [A common error encoding code interface for abort codes](#errors).
* [32-bit precision fixed-point numbers](#fixedpoint32).

## <a href="vector">Vector</a>

The `Vector` module defines a number of operations over the primitive
[`vector`](./vector.md) type. The module is published under the
core code address at `0x1` and consists of a number of native functions, as
well as functions defined in Move. The API for this module is as follows.

### Functions

---------------------------------------------------------------------------

Create an empty [`vector`](./vector.md).
The `Element` type can be both a `resource` or `copyable` type.
```rust
    native public fun empty<Element>(): vector<Element>;
```
---------------------------------------------------------------------------

Create a vector of length `1` containing the passed in `element`.
```rust
    public fun singleton<Element>(e: Element): vector<Element>;
```
---------------------------------------------------------------------------

Destroy (deallocate) the vector `v`. Will abort if `v` is non-empty.
*Note*: The emptiness restriction is due to the fact that `Element` can be a
resource type, and destruction of a non-empty vector would violate
[resource conservation](./structs-and-resources.md).
```rust
    native public fun destroy_empty<Element>(v: vector<Element>);
```
---------------------------------------------------------------------------

Acquire an [immutable reference](./references.md) to the `i`th element of the vector `v`.  Will abort if
the index `i` is out of bounds for the vector `v`.
```rust
    native public fun borrow<Element>(v: &vector<Element>, i: u64): &Element;
```
---------------------------------------------------------------------------

Acquire a [mutable reference](./references.md)
to the `i`th element of the vector `v`.  Will abort if
the index `i` is out of bounds for the vector `v`.
```rust
    native public fun borrow_mut<Element>(v: &mut vector<Element>, i: u64): &mut Element;
```
---------------------------------------------------------------------------

Empty and destroy the `other` vector, and push each of the elements in
the `other` vector onto the `lhs` vector in the same order as they occurred in `other`.
```rust
    public fun append<Element>(lhs: &mut vector<Element>, other: vector<Element>);
```
---------------------------------------------------------------------------

Push an element `e` of type `Element` onto the end of the vector `v`. May
trigger a resizing of the underlying vector's memory.
```rust
    native public fun push_back<Element>(v: &mut vector<Element>, e: Element);
```
---------------------------------------------------------------------------

Pop an element from the end of the vector `v` in-place and return the owned
value. Will abort if `v` is empty.
```rust
    native public fun pop_back<Element>(v: &mut vector<Element>): Element;
```
---------------------------------------------------------------------------

Remove the element at index `i` in the vector `v` and return the owned value
that was previously stored at `i` in `v`. All elements occurring at indices
greater than `i` will be shifted down by 1. Will abort if `i` is out of bounds
for `v`.
```rust
    public fun remove<Element>(v: &mut vector<Element>, i: u64): Element;
```
---------------------------------------------------------------------------

Swap the `i`th element of the vector `v` with the last element and then pop
this element off of the back of the vector and return the owned value that
was previously stored at index `i`.
This operation is O(1), but does not preserve ordering of elements in the vector.
Aborts if the index `i` is out of bounds for the vector `v`.
```rust
    public fun swap_remove<Element>(v: &mut vector<Element>, i: u64): Element;
```
---------------------------------------------------------------------------

Swap the elements at the `i`'th and `j`'th indices in the vector `v`. Will
abort if either of `i` or `j` are out of bounds for `v`.
```rust
    native public fun swap<Element>(v: &mut vector<Element>, i: u64, j: u64);
```
---------------------------------------------------------------------------

Reverse the order of the elements in the vector `v` in-place.
```rust
    public fun reverse<Element>(v: &mut vector<Element>);
```
---------------------------------------------------------------------------

Return the index of the first occurrence of an element in `v` that is
equal to `e`. Returns `(true, index)` if such an element was found, and
`(false, 0)` otherwise.
```rust
    public fun index_of<Element>(v: &vector<Element>, e: &Element): (bool, u64);
```
---------------------------------------------------------------------------

Return if an element equal to `e` exists in the vector `v`.
```rust
    public fun contains<Element>(v: &vector<Element>, e: &Element): bool;
```
---------------------------------------------------------------------------

Return the length of a `vector`.
```rust
    native public fun length<Element>(v: &vector<Element>): u64;
```
---------------------------------------------------------------------------

Return whether the vector `v` is empty.
```rust
    public fun is_empty<Element>(v: &vector<Element>): bool;
```
---------------------------------------------------------------------------

## <a href="option">Option</a>

The `Option` module defines a generic option type `Option<T>` that represents a
value of type `T` that may, or may not, be present. It is published under the core code address at `0x1`.

The Move option type is internally represented as a singleton vector, and may
contain a value of `resource` or `copyable` kind.  If you are familiar with option
types in other languages, the Move `Option` behaves similarly to those with a
couple notable exceptions since the option can contain a value of kind `resource`.
Particularly, certain operations such as `get_with_default` and
`destroy_with_default` require that the element type `T` be of `copyable` kind.

The API for the `Option` module is as as follows

### Types

Generic type abstraction of a value that may, or may not, be present. Can contain
a value of either `resource` or `copyable` kind.
```rust
    struct Option<T>;
```

### Functions

Create an empty `Option` of that can contain a value of `Element` type.
```rust
    public fun none<Element>(): Option<Element>;
```
---------------------------------------------------------------------------

Create a non-empty `Option` type containing a value `e` of type `Element`.
```rust
    public fun some<Element>(e: T): Option<Element>;
```
---------------------------------------------------------------------------

Return an immutable reference to the value inside the option `opt_elem`
Will abort if `opt_elem` does not contain a value.
```rust
    public fun borrow<Element>(opt_elem: &Option<Element>): &Element;
```
---------------------------------------------------------------------------

Return a reference to the value inside `opt_elem` if it contains one. If
`opt_elem` does not contain a value the passed in `default_ref` reference will be returned.
Does not abort.
```rust
    public fun borrow_with_default<Element>(opt_elem: &Option<Element>, default_ref: &Element): &Element;
```
---------------------------------------------------------------------------

Return a mutable reference to the value inside `opt_elem`. Will abort if
`opt_elem` does not contain a value.
```rust
    public fun borrow_mut<Element>(opt_elem: &mut Option<Element>): &mut Element;
```
---------------------------------------------------------------------------

Convert an option value that contains a value to one that is empty in-place by
removing and returning the value stored inside `opt_elem`.
Will abort if `opt_elem` does not contain a value.
```rust
    public fun extract<Element>(opt_elem: &mut Option<Element>): Element;
```
---------------------------------------------------------------------------

Return the value contained inside the option `opt_elem` if it contains one.
Will return the passed in `default` value if `opt_elem` does not contain a
value. The `Element` type that the `Option` type is instantiated with must be
of `copyable` kind in order for this function to be callable.
```rust
    public fun get_with_default<Element: copyable>(opt_elem: &Option<Element>, default: Element): Element;
```
---------------------------------------------------------------------------

Convert an empty option `opt_elem` to an option value that contains the value `e`.
Will abort if `opt_elem` already contains a value.
```rust
    public fun fill<Element>(opt_elem: &mut Option<Element>, e: Element);
```
---------------------------------------------------------------------------

Swap the value currently contained in `opt_elem` with `new_elem` and return the
previously contained value. Will abort if `opt_elem` does not contain a value.
```rust
    public fun swap<Element>(opt_elem: &mut Option<Element>, e: Element): Element;
```
---------------------------------------------------------------------------

Return true if `opt_elem` contains a value equal to the value of `e_ref`.
Otherwise, `false` will be returned.
```rust
    public fun contains<Element>(opt_elem: &Option<Element>, e_ref: &Element): bool;
```
---------------------------------------------------------------------------

Return `true` if `opt_elem` does not contain a value.
```rust
    public fun is_none<Element>(opt_elem: &Option<Element>): bool;
```
---------------------------------------------------------------------------

Return `true` if `opt_elem` contains a value.
```rust
    public fun is_some<Element>(opt_elem: &Option<Element>): bool;
```

---------------------------------------------------------------------------

Unpack `opt_elem` and return the value that it contained.
Will abort if `opt_elem` does not contain a value.
```rust
    public fun destroy_some<Element>(opt_elem: Option<Element>): Element;
```
---------------------------------------------------------------------------

Destroys the `opt_elem` value passed in. If `opt_elem` contained a value it
will be returned otherwise, the passed in `default` value will be returned.
```rust
    public fun destroy_with_default<Element: copyable>(opt_elem: Option<Element>, default: Element): Element;
```
---------------------------------------------------------------------------

Destroys the `opt_elem` value passed in, `opt_elem` must be empty and not
contain a value. Will abort if `opt_elem` contains a value.
```rust
    public fun destroy_none<Element>(opt_elem: Option<Element>);
```

## Errors

Recall that each abort code in Move is represented as an unsigned 64-bit integer. The `Errors` module defines a common interface that can be used to "tag" each of these abort codes so that they can represent both the error **category** along with an error **reason**.

Error categories are declared as constants in the `Errors` module and are globally unique with respect to this module. Error reasons on the other hand are module-specific error codes, and can provide greater detail (perhaps, even a particular _reason_) about the specific error condition. This representation of a category and reason for each error code is done by dividing the abort code into two sections.

The lower 8 bits of the abort code hold the *error category*. The remaining 56 bits of the abort code hold the *error reason*.
The reason should be a unique number relative to the module which raised the error and can be used to obtain more information about the error at hand. It should mostly be used for diagnostic purposes as error reasons may change over time if the module is updated.

![Error bits](/img/docs/standard-library-error-bits.png)

Since error categories are globally stable, these present the most stable API and should in general be what is used by clients to determine the messages they may present to users (whereas the reason is useful for diagnostic purposes). There are public functions in the `Errors` module for creating an abort code of each error category with a specific `reason` number (represented as a `u64`).

### Constants


The system is in a state where the performed operation is not allowed.
```rust
    const INVALID_STATE: u8 = 1;
```

---------------------------------------------------------------------------
A specific account address was required to perform an operation, but a different address from what was expected was encounterd.
```rust
    const REQUIRES_ADDRESS: u8 = 2;
```

---------------------------------------------------------------------------
An account did not have the expected  role for this operation. Useful for Role Based Access Control (RBAC) error conditions.
```rust
    const REQUIRES_ROLE: u8 = 3;
```

---------------------------------------------------------------------------
An account did not not have a required capability. Useful for RBAC error conditions.
```rust
    const REQUIRES_CAPABILITY: u8 = 4;
```

---------------------------------------------------------------------------
A resource was expected, but did not exist under an address.
```rust
    const NOT_PUBLISHED: u8 = 5;
```

---------------------------------------------------------------------------
Attempted to publish a resource under an address where one was already published.
```rust
    const ALREADY_PUBLISHED: u8 = 6;
```

---------------------------------------------------------------------------
An argument provided for an operation was invalid.
```rust
    const INVALID_ARGUMENT: u8 = 7;
```

---------------------------------------------------------------------------
A limit on a value was exceeded.
```rust
    const LIMIT_EXCEEDED: u8 = 8;
```

---------------------------------------------------------------------------
An internal error (bug) has occurred.
```rust
    const INTERNAL: u8 = 10;
```

---------------------------------------------------------------------------
A custom error category for extension points.
```rust
    const CUSTOM: u8 = 255;
```
---------------------------------------------------------------------------

### Functions

 Should be used in the case where invalid (global) state is encountered. Constructs an abort code with specified `reason` and category `INVALID_STATE`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun invalid_state(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if an account's address does not match a specific address. Constructs an abort code with specified `reason` and category `REQUIRES_ADDRESS`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun requires_address(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if a role did not match a required role when using RBAC. Constructs an abort code with specified `reason` and category `REQUIRES_ROLE`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun requires_role(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if an account did not have a required capability when using RBAC. Constructs an abort code with specified `reason` and category `REQUIRES_CAPABILITY`. Should be Will abort if `reason` does not fit in 56 bits.
```rust
    public fun requires_capability(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if a resource did not exist where one was expected. Constructs an abort code with specified `reason` and category `NOT_PUBLISHED`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun not_published(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if a resource already existed where one was about to be published. Constructs an abort code with specified `reason` and category `ALREADY_PUBLISHED`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun already_published(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if an invalid argument was passed to a function/operation. Constructs an abort code with specified `reason` and category `INVALID_ARGUMENT`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun invalid_argument(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if a limit on a specific value is reached, e.g., subtracting 1 from a value of 0. Constructs an abort code with specified `reason` and category `LIMIT_EXCEEDED`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun limit_exceeded(reason: u64): u64;
```

---------------------------------------------------------------------------
Should be used if an internal error or bug was encountered. Constructs an abort code with specified `reason` and category `INTERNAL`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun internal(reason: u64): u64;
```

---------------------------------------------------------------------------
Used for extension points, should be not used under most circumstances. Constructs an abort code with specified `reason` and category `CUSTOM`. Will abort if `reason` does not fit in 56 bits.
```rust
    public fun custom(reason: u64): u64;
```

---------------------------------------------------------------------------

## <a href="fixedpoint32">FixedPoint32</a>


The `FixedPoint32` module defines a fixed-point numeric type with 32 integer bits and 32 fractional bits. Internally, this is represented as a `u64` integer wrapped in a struct to make a unique `FixedPoint32` type. Since the numeric representation is a binary one, some decimal values may not be exactly representable, but it provides more than 9 decimal digits of precision both before and after the decimal point (18 digits total). For comparison, double precision floating-point has less than 16 decimal digits of precision, so you should be careful about using floating-point to convert these values to decimal.

### Types


Represents a fixed-point numeric number with 32 fractional bits.
```rust
    struct FixedPoint32;
```

### Functions

Multiply a u64 integer by a fixed-point number, truncating any fractional part of the product. This will abort if the product overflows.
```rust
    public fun multiply_u64(val: u64, multiplier: FixedPoint32): u64;
```

---------------------------------------------------------------------------
Divide a u64 integer by a fixed-point number, truncating any fractional part of the quotient. This will abort if the divisor is zero or if the quotient overflows.
```rust
    public fun divide_u64(val: u64, divisor: FixedPoint32): u64;
```

---------------------------------------------------------------------------
Create a fixed-point value from a rational number specified by its numerator and denominator. Calling this function should be preferred for using `FixedPoint32::create_from_raw_value` which is also available. This will abort if the denominator is zero. It will also abort if the numerator is nonzero and the ratio is not in the range $2^{-32}\ldots2^{32}-1$. When specifying decimal fractions, be careful about rounding errors: if you round to display $N$ digits after the decimal point, you can use a denominator of $10^N$ to avoid numbers where the very small imprecision in the binary representation could change the rounding, e.g., 0.0125 will round down to 0.012 instead of up to 0.013.
```rust
    public fun create_from_rational(numerator: u64, denominator: u64): FixedPoint32;
```

---------------------------------------------------------------------------
Create a fixedpoint value from a raw `u64` value.
```rust
    public fun create_from_raw_value(value: u64): FixedPoint32;
```

---------------------------------------------------------------------------
Returns `true` if the decimal value of `num` is equal to zero.
```rust
    public fun is_zero(num: FixedPoint32): bool;
```

---------------------------------------------------------------------------
Accessor for the raw `u64` value. Other less common operations, such as adding or subtracting `FixedPoint32` values, can be done using the raw values directly.
```rust
    public fun get_raw_value(num: FixedPoint32): u64;
```
---------------------------------------------------------------------------
