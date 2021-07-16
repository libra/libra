---
id: move-vector
title: Vector
sidebar_label: Vector
---

`vector<T>` is the only primitive collection type provided by Move. A `vector<T>` is a homogenous collection of `T`'s that can grow or shrink by pushing/popping values off the "end".

A `vector<T>` can be instantiated with any type `T`, including resource types and other vectors. For example, `vector<u64>`, `vector<address>`, `vector<0x42::MyModule::MyResource>`, and `vector<vector<u8>>` are all valid vector types.

## Operations

`vector` supports the following operations via the `0x1::Vector` module in the Move standard library:

| Function | Description | Aborts?
| ---------- | ----------|----------
| `Vector::empty<T>(): vector<T>` | Create an empty vector that can store values of type `T` | Never
| `Vector::singleton<T>(t: T): vector<T>` | Create a vector of size 1 containing `t` | Never
| `Vector::push_back<T>(v: &mut T, t: T)` | Add `t` to the end of `v` | Never
| `Vector::pop_back<T>(v: &mut T): T` | Remove and return the last element in `v` | If `v` is empty
| `Vector::borrow<T>(v: &vector<T>, i: u64): &T` | Return an immutable reference to the `T` at index `i` | If `i` is not in bounds
| `Vector::borrow_mut<T>(v: &mut vector<T>, i: u64): &mut T` | Return an mutable reference to the `T` at index `i` | If `i` is not in bounds
| `Vector::destroy_empty<T>(v: vector<T>)` | Delete `v` | If `v` is not empty
| `Vector::append<T>(v1: &mut vector<T>, v2: vector<T>)` | Add the elements in `v2` to the end of `v1` | If `i` is not in bounds

More operations may be added overtime

## Example

```rust
use 0x1::Vector;

let v = Vector::empty<u64>();
Vector::push_back(&mut v, 5);
Vector::push_back(&mut v, 6);

assert(*Vector::borrow(&v, 0) == 5, 42);
assert(*Vector::borrow(&v, 1) == 6, 42);
assert(Vector::pop_back(&mut v) == 6, 42);
assert(Vector::pop_back(&mut v) == 5, 42);
```

## Destroying and copying `vector`s

Some behaviors of `vector<T>` depend on whether `T` is a resource type. For example, vectors containing resources cannot be implictly discarded like `v` in the example above--they must be explicitly destroyed with `Vector::destroy_empty`.

Note that `Vector::destroy_empty` will abort at runtime unless `vec` contains zero elements.

```rust
fun destroy_resource_vector<T: resource>(vec: vector<T>) {
    Vector::destroy_empty(vec) // deleting this line will cause a compiler error
}
```
This error would also happen for an unconstrained `T` as the type *might* be a resource.
```rust
fun destroy_vector<T>(vec: vector<T>) {
    Vector::destroy_empty(vec) // deleting this line will cause a compiler error
}
```
But no error would occur for dropping a vector that contains `copyable` elements
```rust
fun destroy_copyable_vector<T: copyable>(vec: vector<T>) {
    // valid!
    // nothing needs to be done explicitly to destroy the vector
}
```

Similarly, resource vectors cannot be copied. A `vector<T>` is copyable if and only if `T` is copyable. However, even copyable vectors are never implicitly copied:

```rust
let x = Vector::singleton<u64>(10);
let y = copy x; // compiler error without the copy!
```

Copies of large vectors can be expensive, so the compiler requires explicit `copy`'s to make it easier to see where they are happening.

## Literals

### `vector<u8>` literals

A common use-case for vectors in Move is to represent "byte arrays", which are represented with `vector<u8>`. These values are often used for cryptographic purposes, such as a public key or a hash result.

There are currently two supported types of `vector<u8>` literals, byte strings and hex strings.

#### Byte Strings

Byte strings are quoted string literals prefixed by a `b`, e.g. `b"Hello!\n"`.

These are ASCII encoded strings that allow for escape sequences. Currently, the supported escape sequences are

| Escape Sequence | Description
| -------- | --------
| `\n` | New line (or Line feed)
| `\r` | Carriage return
| `\t` | Tab
| `\\` | Backslash
| `\0` | Null
| `\"` | Quote
| `\xHH` | Hex escape, inserts the hex byte sequence `HH`

#### Hex Strings

Hex strings are quoted string literals prefixed by a `x`, e.g. `x"48656C6C6F210A"`

Each byte pair, ranging from `00` to `FF`, is interpreted as hex encoded `u8` value. So each byte pair corresponds to a single entry in the resulting `vector<u8>`

#### Examples

```rust
script {
fun byte_and_hex_strings() {
    assert(b"" == x"", 0);
    assert(b"Hello!\n" == x"48656C6C6F210A", 1);
    assert(b"\x48\x65\x6C\x6C\x6F\x21\x0A" == x"48656C6C6F210A", 2);
    assert(
        b"\"Hello\tworld!\"\n \r \\Null=\0" ==
            x"2248656C6C6F09776F726C6421220A200D205C4E756C6C3D00",
        3
    );
}
}
```

### Other `vector` literals

Currently, there is no support for general `vector<T>` literals in Move where `T` is not a `u8`. However, Move bytecode supports `vector<T>` constants for any primitive type `T`. We plan to add `vector<T>` literals to the source language that can compile to bytecode constants.
