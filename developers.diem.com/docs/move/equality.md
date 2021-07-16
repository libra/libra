---
id: move-equality
title: Equality
sidebar_label: Equality
---

Move supports two equality operations `==` and `!=`

## Operations

| Syntax   | Operation | Description
| -------- | ----------|------------
| `==`     | equal     | Returns `true` if the two operands have the same value, `false` otherwise
| `!=`     | not equal | Returns `true` if the two operands have different values, `false` otherwise

### Typing
Both the equal (`==`) and not-equal (`!=`) operations only work if both operands are the same type
```rust
0 == 0; // `true`
1u128 == 2u128; // `false`
b"hello" != x"00"; // `true`
```
Equality and non-equality also work over user defined types!
```rust=
address 0x42 {
module Example {
    struct S { f: u64, s: vector<u8> }

    fun always_true(): bool {
        let s = S { f: 0, s: b"" };
        // parens are not needed but added for clarity in this example
        (copy s) == s
    }

    fun always_false(): bool {
        let s = S { f: 0, s: b"" };
        // parens are not needed but added for clarity in this example
        (copy s) != s
    }
}
}
```

If the operands have different types, there is a type checking error
```rust
1u8 == 1u128; // ERROR!
//     ^^^^^ expected an argument of type 'u8'
b"" != 0; // ERROR!
//     ^ expected an argument of type 'vector<u8>'
```
### Typing with references
When comparing [references](./references.md), the type of the reference does not matter. This means that you can compare an immutable `&` reference with a mutable one `&mut` of the same type.
```rust
let i = &0;
let m = &mut 1;

i == m; // `false`
m == i; // `false`
m == m; // `true`
i == i; // `true`
```
The above is equivalent to applying an explicit freeze to each mutable reference where needed
```rust
let i = &0;
let m = &mut 1;

i == freeze(m); // `false`
freeze(m) == i; // `false`
m == m; // `true`
i == i; // `true`
```
But similar to non-reference types, the underlying type must be the same type
```rust
let i = &0;
let s = &b"";

i == s; // ERROR!
//   ^ expected an argument of type '&u64'
```

## Restrictions

Both `==` and `!=` consume the value when comparing them. As a result, the type system enforces that the type must be `copyable`, that is that it is not a `resource` value. Recall that resources cannot be copied, ownership must be transferred by the end of the function, and they can only be explicitly destroyed within their declaring module. If resources were used directly with either equality `==` or non-equality `!=`, the value would be destroyed which would break resource safety!
```rust=
address 0x42 {
module Example {
    resource struct Coin { value: u64 }
    fun invalid(c1: Coin, c2: Coin) {
        c1 == c2 // ERROR!
//      ^^    ^^ These resources would be destroyed!
    }
}
}
```

But, a programmer can *always* borrow the value first--to make it a `copyable` type--instead of directly comparing the resource. For example
```rust=
address 0x42 {
module Example {
    resource struct Coin { value: u64 }
    fun swap_if_equal(c1: Coin, c2: Coin): (Coin, Coin) {
        let are_equal = &c1 == &c2; // valid
        if (are_equal) (c2, c1) else (c1, c2)
    }
}
}
```
## Avoid Extra Copies

While a programmer *can* compare any `copyable` value, a programmer should often compare by reference to avoid expensive copies.
```rust=
let v1: vector<u8> = function_that_returns_vector();
let v2: vector<u8> = function_that_returns_vector();
assert(copy v1 == copy v2, 42);
//     ^^^^       ^^^^
use_two_vectors(v1, v2);

let s1: Foo = function_that_returns_large_struct();
let s2: Foo = function_that_returns_large_struct();
assert(copy s1 == copy s2, 42);
//     ^^^^       ^^^^
use_two_foos(s1, s2);
```
This code is perfectly acceptable, just not efficient. The highlighted copies can be removed and replaced with borrows
```rust=
let v1: vector<u8> = function_that_returns_vector();
let v2: vector<u8> = function_that_returns_vector();
assert(&v1 == &v2, 42);
//     ^      ^
use_two_vectors(v1, v2);

let s1: Foo = function_that_returns_large_struct();
let s2: Foo = function_that_returns_large_struct();
assert(&s1 == &s2, 42);
//     ^      ^
use_two_foos(s1, s2);
```
The efficiency of the `==` itself remains the same, but the `copy`s are removed and thus the program is more efficient.

###### tags: `basics` `Reviewed by Legal`
