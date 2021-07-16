---
id: move-tuples-and-unit
title: Tuples and Unit
sidebar_label: Tuples and Unit
---

Move does not fully support tuples as one might expect coming from another language with them as a first-class value. However, in order to support multiple return values, Move has tuple-like expressions. These expressions do not result in a concrete value at runtime (there are no tuples in the bytecode), and as a result they are very limited: they can only appear in expressions (usually in the return position for a function); they cannot be bound to local variables; they cannot be stored in structs; and tuple types cannot be used to instantiate generics.

Similarly, unit `()` is a type created by the Move source language in order to be expression based. The unit value `()` does not result in any runtime value. We can consider unit`()` to be an empty tuple, and any restrictions that apply to tuples also apply to unit.

It might feel weird to have tuples in the language at all given these restrictions. But one of the most common use cases for tuples in other languages is for functions to allow functions to return multiple values. Some languages work around this by forcing the users to write structs that contain the multiple return values. However in Move, you cannot put references inside of [structs](./structs-and-resources.md). This required Move to support multiple return values. These multiple return values are all pushed on the stack at the bytecode level. At the source level, these multiple return values are represented using tuples.

## Literals

Tuples are created by a comma separated list of expressions inside of parentheses

|Syntax | Type | Description |
| -------- | -------- | -------- |
| `()`     | `(): ()` | Unit, the empty tuple, or the tuple of arity 0
| `(e0, ..., en)` |`(e0, ..., en): (T0, ..., Tn)` where `e_i: Ti` s.t. `0 <= i <= n` and `n > 0` | A `n`-tuple, a tuple of arity `n`, a tuple with `n` elements

Note that `(e)` does not have type `(e): (t)`, in other words there is no tuple with one element. If there is only a single element inside of the parentheses, the parentheses are only used for disambiguation and do not carry any other special meaning.

Sometimes, tuples with two elements are called "pairs" and tuples with three elements are called "triples."

### Examples

```rust=
address 0x42 {
module Example {
    // all 3 of these functions are equivalent

    // when no return type is provided, it is assumed to be `()`
    fun returs_unit_1() { }

    // there is an implicit () value in empty expression blocks
    fun returs_unit_2(): () { }

    // explicit version of `returs_unit_1` and `returs_unit_2`
    fun returs_unit_3(): () { () }


    fun returns_3_values(): (u64, bool, address) {
        (0, false, 0x42)
    }
    fun returns_4_values(x: &u64): (&u64, u8, u128, vector<u8>) {
        (x, 0, 1, b"foobar")
    }
}
}
```

## Operations

The only operation that can be done on tuples currently is destructuring.

### Destructuring

For tuples of any size, they can be destructured in either a `let` binding or in an assignment.

For example:
```rust=
address 0x42 {
module Example {
    // all 3 of these functions are equivalent
    fun returns_unit() {}
    fun returns_2_values(): (bool, bool) { (true, false) }
    fun returns_4_values(x: &u64): (&u64, u8, u128, vector<u8>) { (x, 0, 1, b"foobar") }

    fun examples(cond: bool) {
        let () = ();
        let (x, y): (u8, u64) = (0, 1);
        let (a, b, c, d) = (0x0, 0, false, b"");

        () = ();
        (x, y) = if (cond) (1, 2) else (3, 4);
        (a, b, c, d) = (0x1, 1, true, b"1");
    }

    fun examples_with_function_calls() {
        let () = returns_unit();
        let (x, y): (bool, bool) = returns_2_values();
        let (a, b, c, d) = returns_4_values(&0);

        () = returns_unit();
        (x, y) = returns_2_values();
        (a, b, c, d) = returns_4_values(&1);
    }
}
}
```

For more details, see [Move Variables](./variables.md).

## Subtyping

Along with references, tuples are the only types that have subtyping in Move. Tuples do have subtyping only in the sense that subtype with references (in a covariant way).

For example
```rust=
let x: &u64 = &0;
let y: &mut u64 = &mut 1;

// (&u64, &mut u64) is a subtype of (&u64, &u64)
//   since &mut u64 is a subtype of &u64
let (a, b): (&u64, &u64) = (x, y);
// (&mut u64, &mut u64) is a subtype of (&u64, &u64)
//   since &mut u64 is a subtype of &u64
let (c, d): (&u64, &u64) = (y, y);
// error! (&mut u64, &mut u64) is NOT a subtype of (&u64, &mut u64)
//   since &u64 is NOT a subtype of &mut u64
let (e, f): (&mut u64, &mut u64) = (x, y);
```

## Ownership

As mentioned above, tuple values don't really exist at runtime. And currently they cannot be stored into local variables because of this (but it is likely that this feature will come soon). As such, tuples can only be moved currently, as copying them would require putting them into a local variable first.
