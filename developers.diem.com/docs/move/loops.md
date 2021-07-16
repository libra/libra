---
id: move-while-and-loop
title: While and Loop
sidebar_label: While and Loop
---

Move offers two constructs for looping: `while` and `loop`.

## `while` loops
The `while` construct repeats the body (an expression of type unit) until the condition (an expression of type `bool`) evaluates to `false`.

Here is an example of simple `while` loop that computes the sum of the numbers from `1` to `n`:
```rust=
fun sum(n: u64): u64 {
    let sum = 0;
    let i = 1;
    while (i <= n) {
        sum = sum + i;
        i = i + 1
    };

    sum
}
```
Infinite loops are allowed:
```rust=
fun foo() {
    while (true) { }
}
```

### `break`

The `break` expression can be used to exit a loop before the condition evaluates to `false`. For example, this loop uses `break` to find the smallest factor of `n` that's greater than 1:
```rust=
fun upper_bound_sqrt(n: u64): u64 {
    // assuming the input is not 0 or 1
    let i = 2;
    while (i <= n) {
        if (n % i == 0) break;
        i = i + 1
    };

    i
}
```

The `break` expression cannot be used outside of a loop.

### `continue`
The `continue` expression skips the rest of the loop and continuess to the next iteration. This loop uses `continue` to compute the sum of `1, 2, ..., n`, except when the number is divisible by 10:
```rust=
fun sum_intermediate(n: u64): u64 {
    let sum = 0;
    let i = 1;
    while (i <= n) {
        if (i % 10 == 0) continue;
        sum = sum + i;
        i = i + 1
    };

    sum
}
```

The `continue` expression cannot be used outside of a loop.

### The type of `break` and `continue`

`break` and `continue`, much like `return` and `abort`, can have any type. The following examples illustrate where this flexible typing can be helpful:

```rust=
fun pop_smallest_while_not_equal(
    v1: vector<u64>,
    v2: vector<u64>,
): vector<u64> {
    let result = Vector::empty();
    while (!Vector::is_empty(&v1) && !Vector::is_empty(&v2)) {
        let u1 = *Vector::borrow(&v1, Vector::length(&v1) - 1);
        let u2 = *Vector::borrow(&v1, Vector::length(&v1) - 1);
        let popped =
            if (u1 < u2) Vector::pop_back(&mut v1)
            else if (u2 < u1) Vector::pop_back(&mut v2)
            else break; // Here, `break` has type `u64`
        Vector::push_back(&mut result, popped);
    };

    result
}
```
```rust=
fun pick(
    indexes: vector<u64>,
    v1: &vector<address>,
    v2: &vector<address>
): vector<address> {
    let len1 = Vector::length(v1);
    let len2 = Vector::length(v2);
    let result = Vector::empty();
    while (!Vector::is_empty(&indexes)) {
        let index = Vector::pop_back(&mut indexes);
        let chosen_vector =
            if (index < len1) v1
            else if (index < len2) v2
            else continue; // Here, `continue` has type `&vector<address>`
        Vector::push_back(&mut result, *Vector::borrow(chosen_vector, index))
    };

    result
}
```

## The `loop` expression
The `loop` expression repeats the loop body (an expression with type `()`) until it hits a `break`

Without a `break`, the loop will continue forever
```rust=
fun foo() {
    let i = 0;
    loop { i = i + 1 }
}
```

Here is an example that uses `loop` to write the `sum` function:
```rust=
fun sum(n: u64): u64 {
    let sum = 0;
    let i = 0;
    loop {
        i = i + 1;
        if (i > n) break;
        sum = sum + i
    };

    sum
}
```
As you might expect, `continue` can also be used inside a `loop`. Here is `sum_intermediate` from above rewritten using `loop` instead of `while`
```rust=
fun sum_intermediate(n: u64): u64 {
    let sum = 0;
    let i = 0;
    loop {
        if (i % 10 == 0) continue;
        i = i + 1;
        if (i > n) break;
        sum = sum + i
    };

    sum
}
```

## The type of `while` and `loop`

Move loops are typed expressions. A `while` expression always has type `()`.
```rust
let () = while (i < 10) { i = i + 1 };
```

If a `loop` contains a `break`, the expression has type unit `()`

```rust
(loop { if (i < 10) i = i + 1 else break }: ());
let () = loop { if (i < 10) i = i + 1 else break };
```

If `loop` does not have a `break`, `loop` can have any type much like `return`, `abort`, `break`, and `continue`.
```rust
(loop (): u64);
(loop (): address);
(loop (): &vector<vector<u8>>);
```
