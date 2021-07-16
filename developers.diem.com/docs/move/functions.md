---
id: move-functions
title: Functions
sidebar_label: Functions
---

Function syntax in Move is shared between module functions and script functions. Functions inside of modules are reusable, whereas script functions are only used once to invoke a transaction.

## Declaration

Functions are declared with the `fun` keyword followed by the function name, type parameters, parameters, a return type, acquires annotations, and finally the function body.
```
fun <identifier><[type_parameters: constraint],*>([identifier: type],*): <return_type> <acquires [identifier],*> <function_body>
```
For example
```rust
fun foo<T1, T2>(x: u64, y: T1, z: T2): (T2, T1, u64) { (z, y, x) }
```

### Visibility

Module functions, by default, can only be called within the same module. These internal (sometimes called private) functions cannot be called from other modules or from scripts.
```rust=
address 0x42 {
module M {
    fun foo(): u64 { 0 }
    fun calls_foo(): u64 { foo() } // valid
}

module other {
    fun calls_M_foo(): u64 {
        0x42::M::foo() // ERROR!
//      ^^^^^^^^^^^^ 'foo' is internal to '0x42::M'
    }
}
}

script {
    fun calls_M_foo(): u64 {
        0x42::M::foo() // ERROR!
//      ^^^^^^^^^^^^ 'foo' is internal to '0x42::M'
    }
}
```
To allow access from other modules or from scripts, the function must be declared `public`
```rust=
address 0x42 {
module M {
    public fun foo(): u64 { 0 }
    fun calls_foo(): u64 { foo() } // valid
}

module other {
    fun calls_M_foo(): u64 {
        0x42::M::foo() // valid
    }
}
}

script {
    fun calls_M_foo(): u64 {
        0x42::M::foo() // valid
    }
}
```

### Name

Function names can start with letters `a` to `z` or letters `A` to `Z`. After the first character, function names can contain underscores `_`, letters `a` to `z`, letters `A` to `Z`, or digits `0` to `9`.
```rust
fun FOO() {}
fun bar_42() {}
fun _bAZ19() {}
```

### Type Parameters

After the name, functions can have type parameters
```rust
fun id<T>(x: T): T { x }
fun example<T1: copyable, T2>(x: T1, y: T2): (T1, T1, T2) { (copy x, x, y) }
```
For more details, see [Move generics](./generics.md).

### Parameters

Functions parameters are declared with a local variable name followed by a type annotation
```rust
fun add(x: u64, y: u64): u64 { x + y }
```
We read this as `x` has type `u64`

A function does not have to have any parameters at all.
```rust
fun useless() { }
```
This is very common for functions that create new or empty data structures
```rust=
address 0x42 {
module Example {
  struct Counter { count: u64 }

  fun new_counter(): Counter {
      Counter { count: 0 }
  }

}
}
```

### Acquires

When a function accesses a resource using `move_from`, `borrow_global`, or `borrow_global_mut`, the function must indicate that it `acquires` that resource. This is then used by Move's type system to ensure the references into global storage are safe, specifically that there are no dangling references into global storage.
```rust=
address 0x42 {
module Example {

    resource struct Balance { value: u64 }

    public fun add_balance(s: &signer, value: u64) {
        move_to(s, Balance { value })
    }

    public fun extract_balance(addr: address): u64 acquires Balance {
        let Balance { value } = move_from(addr); // acquires needed
        value
    }

}
}
```
`acquires` annotations must also be added for transitive calls within the module. Calls to these functions from another module do not need to annotated with these acquires because one module cannot access resources declared in another module--so the annotation is not needed to ensure reference safety.

```rust=
address 0x42 {
module Example {

    resource struct Balance { value: u64 }

    public fun add_balance(s: &signer, value: u64) {
        move_to(s, Balance { value })
    }

    public fun extract_balance(addr: address): u64 acquires Balance {
        let Balance { value } = move_from(addr); // acquires needed
        value
    }

    public fun extract_and_add(sender: address, receiver: &signer) acquires Balance {
        let value = extract_balance(sender); // acquires needed here
        add_balance(receiver, value)
    }

}
}

address 0x42 {
module Other {
    fun extract_balance(addr: address): u64 {
        0x42::Example::extract_balance(addr) // no acquires needed
    }
}
}
```

A function can `acquire` as many resources as it needs to
```rust=
address 0x42 {
module Example {

    use 0x1::Vector;

    resource struct Balance { value: u64 }
    resource struct Box<T> { items: vector<T> }

    public fun store_two<Item1, Item2>(
        addr: address,
        item1: Item1,
        item2: Item2,
    ) acquires Balance, Box {
        let balance = borrow_global_mut<Balance>(addr); // acquires needed
        balance.value = balance.value - 2;
        let box1 = borrow_global_mut<Box<Item1>>(addr); // acquires needed
        Vector::push_back(&mut box1.items, item1);
        let box2 = borrow_global_mut<Box<Item2>>(addr); // acquires needed
        Vector::push_back(&mut box2.items, item2);
    }
}
}
```
### Return type

After the parameters, a function specifies its return type.
```rust
fun zero(): u64 { 0 }
```
Here `: u64` indicates that the function's return type is `u64`.

Using tuples, a function can return multiple values

```rust
fun one_two_three(): (u64, u64, u64) { (0, 1, 2) }
```

If no return type is specified, the function has an implicit return type of unit `()`. These functions are equivalent
```rust
fun just_unit(): () { () }
fun just_unit() { () }
fun just_unit() { }
```
`script` functions must have a return type of unit `()`
```rust=
script {
    fun do_nothing() {
    }
}
```

As mentioned in the [tuples section](./tuples.md), these tuple "values" are virtual and do not exist at runtime. So for a function that returns unit `()`, it will not be returning any value at all during execution.

### Function body

A function's body is an expression block. The return value of the function is the last value in the sequence
```rust=
fun example(): u64 {
    let x = 0;
    x = x + 1;
    x // returns 'x'
}
```

See [the section below for more information on returns](#returning-values)

For more information on expression blocks, see [Move variables](./variables.md).

### Native Functions

Some functions do not have a body specified, and instead have the body provided by the VM. These functions are marked `native`.

Without modifying the VM source code, a programmer cannot add new native functions. Furthermore, it is the intent that `native` functions are used for either standard library code or for functionality needed for the given Move environment.

Most `native` functions you will likely see are in standard library code such as `Vector`
```rust=
address 0x1 {
module Vector {
    native public fun empty<Element>(): vector<Element>;
    ...
}
}
```

## Calling

When calling a function, the name can be specified either through an alias or fully qualified
```rust=
address 0x42 {
module Example {
    public fun zero(): u64 { 0 }
}
}

script {
    use 0x42::Example::{Self, zero};
    fun call_zero() {
        // With the `use` above all of these calls are equivalent
        0x42::Example::zero();
        Example::zero();
        zero();
    }
}
```

When calling a function, an argument must be given for every parameter.
```rust=
address 0x42 {
module Example {
    public fun takes_none(): u64 { 0 }
    public fun takes_one(x: u64): u64 { x }
    public fun takes_two(x: u64, y: u64): u64 { x + y }
    public fun takes_three(x: u64, y: u64, z: u64): u64 { x + y + z }
}
}

script {
    use 0x42::Example;
    fun call_all() {
        Example::takes_none();
        Example::takes_one(0);
        Example::takes_two(0, 1);
        Example::takes_three(0, 1, 2);
    }
}
```

Type arguments can be either specified or inferred. Both calls are equivalent.
```rust=
address 0x42 {
module Example {
    public fun id<T>(x: T): T { x }
}
}

script {
    use 0x42::Example;
    fun call_all() {
        Example::id(0);
        Example::id<u64>(0);
    }
}
```
For more details, see [Move generics](./generics.md).


## Returning values

The result of a function, it's "return value", is the final value of it's function body. For example
```rust=
fun add(x: u64, y: u64): u64 {
    x + y
}
```
[As mentioned above](#function-body), the function's body is an [expression block](./variables.md). The expression block can sequence various statements, and the final expression in the block will be be the value of that block
```rust=
fun double_and_add(x: u64, y: u64): u64 {
    let double_x = x * 2;
    let double_y = y * 2;
    double_x + double_y
}
```
The return value here is `double_x + double_y`


### `return` expression

A function implicitly returns the value that its body evaluates to. However, functions can also use the explicit `return` expression:

```rust
fun f1(): u64 { return 0 }
fun f2(): u64 { 0 }
```
These two functions are equivalent. In this slightly more involved example, the function subtracts two `u64` values, but returns early with `0` if the second value is too large:
```rust=
fun safe_sub(x: u64, y: u64): u64 {
    if (y > x) return 0;
    x - y
}
```
Note that the body of this function could also have been written as `if (y > x) 0 else x - y`.

However `return` really shines is in exiting deep within other control flow constructs. In this example, the function iterates through a vector to find the index of a given value:
```rust=
use 0x1::Vector;
use 0x1::Option::{Self, Option};
fun index_of<T>(v: &vector<T>, target: &T): Option<u64> {
    let i = 0;
    let n = Vector::length(v);
    while (i < n) {
        if (Vector::borrow(v, i) == target) return Option::some(i);
        i = i + 1
    };

    Option::none()
}
```

Using `return` without an argument is shorthand for `return ()`. That is, the following two functions are equivalent:
```rust
fun foo() { return }
fun foo() { return () }
```
