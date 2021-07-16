---
id: move-uses-and-aliases
title: Uses and Aliases
sidebar_label: Uses and Aliases
---

The `use` syntax can be used to create aliases to members in other modules. `use` can be used to create aliases that last either for the entire module, or for a given expression block scope.

## Syntax

There are several different syntax cases for `use`. Starting with the most simple, we have the following for creating aliases to other modules
```rust
use <address>::<module name>;
use <address>::<module name> as <module alias name>;
```
For example
```rust
use 0x1::Vector;
use 0x1::Vector as V;
```
`use 0x1::Vector;` introduces an alias `Vector` for `0x1::Vector`. This means that anywhere you would want to use the module name `0x1::Vector` (assuming this `use` is in scope), you could use `Vector` instead. `use 0x1::Vector;`  is equivalent to `use 0x1::Vector as Vector;`

Similarly `use 0x1::Vector as V;` would let you use `V` instead of `0x1::Vector`
```rust=
use 0x1::Vector;
use 0x1::Vector as V;

fun new_vecs(): (vector<u8>, vector<u8>, vector<u8>) {
    let v1 = 0x1::Vector::empty();
    let v2 = Vector::empty();
    let v3 = V::empty();
    (v1, v2, v3)
}
```

If you want to import a specific module member (such as a function, struct, or constant). You can use the following syntax.

```rust
use <address>::<module name>::<module member>;
use <address>::<module name>::<module member> as <member alias>;
```
For example
```rust
use 0x1::Vector::empty;
use 0x1::Vector::empty as empty_vec;
```
This would let you use the function `0x1::Vector::empty` without full qualification. Instead you could use `empty` and `empty_vec` respectively. Again, `use 0x1::Vector::empty;` is equivalent to `use 0x1::Vector::empty as empty;`

```rust=
use 0x1::Vector::empty;
use 0x1::Vector::empty as empty_vec;

fun new_vecs(): (vector<u8>, vector<u8>, vector<u8>) {
    let v1 = 0x1::Vector::empty();
    let v2 = empty();
    let v3 = empty_vec();
    (v1, v2, v3)
}
```

If you want to add aliases for multiple module members at once, you can do so with the following syntax
```rust
use <address>::<module name>::{<module member>, <module member> as <member alias> ... };
```
For example
```rust=
use 0x1::Vector::{push_back, length as len, pop_back};

fun swap_last_two<T>(v: &mut vector<T>) {
    assert(len(v) >= 2, 42);
    let last = pop_back(v);
    let second_to_last = pop_back(v);
    push_back(v, last);
    push_back(v, second_to_last)
}

```

If you need to add an alias to the Module itself in addition to module members, you can do that in a single `use` using `Self`. `Self` is a member of sorts that refers to the module.
```rust
use 0x1::Vector::{Self, empty};
```

For clarity, all of the following are equivalent:
```rust
use 0x1::Vector;
use 0x1::Vector as Vector;
use 0x1::Vector::Self;
use 0x1::Vector::Self as Vector;
use 0x1::Vector::{Self};
use 0x1::Vector::{Self as Vector};
```

If needed, you can have as many aliases for any item as you like
```rust=
use 0x1::Vector::{
    Self,
    Self as V,
    length,
    length as len,
};

fun pop_twice<T>(v: &mut vector<T>): (T, T) {
    // all options available given the `use` above
    assert(Vector::length(v) > 1, 42);
    assert(V::length(v) > 1, 42);
    assert(length(v) > 1, 42);
    assert(len(v) > 1, 42);

    (Vector::pop_back(v), Vector::pop_back(v))
}
```

## Inside a `module`

Inside of a `module` all `use` declarations are usable regardless of the order of declaration.

```rust=
address 0x42 {
module Example {
    use 0x1::Vector;

    fun example(): vector<u8> {
        let v = empty();
        Vector::push_back(&mut v, 0);
        Vector::push_back(&mut v, 10);
        v
    }

    use 0x1::Vector::empty;
}
}
```
The aliases declared by `use` in the module usable within that module.

Additionally, the aliases introduced cannot conflict with other module members. See [Uniqueness](#uniqueness) for more details

## Inside an expression

You can add `use` declarations to the beginning of any expression block
```rust=
address 0x42 {
module Example {

    fun example(): vector<u8> {
        use 0x1::Vector::{empty, push_back};

        let v = empty();
        push_back(&mut v, 0);
        push_back(&mut v, 10);
        v
    }
}
}
```
As with `let`, the aliases introduced by `use` in an expression block are removed at the end of that block.
```rust=
address 0x42 {
module Example {

    fun example(): vector<u8> {
        let result = {
            use 0x1::Vector::{empty, push_back};
            let v = empty();
            push_back(&mut v, 0);
            push_back(&mut v, 10);
            v
        };
        result
    }

}
}
```
Attempting to use the alias after the block ends will result in an error
```rust=
fun example(): vector<u8> {
    let result = {
        use 0x1::Vector::{empty, push_back};
        let v = empty();
        push_back(&mut v, 0);
        push_back(&mut v, 10);
        v
    };
    let v2 = empty(); // ERROR!
//           ^^^^^ unbound function 'empty'
    result
}
```

Any `use` must be the first item in the block. If the `use` comes after any expression or `let`, it will result in a parsing error
```rust=
{
    let x = 0;
    use 0x1::Vector; // ERROR!
    let v = Vector::empty();
}
```

## Naming rules

Aliases must follow the same rules as other module members. This means that aliases to structs or constants must start with `A` to `Z`

```rust=
address 0x42 {
module Data {
    struct S {}
    const FLAG: bool = false;
    fun foo() {}
}
module Example {
    use 0x42::Data::{
        S as s, // ERROR!
        FLAG as fLAG, // ERROR!
        foo as FOO,  // valid
        foo as bar, // valid
    };
}
}
```

## Uniqueness

Inside a given scope, all aliases introduced by `use` declarations must be unique.

For a module, this means aliases introduced by `use` cannot overla
```rust=
address 0x42 {
module Example {

    use 0x1::Vector::{empty as foo, length as foo}; // ERROR!
    //                                        ^^^ duplicate 'foo'

    use 0x1::Vector::empty as bar;

    use 0x1::Vector::length as bar; // ERROR!
    //                         ^^^ duplicate 'bar'

}
}
```

And, they cannot overlap with any of the module's other members
```rust=
address 0x42 {
module Data {
    struct S {}
}
module Example {
    use 0x42::Data::S;

    struct S { value: u64 } // ERROR!
    //     ^ conflicts with alias 'S' above
}
}
```

Inside of an expression block, they cannot overlap with each other, but they can [shadow](#shadowing) other aliases or names from an outer scope

## Shadowing

`use` aliases inside of an expression block can shadow names (module members or aliases) from the outer scope. As with shadowing of locals, the shadowing ends at the end of the expression block;

```rust=
address 0x42 {
module Example {

    struct WrappedVector { vec: vector<u64> }

    fun empty(): WrappedVector {
        WrappedVector { vec: 0x1::Vector::empty() }
    }

    fun example1(): (WrappedVector, WrappedVector) {
        let vec = {
            use 0x1::Vector::{empty, push_back};
            // 'empty' now refers to 0x1::Vector::empty

            let v = empty();
            push_back(&mut v, 0);
            push_back(&mut v, 1);
            push_back(&mut v, 10);
            v
        };
        // 'empty' now refers to Self::empty

        (empty(), WrappedVector { vec })
    }

    fun example2(): (WrappedVector, WrappedVector) {
        use 0x1::Vector::{empty, push_back};
        let w: WrappedVector = {
            use 0x42::Example::empty;
            empty()
        };
        push_back(&mut w.vec, 0);
        push_back(&mut w.vec, 1);
        push_back(&mut w.vec, 10);

        let vec = empty();
        push_back(&mut vec, 0);
        push_back(&mut vec, 1);
        push_back(&mut vec, 10);

        (w, WrappedVector { vec })
    }
}
}
```

## Unused Use or Alias

An unused `use` will result in an error
```rust=
address 0x42 {
module Example {
    use 0x1::Vector::{empty, push_back}; // ERROR!
    //                       ^^^^^^^^^ unused alias 'push_back'

    fun example(): vector<u8> {
        empty()
    }
}
}
```
