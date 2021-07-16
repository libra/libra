---
id: move-structs-and-resources
title: Structs and Resources
sidebar_label: Structs and Resources
---

A *struct* is a user-defined data structure containing typed fields. Structs can store any non-reference type, including other structs.

A *resource* is a kind of struct that cannot be copied and cannot be dropped. All resource values must have ownership transferred by the end of the function. Resources are used to define global storage schemas, and Only resource structs can be saved directly into global storage.

## Defining Structs

Structs must be defined inside a module:
```rust
address 0x2 {
module M {
    struct Foo { x: u64, y: bool }
    struct Bar {}
    struct Baz { foo: Foo, }
    //                   ^ note: it is fine to have a trailing comma
}
}
```
Structs cannot be recursive, so the following definition is invalid:
```rust=
struct Foo { x: Foo }
//              ^ error! Foo cannot contain Foo
```
Struct definitions can be annotated with the `resource` modifier, which imposes a few additional constraints on the type, but also enables it to be used in global storage. We will cover the details later in this tutorial.
```rust=
address 0x2 {
module M {
    resource struct Foo { x: u64, y: bool }
}
}
```
Note: the term `resource struct` is a little bit cumbersome so in many places we just call it `resource`.

### Naming

Structs must start with a capital letter `A` to `Z`. After the first letter, constant names can contain underscores `_`, letters `a` to `z`, letters `A` to `Z`, or digits `0` to `9`.
```rust
struct Foo {}
struct BAR {}
struct B_a_z_4_2 {}
```

This naming restriction of starting with `A` to `Z` is in place to give room for future language features. It may or may not be removed later.


## Using Structs

### Creating Structs

Values of a struct type can be created (or "packed") by indicating the struct name, followed by value for each field:

```rust=
address 0x2 {
module M {
    struct Foo { x: u64, y: bool }
    struct Baz { foo: Foo }

    fun example() {
        let foo = Foo { x: 0, y: false };
        let baz = Baz { foo: foo };
    }
}
}
```

If you initialize a struct field with a local variable whose name is the same as the field, you can use the following shorthand:
```rust
let baz = Baz { foo: foo };
// is equivalent to
let baz = Baz { foo };
```

This is called sometimes called "field name punning".

### Destroying Structs via Pattern Matching

Struct values can be destroyed by binding or assigning them patterns.
```rust=
address 0x2 {
module M {
    struct Foo { x: u64, y: bool }
    struct Bar { foo: Foo }
    struct Baz {}

    fun example_destroy_foo() {
        let foo = Foo { x: 3, y: false };
        let Foo { x, y: foo_y } = foo;
        //        ^ shorthand for `x: x`

        // two new bindings
        //   x: u64 = 3
        //   foo_y: bool = false
    }

    fun example_destroy_foo_wildcard() {
        let foo = Foo { x: 3, y: false };
        let Foo { x, y: _ } = foo;
        // only one new binding since y was bound to a wildcard
        //   x: u64 = 3
    }

    fun example_destroy_foo_assignment() {
        let x: u64;
        let y: bool;
        Foo { x, y } = Foo { x: 3, y: false };
        // mutating existing variables x & y
        //   x = 3, y = false
    }

    fun example_foo_ref() {
        let foo = Foo { x: 3, y: false };
        let Foo { x, y } = &foo;
        // two new bindings
        //   x: &u64
        //   y: &bool
    }

    fun example_foo_ref_mut() {
        let foo = Foo { x: 3, y: false };
        let Foo { x, y } = &mut foo;
        // two new bindings
        //   x: &mut u64
        //   y: &mut bool
    }

    fun example_destroy_bar() {
        let bar = Bar { foo: Foo { x: 3, y: false } };
        let Bar { foo: Foo { x, y } } = bar;
        //             ^ nested pattern
        // two new bindings
        //   x: u64 = 3
        //   foo_y: bool = false
    }

    fun example_destroy_baz() {
        let baz = Baz {};
        let Baz {} = baz;
    }
}
}
```

### Borrowing Structs and Fields

The `&` and `&mut` operator can be used to create references to structs or fields. These examples include some optional type annotations (e.g., `:& Foo`) to demonstrate the type of operations.
```rust=
let foo = Foo { x: 3, y: true };
let foo_ref: &Foo = &foo;
let y: bool = foo_ref.y;          // reading a field via a reference to the struct
let x_ref: &u64 = &foo.x;

let x_ref_mut: &mut u64 = &mut foo.x;
*x_ref_mut = 42;            // modifying a field via a mutable reference
```
It is possible to borrow inner fields of nested structs.
```rust=
let foo = Foo { x: 3, y: true };
let bar = Bar { foo };

let x_ref = &bar.foo.x;
```
You can also borrow a field via a reference to a struct.
```rust=
let foo = Foo { x: 3, y: true };
let foo_ref = &foo;
let x_ref = &foo_ref.x;
// this has the same effect as let x_ref = &foo.x
```

### Reading and Writing Fields

If you need to read and copy a field's value, you can then dereference the borrowed field
```rust=
let foo = Foo { x: 3, y: true };
let bar = Bar { foo: copy foo };
let x: u64 = *&foo.x;
let y: bool = *&foo.y;
let foo2: Foo = *&foo.bar;
```

If the field is an implicitly copyable, the dot operator can be used to read fields of a struct without any borrowing.
```rust=
let foo = Foo { x: 3, y: true };
let x = foo.x;  // x == 3
let y = foo.y;  // y == true
```
Dot operators can be chained to access nested fields.
```rust=
let baz = Baz { foo: Foo { x: 3, y: true } };
let x = baz.foo.x; // x = 3;
```

However, this is not permitted for fields that contain non-primitive types, such a vector or another struct
```rust=
let foo = Foo { x: 3, y: true };
let bar = Bar { foo };
let foo2: Foo = *&foo.bar;
let foo3: Foo = foo.bar; // error! add an explicit copy with *&
```
The reason behind this design decision is that copying a vector or another struct might be an expensive operation. It is important for a programmer to be aware of this copy and make others aware with the explicit syntax `*&`

In addition reading from fields, the dot syntax can be used to modify fields, regardless of the field being a primitive type or some other struct
```rust=
let foo = Foo { x: 3, y: true };
foo.x = 42;     // foo = Foo { x: 42, y: true }
foo.y = !foo.y; // foo = Foo { x: 42, y: false }
let bar = Bar { foo };            // bar = Bar { foo: Foo { x: 42, y: false } }
bar.foo.x = 52;                   // bar = Bar { foo: Foo { x: 52, y: false } }
bar.foo = Foo { x: 62, y: true }; // bar = Bar { foo: Foo { x: 62, y: true } }
```

The dot syntax also works via a reference to a struct
```rust=
let foo = Foo { x: 3, y: true };
let foo_ref = &mut foo;
foo.x = foo.x + 1;
```

## Privileged Struct Operations

Most struct operations on a struct type `T` can only be performed inside the module that declares `T`:

- Struct types can only be created ("packed"), destroyed ("unpacked") inside the module that defines the struct.
- The fields of a struct are only accessible inside the module that defines the struct.

Following these rules, if you want to modify your struct outside the module, you will need to provide publis APIs for them. The end of the chapter contains some examples of this.

However, struct *types* are always visible to another module or script:
```rust=
// M.move
address 0x2 {
module M {
    struct Foo { x: u64 }

    public fun new_foo(): Foo {
        Foo { x: 42 }
    }
}
}
```
```rust=
// N.move
address 0x2 {
module N {
    use 0x2::M;

    struct Wrapper {
        foo: M::Foo
    }

    fun f1(foo: M::Foo) {
        let x = foo.x;
        //      ^ error! cannot access fields of `foo` here
    }

    fun f2() {
        let foo_wrapper = Wrapper { foo: M::new_foo() };
    }
}
}
```

Note that structs do not have visibility modifiers (e.g., `public` or `private`).

## Ownership
By default, structs can be freely copied and silently dropped.
```rust=
address 0x2 {
module M {
    struct Foo { x: u64 }

    public fun run() {
        let foo = Foo { x: 100 };
        let foo_copy = copy foo;
        // ^ this code copies foo, whereas `let x = foo` or
        // `let x = move foo` both move foo

        let x = foo.x;            // x = 100
        let x_copy = foo_copy.x;  // x = 100

        // both foo and foo_copy are implicitly discarded when the function returns
    }
}
}
```
Resource structs on the other hand, cannot be copied or dropped silently. This property can be very useful when modeling
real world resources like money, as you do not want money to be duplicated or get lost
in circulation.
```rust=
address 0x2 {
module M {
    resource struct Foo { x: u64 }

    public fun copying_resource() {
        let foo = Foo { x: 100 };
        let foo_copy = copy foo; // error! resources cannot be copied
        let foo_ref = &foo;
        let another_copy = *foo_ref // error! resources cannot be copied
    }

    public fun destroying resource1() {
        let foo = Foo { x: 100 };

        // error! when the function returns, foo still contains a resource
    }

    public fun destroying resource2(f: &mut Foo) {
        *f = Foo { x: 100 } // error! destroying resource
    }
}
}
```
To fix the second example (`fun dropping_resource`), you will need to manually "unpack" the resource:
```rust=
address 0x2 {
module M {
    resource struct Foo { x: u64 }

    public fun destroying_resource() {
        let foo = Foo { x: 100 };
        let Foo { x } = foo;
    }
}
}
```
In addition, in order to enforce the said ownership rules at all times, it is required that normal structs do NOT have contain fields of resource types.
```rust=
address 0x2 {
module M {
    resource struct R {}

    struct Foo { x: R }
    //           ^~~~ error! Foo is not a resource so
    //                it cannot contain R

    resource struct Bar { x: R }
    // good
}
}
```

Recall that you are only able to deconstruct a resource within the module in which it is defined. This can be leveraged to enforce certain invariants in a system, for example, conservation of money.

## Storing Resources in Global Storage

Only resource structs can be saved directly in [persistent global storage](./global-storage-operators.md). See the [global storage](./global-storage-operators.md) chapter for more detail.


## Example 1: Coin
```rust=
address 0x2 {
module M {
    resource struct Coin {
        value: u64,
    }

    public fun zero(): Coin {
        Coin { value: 0 }
    }

    public fun withdraw(coin: &mut Coin, amount: u64): Coin {
        assert(coin.balance >= amount, 1000);
        coin.value = coin.value - amount;
        Coin { value: amount }
    }

    public fun deposit(coin: &mut Coin, other: Coin) {
        let Coin { value } = other;
        coin.value = coin.value + value;
    }

    public fun split(coin: Coin, amount: u64): (Coin, Coin) {
        let other = withdraw(&mut coin, amount);
        (coin, other)
    }

    public fun merge(coin1: Coin, coin2: Coin): Coin {
        deposit(&mut coin1, coin2);
        coin1
    }
}
}
```

## Example 2: Geometry
```rust=
address 0x2 {
module Point {
    struct Point {
        x: u64,
        y: u64,
    }

    public fun new(x: u64, y: u64): Point {
        Point {
            x, y
        }
    }

    public fun x(p: &Point): u64 {
        p.x
    }

    public fun y(p: &Point): u64 {
        p.y
    }

    fun abs_sub(a: u64, b: u64): u64 {
        if (a < b) {
            b - a
        }
        else {
            a - b
        }
    }

    public fun dist_squared(p1: &Point, p2: &Point): u64 {
        let dx = abs_sub(p1.x, p2.x);
        let dy = abs_sub(p1.y, p2.y);
        dx*dx + dy*dy
    }
}
}
```

```rust=
address 0x2 {
module Circle {
    use 0x2::Point::{Self, Point};

    struct Circle {
        center: Point,
        radius: u64,
    }

    public fun new(center: Point, radius: u64): Circle {
        Circle { center, radius }
    }

    public fun overlaps(c1: &Circle, c2: &Circle): bool {
        let d = Point::dist_squared(&c1.center, &c2.center);
        let r1 = c1.radius;
        let r2 = c2.radius;
        d*d <= r1*r1 + 2*r1*r2 + r2*r2
    }
}
}
```
