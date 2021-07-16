---
id: move-generics
title: Generics
sidebar_label: Generics
---

Generics can be used to define functions and structs over different input data types. This language feature is sometimes referred to as *parametric polymorphism*. In Move, we will often use the term generics interchangeably with type parameters and type arguments.

Generics are commonly used in library code, such as in Vector, to declare code that works over any possible instantiation (that satisfies the specified constraints). In other frameworks, generic code can sometimes be used to interact with global storage many different ways that all still share the same implementation.

## Declaring Type Parameters

Both functions and structs can take a list of type parameters in their signatures, enclosed by a pair of angle brackets `<...>`.

### Generic Functions
Type parameters for functions are placed after the function name and before the (value) parameter list. The following code defines a generic identity function that takes a value of any type and returns that value unchanged.
```rust
fun id<T>(x: T): T {
    // this type annotation is unnecessary but valid
    (x: T)
}
```
Once defined, the type parameter `T` can be used in parameter types, return types, and inside the function body.

### Generic Structs

Type parameters for structs are placed after the struct name, and can be used to name the types of the fields.

```rust
struct Foo<T> { x: T }

struct Bar<T1, T2> {
    x: T1,
    y: vector<T2>,
}
```

[Note that type parameters do not have to be used](#unused-type-parameters)


## Type Arguments

### Calling Generic Functions

When calling a generic function, one can specify the type arguments for the function's type parameters in a list enclosed by a pair of angle brackets.

```rust=
fun foo() {
    let x = id<bool>(true);
}
```

If you do not specify the type arguments, Move's [type inference](#type-inference) will supply them for you.

### Using Generic Structs

Similarly, one can attach a list of type arguments for the struct's type parameters when constructing or destructing values of generic types.

```rust=
fun foo() {
    let foo = Foo<bool> { x: true };
    let Foo<bool> { x } = foo;
}
```
If you do not specify the type arguments, Move's [type inference](#type-inference) will supply them for you.

### Type Argument Mismatch

If you specify the type arguments and they conflict with the actual values supplied, an error will be given
```rust=
fun foo() {
    let x = id<u64>(true); // error! true is not a u64
}
```
and similarly
```rust=
fun foo() {
    let foo = Foo<bool> { x: 0 }; // error! 0 is not a bool
    let Foo<address> { x } = foo; // error! bool is incompatible with address
}
```

## Type Inference

In most cases, the Move compiler will be able to infer the type arguments so you don't have to write them down explicitly. Here's what the examples above would look like if we omit the type arguments.

```rust=
fun foo() {
    let x = id(true);
    //        ^ <bool> is inferred

    let foo = Foo { x: true };
    //           ^ <bool> is inferred

    let Foo { x } = foo;
    //     ^ <bool> is inferred
}
```
Note: when the compiler is unable to infer the types, you'll need annotate them manually. A common scenario is to call a function with type parameters appearing only at return positions.
```rust=
address 0x2 {
module M {
    using 0x1::Vector;

    fun foo() {
        // let v = Vector::new();
        //                    ^ The compiler cannot figure out the element type.

        let v = Vector::new<u64>();
        //                 ^~~~~ Must annotate manually.
    }
}
}
```
However, the compiler will be able to infer the type if that return value is used later in that function
```rust=
address 0x2 {
module M {
    using 0x1::Vector;

    fun foo() {
        let v = Vector::new();
        //                 ^ <u64> is inferred
        Vector::push_back(&mut v, 42);
    }
}
}
```

## Unused Type Parameters
Move allows unused type parameters so the following struct definition is valid:
```rust=
struct Foo<T> {
    foo: u64
}
```
This can be convenient when modeling certain concepts. Here is an example:
```rust=
address 0x2 {
module M {
    // Currency Specifiers
    struct Currency1 {}
    struct Currency2 {}

    // A generic coin type that can be instantiated using a currency
    // specifier type.
    //   e.g. Coin<Currency1>, Coin<Currency2> etc.
    resource struct Coin<Currency> {
        value: u64
    }
}
}
```

## Constraints

In the examples above, we have demonstrated how one can use type parameters to define "unkonwn" types that can be plugged in by callers at a later time. This however means the type system has little information about the type and has to perform checks in a very conservative way. In some sense, the type system must assume the worst case scenario for an unconstrained generic. If for instance you were to `copy` an unconstrained generic, you could break resource safety if that type was instantiated with a resource!

This is where constraints come into play: they offer a way to specify what properties these unknown types have so the type system can allow operations that would otherwise be unsafe.

### Declaring Constraints
Constraints can be imposed on type parameters using the following syntax.
```rust=
// T is the name of the type parameter
T: resource
// or
T: copyable
```
- `resource` means values of the type cannot be copied and cannot be dropped
- `copyable` means values of the type can be copied and can be dropped

These two constraint are mutually exclusive so you can't have both applied to a type parameter at the same time.
### Verifying Constraints
Constraints are checked at call sites so the following code won't compile.
```rust=
struct Foo<T: resource> { x: T }

struct Bar { x: Foo<u8> }
//                  ^ error! u8 is not resource

struct Baz<T> { x: Foo<T> }
//                     ^ error! T isn't necessarily resource
```

```rust=
resource struct R {}

fun unsafe_consume<T>(x: T) {
    // error! x might be an unused resource
}

fun consume<T: copyable>(x: T) {
    // valid!
    // x will be dropped automatically
}

fun foo() {
    let r = R {};
    consume<R>(r);
    //      ^ error! R is not copyable
}
```

```rust=
resource struct R {}

fun unsafe_double<T>(x: T) {
    (copy x, x)
    // error! cannot copy x as it might be a resource
}

fun double<T: copyable>(x: T) {
    (copy x, x)
}

fun foo(): (R, R) {
    let r = R{};
    double<R>(r)
    //     ^ error! R is not copyable
}
```

### How to tell if a struct type is resource or copyable
Recall that a non-generic struct type is considered resource if and only if it is explicitly marked so.
```rust=
resource struct Foo {} // Foo is resource
struct Bar {}          // Bar is copyable
```
However for a generic struct type, whether it is considered resource depends on the specific type arguments used to instantiate it, unless there's an explicit `resource` marker in the struct definition.
```rust=
struct Foo<T> {}
resource struct Bar<T> {}
resource struct R {}

// R is a resource type by definition

// Foo<u64> is a copyable type since u64 is a copyable type

// Foo<vector<Foo<u64>>> is a copyable type since
//   vector<Foo<u64>> is a copyable type since
//     Foo<u64> is a copyable type since u64 is a copyable type

// Foo<R> is a resource type since R is a resource type
// However, Foo<R> cannot be used with global storage operations

// Bar<u64> is a resource type by definition

// vector<Foo<Bar<u64>>> is a resource type since
//   Foo<Bar<u64>> is a resource type since
//     Bar<u64> is a resource type by definition
```

## Limitations on Recursions

### Recursive Structs

Generic structs can not contain fields of the same type, either directly or indirectly, even with different type arguments. All of the following struct definitions are invalid:

```rust=
struct Foo<T> {
    x: Foo<u64> // error! 'Foo' containing 'Foo'
}

struct Bar<T> {
    x: Bar<T> // error! 'Bar' containing 'Bar'
}

// error! 'A' and 'B' forming a cycle, which is not allowed either.
struct A<T> {
    x: B<T, u64>
}

struct B<T1, T2> {
    x: A<T1>
    y: A<T2>
}
```

### Advanced Topic: Type-level Recursions

Move allows generic functions to be called recursively. However, when used in combination with generic structs, this could create an infinite number of types in certain cases, and allowing this means adding unnecessary complexity to the compiler, vm and other language components. Therefore, such recursions are forbidden.

Allowed:
```rust=
address 0x2 {
module M {
    resource struct A<T> {}

    // Finitely many types -- allowed.
    // foo<T> -> foo<T> -> foo<T> -> ... is valid
    fun foo<T>() {
        foo<T>();
    }

    // Finitely many types -- allowed.
    // foo<T> -> foo<A<u64>> -> foo<A<u64>> -> ... is valid
    fun foo<T>() {
        foo<A<u64>>();
    }
}
}
```

Not allowed:
```rust=
address 0x2 {
module M {
    resource struct A<T> {}

    // Infinitely many types -- NOT allowed.
    // error!
    // foo<T> -> foo<A<T>> -> foo<A<A<T>>> -> ...
    fun foo<T>() {
        foo<Foo<T>>();
    }
}
}
```
```rust=
address 0x2 {
module N {
    resource struct A<T> {}

    // Infinitely many types -- NOT allowed.
    // error!
    // foo<T1, T2> -> bar<T2, T1> -> foo<T2, A<T1>>
    //   -> bar<A<T1>, T2> -> foo<A<T1>, A<T2>>
    //   -> bar<A<T2>, A<T1>> -> foo<A<T2>, A<A<T1>>>
    //   -> ...
    fun foo<T1, T2>() {
        bar<T2, T1>();
    }

    fun bar<T1, T2> {
        foo<T1, A<T2>>();
    }
}
}
```
Note, the check for type level recursions is based on a conservative analysis on the call sites and does NOT take control flow or runtime values into account.
```rust=
address 0x2 {
module M {
    resource struct A<T> {}

    fun foo<T>(n: u64) {
        if (n > 0) {
            foo<A<T>>(n - 1);
        };
    }
}
}
```
The function in the example above will technically terminate for any given input and therefore only creating finitely many types, but it is still considered invalid by Move's type system.
