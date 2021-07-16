---
id: move-modules-and-scripts
title: Modules and Scripts
sidebar_label: Modules and Scripts
---

Move has two different types of programs: ***Modules*** and ***Scripts***. Modules are libraries that define struct types along with functions that operate on these types. Struct types define the schema of Move's [global storage](./global-storage-structure.md), and module functions define the rules for updating storage. Modules themselves are also stored in global storage. Scripts are executable entrypoints similar to a `main` function in a conventional language. A script typically calls functions of a published module that perform updates to global storage. Scripts are ephemeral code snippets that are not published in global storage.

A Move source file (or **compilation unit**) may contain multiple modules and scripts. However, publishing a module or executing a script are separate VM operations.

## Syntax

### Scripts

A script has the following structure:
```
script {
    <use>*
    <constants>*
    fun <identifier><[type parameters: constraint]*>([identifier: type]*) <function_body>
}
```
A `script` block must start with all of its [use](./uses.md) declarations, followed by any [constants](./constants.md) and (finally) the main
[function](./functions.md) declaration.
The main function can have any name (i.e., it need not be called `main`), is the only function in a script block, can have any number of
arguments, and must not return a value. Here is an example with each of these components:
```rust
script {
    // Import the Debug module published at account address 0x1.
    // 0x1 is shorthand for the fully qualified address
    // 0x00000000000000000000000000000001.
    use 0x1::Debug;

    const ONE: u64 = 1;

    fun main(x: u64) {
        let sum = x + ONE;
        Debug::print(&sum)
    }
}
```

Scripts have very limited power--they cannot declare struct types or access global storage. Their primary purpose is invoke module functions.

### Modules

A Module has the following syntax:
```
address <address_const> {
module <identifier> {
    (<use> | <type> | <function> | <constant>)*
}
}
```

For example:
```rust
address 0x42 {
module Test {
    resource struct Example { i: u64 }

    use 0x1::Debug;

    const ONE: u64 = 1;

    public fun print(x: u64) {
        let sum = x + ONE;
        let example = Example { i: sum };
        Debug::print(&sum)
    }
}
}
```

The `address 0x42` part specifies that the module will be published under the [account address](./address.md) 0x42 in [global storage](./global-storage-structure.md).

Multiple modules can be declared in a single `address` block:

```rust
address 0x42 {
module M { ... }
module N { ... }
}
```
Module names can start with letters `a` to `z` or letters `A` to `Z`. After the first character, module names can contain underscores `_`, letters `a` to `z`, letters `A` to `Z`, or digits `0` to `9`.
```rust
module my_module {}
module FooBar42 {}
```
Typically, module names start with an uppercase letter. A module named `MyModule` should be stored in a source file named `MyModule.move`.


All elements inside a `module` block can appear in any order.
Fundamentally, a module is a collection of [`types`](./structs-and-resources.md) and
[`functions`](./functions.md). [Uses](./uses.md) import types from other modules. [Constants](./constants.md) define private constants that can be used in the functions of a module.
