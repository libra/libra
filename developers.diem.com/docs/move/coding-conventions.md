---
id: move-coding-conventions
title: Move Coding Conventions
sidebar_label: Coding Conventions
---

This section lays out some basic coding conventions for Move that the Move team has found helpful. These are only recommendations, and you should feel free to use other formatting guidelines and conventions if you have a preference for them.

## Naming
- **Module names**: should be camel case, e.g., `FixedPoint32`, `Vector`
- **Type names**: should be camel case if they are not a native type, e.g., `Coin`, `RoleId`
- **Function names**: should be lower snake case, e.g., `destroy_empty`
- **Constant names**: should be upper snake case, e.g., `REQUIRES_CAPABILITY`
- Generic types should be descriptive, or anti-descriptive where appropriate, e.g., `T` or `Element` for the Vector generic type parameter. Most of the time the "main" type in a module should be the same name as the module e.g., `Option::Option`, `FixedPoint32::FixedPoint32`.
- **Module file names**: should be the same as the module name e.g., `Option.move`
- **Script file names**: should be lower snake case and should match the name of the “main” function in the script.
- **Mixed file names**: If the file contains multiple modules and/or scripts, the file name should be lower_snake_case, where the name does not match any particular module/script inside.

## Imports
- All module `use` statements should be at the top of the module.
- Functions should be imported and used fully qualified from the module in which they are declared, and not imported at the top level.
- Types should be imported at the top-level. Where there are name clashes, `as` should be used to rename the type locally as appropriate.

For example, if there is a module
```rust=
module Foo {
    resource struct Foo { }
    const CONST_FOO: u64 = 0;
    public fun do_foo(): Foo { Foo{} }
    ...
}
```

this would be imported and used as:

```rust=
module Bar {
    use 0x1::Foo::{Self, Foo};

    public fun do_bar(x: u64): Foo {
        if (x == 10) {
            Foo::do_foo()
        } else {
            abort 0
        }
    }
    ...
}
```

And, if there is a local name-clash when importing two modules:

```rust=
module OtherFoo {
    resource struct Foo {}
    ...
}

module Importer {
    use 0x1::OtherFoo::Foo as OtherFoo;
    use 0x1::Foo::Foo;
....
}
```


## Comments

- Each module, struct, resource, and public function declaration should be commented
- Move has both doc comments `///`, regular single-line comments `//`, and block comments `/* */`


## Formatting
The Move team plans to write an autoformatter to enforce formatting conventions. However, in the meantime:

- Four space indentation should be used except for `script` and `address` blocks whose contents should not be indented
- Lines should be broken if they are longer than 100 characters
- Resources, structs, and constants should be declared before all functions in a module
