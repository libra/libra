---
id: move-tutorial-creating-coins
title: Tutorial - Creating Coins
sidebar_label: Creating Coins
---

Move is a language about resources. Resources are special types of values that cannot be copied or forgotten about; they must always be moved from one place to another.

Resources are a valuable tool for representing things that should be scarce like assets. For a cryptocurrency, the value of a coin that can be copied is nothing, and you'd like to know that smart contracts you write don't accidentally lose resources. Move makes resources a first class primitive in the language, and enforces many invariants useful for scarce values.

In this first tutorial, we'll implement a simple coin and show off some of the ways that Move helps write correct code when creating, manipulating, and destroying coins.

Let's get started!

## Modules and Scripts

Move code can exist in two forms, as modules or as transaction scripts.

Move modules contain type definitions and code and expose these through a set of public functions that operate on those types. Modules are published at specific address, and that address is part of the fully qualified module name. Most Move code you will write will be in the form of modules.

Transaction scripts are functions that can take any number of arguments and return nothing. These can call any published module's public functions attempt to achieve a specific change in the global state. Scripts only change global state if they are successful; if they abort any changes they have previously made will be discarded.

To make this concrete, we're going to create a module `0x2::Coin` which defines a simple digital coin and some public functions for managing coins. After publishing this module, we'll use transaction scripts to interact with it.

## Move CLI and Project Structure

Before we jump into the code, let's install the Move CLI and talk briefly about project structure.

To install the Move CLI just use `cargo install`. If you don't already have a Rust toolchain installed, you should install [Rustup](https://rustup.rs/) which will install the latest stable toolchain.

```shell
$ cargo install --git https://github.com/diem/diem move-cli
```

This will install the `move` binary in your Cargo binary directory. On macOS and Linux this is usually `~/.cargo/bin`. You'll want to make sure this location is in your `PATH` environment variable.

Now you should be able to run the Move CLI:

```shell
$ move
Move 0.1.0
CLI frontend for Move compiler and VM

USAGE:
    move [FLAGS] [OPTIONS] <SUBCOMMAND>
  ...
```

Let's create a directory for our new Move project:

```shell
$ mkdir toycoin
$ cd toycoin
$ mkdir -p src/modules
$ mkdir -p src/scripts
```

We've created a directory called `toycoin` which has a subdirectory `src` for the modules we'll create as well as the transaction scripts. Now we can write some code!

## Creating Our Coin

We'll call our module `Coin`, and we'll publish it at address `0x2`. By convention, the Move standard library is published at address `0x1`, and for simplicity we'll use `0x2` for our tutorial code. Any address will work, as long as the address the modules are published to and the address the modules are accessed from is the same.

In our module we'll define a new type `Coin`, which will be a structure with a single field `value`, containing the number of coins. The type of the `value` field is `u64`, which is, as you might have guessed, an unsigned 64-bit integer.

Our module `Coin`, and our type `Coin` both share the same name, and this is another convention used by Move programmers to name the main type in a module the same as the module itself. This doesn't cause a problem as in the Move language as the context of where `Coin` appears will always make the name unambiguous.

Here's a first draft of our `Coin` module, which we'll define in `src/modules/Coin.move`:

```=
address 0x2 {
    module Coin {

        struct Coin {
            value: u64,
        }

    }
}
```

In order to publish our module, we use the Move CLI:

```shell
$ move publish src/modules
```

To test our `Coin` module we'll createa small script that creates a value of our `Coin` type. The following code should go into `src/scripts/test-coin.move`:

```=
script {

    use 0x2::Coin::Coin;

    fun main() {
        let _coin = Coin { value: 100 };
    }

}
```

First, on line 3, we must import the type. Note that the full location and name of the type includes the address and the module. After this `use` statement, we may refer to the type by its short name `Coin`.

Scripts contain a single function definition that has no return value. The function can take any number of arguments and type arguments, but for our purposes we don't need any arguments at all.

On line 6, we use `let` to bind the variable `_coin` to a constructed value of 100 coin. Note that we prefix the variable name with an underscore to signal to the compiler that we don't intend to use this variable. In a real program, we'd remove the underscore and the variable would get used later in the program.

Let's run our scripts `test-coin.move` with the Move CLI:

```shell
$ move run src/scripts/test-coin.move
error:

   ┌── scripts/test-coin.move:6:20 ───
   │
 6 │         let coin = Coin::Coin { value: 100 };
   │                    ^^^^^^^^^^^^^^^^^^^^^^^^^ Invalid instantiation of '0x1::Coin::Coin'.
All structs can only be constructed in the module in which they are declared
   │
```

Uh oh! Something went wrong! The error message tells us that we can't construct values of this type in scripts. Only the module itself may construct a `Coin`.

We'll have to add a constructor to our module to do this.

### Minting

Let's create a function in `Coin.move` to create coins. We'll call our function `mint`.


```=
address 0x2 {
    module Coin {

        struct Coin {
            value: u64,
        }

        public fun mint(value: u64): Coin {
            Coin { value }
        }

    }
}
```

We declare the function public to indicate that other modules and scripts are allowed to call it. Functions that are not public can only be called from within the same module.

Our function takes a `u64` value and returns the constructed `Coin`.

Remember to always re-publish your module after making changes, otherwise our script won't be able to catch those changes.

With this change, we should be able to update our script `test-coin.move` to call our new constructor:


```=
script {

    use 0x2::Coin;

    fun main() {
        let _coin = Coin::mint(100);
    }

}
```

Let's run our script:

```shell
$ move run src/scripts/test-coin.move
```

The script didn't fail this time. There's no output since we didn't generate any. However, there is another problem you may have noticed.

### Disappearing Coins

After we minted a coin, where did it go?

The answer is that it just disappeared into the ether. The local variable that held the coin went out of scope at the end of our script, and the coin ceased to exist. If coin had real value, this would be very bad, as it means if you weren't very careful about making sure you used the coin somehow, it might disappear and the value it represented would be lost forever.

Move is designed around the concept of resources. Resources behave like money or an asset in that they can only be moved around, never copied. In addition, while we've seen that Move already restricts the construction of types, resources must have controlled destruction as well. Only the module that defines a resource type is able to destroy that type.

We can convert our `Coin` into a resource just by adding the `resource` keyword to our type definition in `Coin.move`:


```=
        resource struct Coin {
            value: u64,
        }
```

Let's publish our `Coin` module again and re-run our script:

```shell
$ move publish src/modules
$ move run src/scripts/test-coin.move
error:

   ┌── scripts/test-coin.move:6:13 ───
   │
 6 │         let _coin = Coin::mint(100);
   │             ^^^^^ Cannot ignore resource values. The value must be used
   │

    ┌── move_build_output/mv_interfaces/00000000000000000000000000000001/Coin.move:6:5 ───
    │
 11 │     native public fun mint(a0: u64): Coin::Coin;
    │                                      ---------- The type: '0x1::Coin::Coin'
    ·
  6 │     resource struct Coin {
    │     -------- Is found to be a non-copyable type here
    │
 ```

 Now we have a different error! The Move compiler is telling us that it is invalid to ignore a resource value. If ignored, the value would just disappear, but since it is a resource type, we must do something with it. We must move it somewhere.

 Let's create a a `burn` function that will destroy coins as well as a function to retrieve the value of a coin. Add the following functions to `Coin.move`:


 ```=
         public fun value(coin: &Coin): u64 {
            coin.value
        }

        public fun burn(coin: Coin): u64 {
            let Coin { value: value } = coin;
            value
        }

```

These are both declared public so they can be used by scripts and other modules.

Notice that `value` takes a reference to a `Coin`. This is a read-only value, but more critically, when passing a reference to a function the value is not moved. Compare this to `burn` which takes an actual `Coin` value. Calling this function with a coin will move the coin into the function and out of the caller's scope.

The `value` function simply returns the internal `u64` value. Scripts and other modules can't directly access the interior fields of a module's types, so we need public accessor functions if that data should be available outside the module.

The `burn` function uses pattern matching to unpack the `Coin` into just its internal value. This essentially destroys the resource and returns a normal `u64` value. We return the value of the coin to let the caller know how much money just disappeared. (see [Structs and Resources](./structs-and-resources.md#destroying-structs-via-pattern-matching))

Now we can write a slightly more complicated script that tests our `Coin` module. We'll mint a coin, display its value, and then burn it. Add this code to `src/scripts/test-burn.move`:

```=
script {

    use 0x1::Debug;
    use 0x2::Coin;

    fun main() {
        let coin = Coin::mint(100);

        Debug::print(&Coin::value(&coin));

        Coin::burn(coin);
    }

}
```

Give it a try with `move run`:

```shell
$ move run src/scripts/test-burn.move
[debug] 100
```

The only new thing in our script is the use of the standard library function `Debug::print` which takes a reference to a type and prints a human readable string respresentation of it.

Note that we pass references using `&` to `Debug::print` and `Coin::value`. Also, since we move `coin` into the `burn` function, it no longer exists in our script's scope and because our script compiles we can be sure that we didn't accidentally lose some money. The only way to get rid of a coin we create is to move it somewhere else.


# Wrap Up

In this tutorial, we learned how to get the Move CLI and how to use it to publish and run Move code.

Move code is made of up modules, which are published at specific addresses in global storage, and transaction scripts which can call public module functions and cause changes to global storage. These scripts either complete successfully or abort making no changes to global storage.

As we created our first coin, we learned the difference between normal types and resource types, and how the Move compiler and virtual machine enforce invariants about which code can construct types, access fields, and whether values can be copied and destroyed.

In the next tutorial, we'll build on our coin to implement accounts with balances.
