---
id: move-global-storage-structure
title: Global Storage - Structure
sidebar_label: Global Storage Structure
---

The purpose of Move programs is to [read from and write to](./global-storage-operators.md) tree-shaped persistent global storage. Programs cannot access the filesystem, network, or any other data outside of this tree.

In pseudocode, the global storage looks something like

```rust
struct GlobalStorage {
  resources: Map<(address, ResourceType), ResourceValue>
  modules: Map<(address, ModuleName), ModuleBytecode>
}
```

Structurally, global storage is a [forest](https://en.wikipedia.org/wiki/Tree_(graph_theory)) consisting of trees rooted at an account [`address`](./address.md). Each address can store both [resource](./structs-and-resources.md) data values and [module](./modules-and-scripts.md) code values. As the pseudocode above indicates, each `address` can store at most one resource value of a given type and at most one module with a given name.
