address 0x1:

module Container {
    struct T<V> {}

    public fun new<V>(): T<V> {
        T {}
    }

    public fun get<V: copyable>(self: &T<V>): V {
        abort 0
    }

    public fun put<V>(self: &mut T<V>, item: V) {
        abort 0
    }
}


module M {
    use 0x1::Container;

    struct Box<T> { f1: T, f2: T }
    resource struct R{}


    fun t0(): Box<bool> {
        let v = Container::new();
        let x = Container::get(&v);
        let b = Box { f1: x, f2: x };
        Container::put(&mut v, 0);
        b
    }

    fun t2(): Box<Box<R>> {
        let v = Container::new();
        let x = Container::get(&v);
        let b = Box { f1: x, f2: x };
        Container::put(&mut v, Box {f1: R{}, f2: R{}});
        b
    }
}
