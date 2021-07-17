address 0x2 {
module Coin {
    struct Coin<T: store> has key { f: T, v: u64 }

    public fun coin_exists<T: store>(): bool {
        exists<Coin<T>>(@0x2)
    }

    public fun coin_info<T: store>(): u64 acquires Coin {
        *&borrow_global<Coin<T>>(@0x2).v
    }
}

module XUS {
    struct XUS has store {}
}

module XDX {
    use 0x2::Coin::Coin;
    use 0x2::Coin::coin_exists;
    use 0x2::Coin::coin_info;

    struct XDX has store {}

    spec fun spec_is_xdx<T: store>(): bool {
        exists<Coin<T>>(@0x2) && exists<Coin<XDX>>(@0x2) &&
            global<Coin<T>>(@0x2).v == global<Coin<XDX>>(@0x2).v
    }

    public fun is_xdx<T: store>(): bool {
        coin_exists<T>() && coin_exists<XDX>() &&
            coin_info<T>() == coin_info<XDX>()
    }
    spec is_xdx {
        pragma opaque;
        ensures result == spec_is_xdx<T>();
    }
}

module Check {
    use 0x2::XUS::XUS;
    use 0x2::XDX::XDX;
    use 0x2::XDX::is_xdx;

    public fun check(): bool {
        is_xdx<XUS>() && is_xdx<XDX>()
    }
}
}
