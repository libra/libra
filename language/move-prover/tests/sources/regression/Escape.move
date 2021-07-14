address 0x1 {

module Escape {
    use Std::Signer;

    struct IndoorThing has key, store { }

    struct OutdoorThing has key, store { }

    struct Wrapper<Thing: key + store> has key { thing: Thing }

    public fun initialize(account: &signer) {
        let owner = Signer::address_of(account);
        assert(owner == @0x123, 0);
        move_to<Wrapper<IndoorThing>>(account, Wrapper{ thing: IndoorThing {} });
        move_to<Wrapper<OutdoorThing>>(account, Wrapper { thing: OutdoorThing {}});
    }

   public fun new_outdoor_thing(): OutdoorThing {
        OutdoorThing { }
    }

    /// Calling module can install whatever object.
    public fun install<Thing: key + store>(account: &signer, thing: Thing) {
        move_to<Wrapper<Thing>>(account, Wrapper{ thing });
    }

    // TODO: Those both invariants fail, because install can violate them. The prover could know,
    // however, that `IndoorThing` can never escape this module, and can therefore never be
    // passed into `install`. This "escape" analysis is currently not performed.
    invariant forall addr: address where exists<Wrapper<IndoorThing>>(addr): addr == @0x123;
    invariant forall addr: address where exists<Wrapper<OutdoorThing>>(addr): addr == @0x123;

}

}
