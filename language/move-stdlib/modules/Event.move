/// The Event module defines an `EventHandleGenerator` that is used to create
/// `EventHandle`s with unique GUIDs. It contains a counter for the number
/// of `EventHandle`s it generates. An `EventHandle` is used to count the number of
/// events emitted to a handle and emit events to the event store.
module Std::Event {
    use Std::Errors;
    use Std::BCS;
    use Std::Signer;
    use Std::Vector;

    /// A resource representing the counter used to generate uniqueness under each account. There won't be destructor for
    /// this resource to guarantee the uniqueness of the generated handle.
    struct EventHandleGenerator has key {
        // A monotonically increasing counter
        counter: u64,
        addr: address,
    }

    /// A handle for an event such that:
    /// 1. Other modules can emit events to this handle.
    /// 2. Storage can use this handle to prove the total number of events that happened in the past.
    struct EventHandle<phantom T: drop + store> has store {
        /// Total number of events emitted to this event stream.
        counter: u64,
        /// A globally unique ID for this event stream.
        guid: vector<u8>,
    }

    /// The event generator resource was in an invalid state
    const EEVENT_GENERATOR: u64 = 0;

    /// Publishs a new event handle generator.
    public fun publish_generator(account: &signer) {
        let addr = Signer::address_of(account);
        assert(!exists<EventHandleGenerator>(addr), Errors::already_published(EEVENT_GENERATOR));
        move_to(account, EventHandleGenerator{ counter: 0, addr })
    }

    /// Derive a fresh unique id by using sender's EventHandleGenerator. The generated vector<u8> is indeed unique because it
    /// was derived from the hash(sender's EventHandleGenerator || sender_address). This module guarantees that the
    /// EventHandleGenerator is only going to be monotonically increased and there's no way to revert it or destroy it. Thus
    /// such counter is going to give distinct value for each of the new event stream under each sender. And since we
    /// hash it with the sender's address, the result is guaranteed to be globally unique.
    fun fresh_guid(counter: &mut EventHandleGenerator): vector<u8> {
        let sender_bytes = BCS::to_bytes(&counter.addr);
        let count_bytes = BCS::to_bytes(&counter.counter);
        counter.counter = counter.counter + 1;

        // EventHandleGenerator goes first just in case we want to extend address in the future.
        Vector::append(&mut count_bytes, sender_bytes);

        count_bytes
    }

    /// Use EventHandleGenerator to generate a unique event handle for `sig`
    public fun new_event_handle<T: drop + store>(account: &signer): EventHandle<T>
    acquires EventHandleGenerator {
        let addr = Signer::address_of(account);
        assert(exists<EventHandleGenerator>(addr), Errors::not_published(EEVENT_GENERATOR));
        EventHandle<T> {
            counter: 0,
            guid: fresh_guid(borrow_global_mut<EventHandleGenerator>(addr))
        }
    }

    /// Emit an event with payload `msg` by using `handle_ref`'s key and counter.
    public fun emit_event<T: drop + store>(handle_ref: &mut EventHandle<T>, msg: T) {
        let guid = *&handle_ref.guid;

        write_to_event_store<T>(guid, handle_ref.counter, msg);
        handle_ref.counter = handle_ref.counter + 1;
    }

    /// Native procedure that writes to the actual event stream in Event store
    /// This will replace the "native" portion of EmitEvent bytecode
    native fun write_to_event_store<T: drop + store>(guid: vector<u8>, count: u64, msg: T);

    /// Destroy a unique handle.
    public fun destroy_handle<T: drop + store>(handle: EventHandle<T>) {
        EventHandle<T> { counter: _, guid: _ } = handle;
    }

    // ****************** SPECIFICATIONS *******************
    spec module {} // switch documentation context to module

    spec module {
        /// Functions of the event module are mocked out using the intrinsic
        /// pragma. They are implemented in the prover's prelude.
        pragma intrinsic = true;

        /// Determines equality between the guids of two event handles. Since fields of intrinsic
        /// structs cannot be accessed, this function is provided.
        fun spec_guid_eq<T>(h1: EventHandle<T>, h2: EventHandle<T>): bool {
            // The implementation currently can just use native equality since the mocked prover
            // representation does not have the `counter` field.
            h1 == h2
        }
    }
}
