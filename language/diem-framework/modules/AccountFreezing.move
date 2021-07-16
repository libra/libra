/// Module which manages freezing of accounts.
module DiemFramework::AccountFreezing {
    use DiemFramework::DiemTimestamp;
    use DiemFramework::CoreAddresses;
    use DiemFramework::Roles;
    use Std::Event::{Self, EventHandle};
    use Std::Errors;
    use Std::Signer;
    friend DiemFramework::DiemAccount;

    struct FreezingBit has key {
        /// If `is_frozen` is set true, the account cannot be used to send transactions or receive funds
        is_frozen: bool,
    }

    struct FreezeEventsHolder has key {
        freeze_event_handle: EventHandle<FreezeAccountEvent>,
        unfreeze_event_handle: EventHandle<UnfreezeAccountEvent>,
    }

    /// Message for freeze account events
    struct FreezeAccountEvent has drop, store {
        /// The address that initiated freeze txn
        initiator_address: address,
        /// The address that was frozen
        frozen_address: address,
    }

    /// Message for unfreeze account events
    struct UnfreezeAccountEvent has drop, store {
        /// The address that initiated unfreeze txn
        initiator_address: address,
        /// The address that was unfrozen
        unfrozen_address: address,
    }

    /// A property expected of the `FreezeEventsHolder` resource didn't hold
    const EFREEZE_EVENTS_HOLDER: u64 = 1;
    /// The `FreezingBit` resource is in an invalid state
    const EFREEZING_BIT: u64 = 2;
    /// An attempt to freeze the Diem Root account was attempted
    const ECANNOT_FREEZE_DIEM_ROOT: u64 = 3;
    /// An attempt to freeze the Treasury & Compliance account was attempted
    const ECANNOT_FREEZE_TC: u64 = 4;
    /// The account is frozen
    const EACCOUNT_FROZEN: u64 = 5;

    public fun initialize(dr_account: &signer) {
        DiemTimestamp::assert_genesis();
        CoreAddresses::assert_diem_root(dr_account);
        assert(
            !exists<FreezeEventsHolder>(Signer::address_of(dr_account)),
            Errors::already_published(EFREEZE_EVENTS_HOLDER)
        );
        move_to(dr_account, FreezeEventsHolder {
            freeze_event_handle: Event::new_event_handle(dr_account),
            unfreeze_event_handle: Event::new_event_handle(dr_account),
        });
    }
    spec initialize {
        include DiemTimestamp::AbortsIfNotGenesis;
        include CoreAddresses::AbortsIfNotDiemRoot{account: dr_account};
        let addr = Signer::spec_address_of(dr_account);
        aborts_if exists<FreezeEventsHolder>(addr) with Errors::ALREADY_PUBLISHED;
        ensures exists<FreezeEventsHolder>(addr);
    }

    public(friend) fun create(account: &signer) {
        let addr = Signer::address_of(account);
        assert(!exists<FreezingBit>(addr), Errors::already_published(EFREEZING_BIT));
        move_to(account, FreezingBit { is_frozen: false })
    }
    spec create {
        let addr = Signer::spec_address_of(account);
        modifies global<FreezingBit>(addr);
        aborts_if exists<FreezingBit>(addr) with Errors::ALREADY_PUBLISHED;
        ensures spec_account_is_not_frozen(addr);
    }

    /// Freeze the account at `addr`.
    public fun freeze_account(
        account: &signer,
        frozen_address: address,
    )
    acquires FreezingBit, FreezeEventsHolder {
        DiemTimestamp::assert_operating();
        Roles::assert_treasury_compliance(account);
        // The diem root account and TC cannot be frozen
        assert(frozen_address != @DiemRoot, Errors::invalid_argument(ECANNOT_FREEZE_DIEM_ROOT));
        assert(frozen_address != @TreasuryCompliance, Errors::invalid_argument(ECANNOT_FREEZE_TC));
        assert(exists<FreezingBit>(frozen_address), Errors::not_published(EFREEZING_BIT));
        borrow_global_mut<FreezingBit>(frozen_address).is_frozen = true;
        let initiator_address = Signer::address_of(account);
        Event::emit_event<FreezeAccountEvent>(
            &mut borrow_global_mut<FreezeEventsHolder>(@DiemRoot).freeze_event_handle,
            FreezeAccountEvent {
                initiator_address,
                frozen_address
            },
        );
    }
    spec freeze_account {
        include DiemTimestamp::AbortsIfNotOperating;
        include Roles::AbortsIfNotTreasuryCompliance;
        aborts_if frozen_address == @DiemRoot with Errors::INVALID_ARGUMENT;
        aborts_if frozen_address == @TreasuryCompliance with Errors::INVALID_ARGUMENT;
        aborts_if !exists<FreezingBit>(frozen_address) with Errors::NOT_PUBLISHED;
        ensures spec_account_is_frozen(frozen_address);
        include FreezeAccountEmits;
    }
    spec schema FreezeAccountEmits {
        account: &signer;
        frozen_address: address;
        let handle = global<FreezeEventsHolder>(@DiemRoot).freeze_event_handle;
        let msg = FreezeAccountEvent {
            initiator_address: Signer::spec_address_of(account),
            frozen_address
        };
        emits msg to handle;
    }

    /// Unfreeze the account at `addr`.
    public fun unfreeze_account(
        account: &signer,
        unfrozen_address: address,
    )
    acquires FreezingBit, FreezeEventsHolder {
        DiemTimestamp::assert_operating();
        Roles::assert_treasury_compliance(account);
        assert(exists<FreezingBit>(unfrozen_address), Errors::not_published(EFREEZING_BIT));
        borrow_global_mut<FreezingBit>(unfrozen_address).is_frozen = false;
        let initiator_address = Signer::address_of(account);
        Event::emit_event<UnfreezeAccountEvent>(
            &mut borrow_global_mut<FreezeEventsHolder>(@DiemRoot).unfreeze_event_handle,
            UnfreezeAccountEvent {
                initiator_address,
                unfrozen_address
            },
        );
    }
    spec unfreeze_account {
        include DiemTimestamp::AbortsIfNotOperating;
        include Roles::AbortsIfNotTreasuryCompliance;
        aborts_if !exists<FreezingBit>(unfrozen_address) with Errors::NOT_PUBLISHED;
        ensures !spec_account_is_frozen(unfrozen_address);
        include UnfreezeAccountEmits;
    }
    spec schema UnfreezeAccountEmits {
        account: &signer;
        unfrozen_address: address;
        let handle = global<FreezeEventsHolder>(@DiemRoot).unfreeze_event_handle;
        let msg = UnfreezeAccountEvent {
            initiator_address: Signer::spec_address_of(account),
            unfrozen_address
        };
        emits msg to handle;
    }

    /// Returns if the account at `addr` is frozen.
    public fun account_is_frozen(addr: address): bool
    acquires FreezingBit {
        exists<FreezingBit>(addr) && borrow_global<FreezingBit>(addr).is_frozen
     }
    spec account_is_frozen {
        aborts_if false;
        pragma opaque = true;
        ensures result == spec_account_is_frozen(addr);
    }

    /// Assert that an account is not frozen.
    public fun assert_not_frozen(account: address) acquires FreezingBit {
        assert(!account_is_frozen(account), Errors::invalid_state(EACCOUNT_FROZEN));
    }
    spec assert_not_frozen {
        pragma opaque;
        include AbortsIfFrozen;
    }
    spec schema AbortsIfFrozen {
        account: address;
        aborts_if spec_account_is_frozen(account) with Errors::INVALID_STATE;
    }


    // =================================================================
    // Module Specification

    spec module {} // Switch to module documentation context

    /// # Initialization
    spec module {
        /// `FreezeEventsHolder` always exists after genesis.
        invariant DiemTimestamp::is_operating() ==>
            exists<FreezeEventsHolder>(@DiemRoot);
    }

    /// # Access Control
    spec module {
        /// The account of DiemRoot is not freezable [[F1]][ROLE].
        /// After genesis, FreezingBit of DiemRoot is always false.
        invariant DiemTimestamp::is_operating() ==>
            spec_account_is_not_frozen(@DiemRoot);

        /// The account of TreasuryCompliance is not freezable [[F2]][ROLE].
        /// After genesis, FreezingBit of TreasuryCompliance is always false.
        invariant DiemTimestamp::is_operating() ==>
            spec_account_is_not_frozen(@TreasuryCompliance);

        /// resource struct FreezingBit persists
        invariant update forall addr: address where old(exists<FreezingBit>(addr)): exists<FreezingBit>(addr);

        /// resource struct FreezeEventsHolder is there forever after initialization
        invariant update DiemTimestamp::is_operating() ==> exists<FreezeEventsHolder>(@DiemRoot);

        /// The permission "{Freeze,Unfreeze}Account" is granted to TreasuryCompliance only [[H7]][PERMISSION].
        apply Roles::AbortsIfNotTreasuryCompliance to freeze_account, unfreeze_account;

        /// Only (un)freeze functions can change the freezing bits of accounts [[H7]][PERMISSION].
        apply FreezingBitRemainsSame to * except freeze_account, unfreeze_account;
    }

    spec schema FreezingBitRemainsSame {
        ensures forall addr: address where old(exists<FreezingBit>(addr)):
            global<FreezingBit>(addr).is_frozen == old(global<FreezingBit>(addr).is_frozen);
    }

    /// # Helper Functions
    spec module {

        fun spec_account_is_frozen(addr: address): bool {
            exists<FreezingBit>(addr) && global<FreezingBit>(addr).is_frozen
        }

        fun spec_account_is_not_frozen(addr: address): bool {
            exists<FreezingBit>(addr) && !global<FreezingBit>(addr).is_frozen
        }
    }

}
