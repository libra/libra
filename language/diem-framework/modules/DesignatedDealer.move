/// Module providing functionality for designated dealers.
module DiemFramework::DesignatedDealer {
    use DiemFramework::Diem;
    use DiemFramework::Roles;
    use DiemFramework::XUS::XUS;
    use Std::Errors;
    use Std::Event;
    use Std::Signer;

    /// A `DesignatedDealer` always holds this `Dealer` resource regardless of the
    /// currencies it can hold. All `ReceivedMintEvent` events for all
    /// currencies will be emitted on `mint_event_handle`.
    struct Dealer has key {
        /// Handle for mint events
        mint_event_handle: Event::EventHandle<ReceivedMintEvent>,
    }

    spec schema AbortsIfNoDealer {
        dd_addr: address;
        aborts_if !exists<Dealer>(dd_addr) with Errors::NOT_PUBLISHED;
    }

    /// The `TierInfo` resource holds the information needed to track which
    /// tier a mint to a DD needs to be in.
    /// DEPRECATED: This resource is no longer used and will be removed from the system
    // PreburnQueue published at top level in Diem.move
    struct TierInfo<phantom CoinType> has key {
        /// Time window start in microseconds
        window_start: u64,
        /// The minted inflow during this time window
        window_inflow: u64,
        /// 0-indexed array of tier upperbounds
        tiers: vector<u64>,
    }

    /// Message for mint events
    struct ReceivedMintEvent has drop, store {
        /// The currency minted
        currency_code: vector<u8>,
        /// The address that receives the mint
        destination_address: address,
        /// The amount minted (in base units of `currency_code`)
        amount: u64,
    }

    /// The `DesignatedDealer` resource is in an invalid state
    const EDEALER: u64 = 0;
    // Error codes 1 -- 3 were deprecated along with tiered minting in Diem Framework version 2
    // const EINVALID_TIER_ADDITION: u64 = 1;
    // const EINVALID_TIER_START: u64 = 2;
    // const EINVALID_TIER_INDEX: u64 = 3;
    /// A zero mint amount was provided
    const EINVALID_MINT_AMOUNT: u64 = 4;

    ///////////////////////////////////////////////////////////////////////////
    // To-be designated-dealer called functions
    ///////////////////////////////////////////////////////////////////////////

    /// Publishes a `Dealer` resource under `dd` with a `PreburnQueue`.
    /// If `add_all_currencies = true` this will add a `PreburnQueue`,
    /// for each known currency at launch.
    public fun publish_designated_dealer_credential<CoinType>(
        dd: &signer,
        tc_account: &signer,
        add_all_currencies: bool,
    ){
        Roles::assert_treasury_compliance(tc_account);
        Roles::assert_designated_dealer(dd);
        assert(!exists<Dealer>(Signer::address_of(dd)), Errors::already_published(EDEALER));
        move_to(dd, Dealer { mint_event_handle: Event::new_event_handle<ReceivedMintEvent>(dd) });
        if (add_all_currencies) {
            add_currency<XUS>(dd, tc_account);
        } else {
            add_currency<CoinType>(dd, tc_account);
        };
    }
    spec publish_designated_dealer_credential {
        pragma opaque;

        let dd_addr = Signer::spec_address_of(dd);

        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        include Roles::AbortsIfNotDesignatedDealer{account: dd};
        aborts_if exists<Dealer>(dd_addr) with Errors::ALREADY_PUBLISHED;
        include if (add_all_currencies) AddCurrencyAbortsIf<XUS>{dd_addr: dd_addr}
                else AddCurrencyAbortsIf<CoinType>{dd_addr: dd_addr};

        modifies global<Dealer>(dd_addr);
        ensures exists<Dealer>(dd_addr);
        modifies global<Event::EventHandleGenerator>(dd_addr);
        modifies global<Diem::PreburnQueue<CoinType>>(dd_addr);
        modifies global<Diem::PreburnQueue<XUS>>(dd_addr);
    }

    ///////////////////////////////////////////////////////////////////////////
    // Publicly callable APIs by Treasury Compliance Account
    ///////////////////////////////////////////////////////////////////////////

    /// Adds the needed resources to the DD account `dd` in order to work with `CoinType`.
    /// Public so that a currency can be added to a DD later on. Will require
    /// multi-signer transactions in order to add a new currency to an existing DD.
    public fun add_currency<CoinType>(dd: &signer, tc_account: &signer) {
        Roles::assert_treasury_compliance(tc_account);
        let dd_addr = Signer::address_of(dd);
        assert(exists_at(dd_addr), Errors::not_published(EDEALER));
        Diem::publish_preburn_queue_to_account<CoinType>(dd, tc_account);
    }
    spec add_currency {
        pragma opaque;

        let dd_addr = Signer::spec_address_of(dd);

        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        include Roles::AbortsIfNotDesignatedDealer{account: dd};
        include AbortsIfNoDealer{dd_addr: dd_addr};
        include AddCurrencyAbortsIf<CoinType>{dd_addr: dd_addr};

        modifies global<Diem::PreburnQueue<CoinType>>(dd_addr);
    }
    spec schema AddCurrencyAbortsIf<CoinType> {
        dd_addr: address;
        include Diem::AbortsIfNoCurrency<CoinType>;
        aborts_if Diem::is_synthetic_currency<CoinType>() with Errors::INVALID_ARGUMENT;
        aborts_if exists<Diem::PreburnQueue<CoinType>>(dd_addr) with Errors::ALREADY_PUBLISHED;
        aborts_if exists<Diem::Preburn<CoinType>>(dd_addr) with Errors::INVALID_STATE;
    }

    public fun tiered_mint<CoinType>(
        tc_account: &signer,
        amount: u64,
        dd_addr: address,
        // tiers are deprecated. We continue to accept this argument for backward
        // compatibility, but it will be ignored.
        _tier_index: u64,
    ): Diem::Diem<CoinType> acquires Dealer, TierInfo {
        Roles::assert_treasury_compliance(tc_account);
        assert(amount > 0, Errors::invalid_argument(EINVALID_MINT_AMOUNT));
        assert(exists_at(dd_addr), Errors::not_published(EDEALER));

        // Delete deprecated `TierInfo` resources.
        // TODO: delete this code once there are no more TierInfo resources in the system
        if (exists<TierInfo<CoinType>>(dd_addr)) {
            let TierInfo { window_start: _, window_inflow: _, tiers: _ } = move_from<TierInfo<CoinType>>(dd_addr);
        };

        // Send ReceivedMintEvent
        Event::emit_event<ReceivedMintEvent>(
            &mut borrow_global_mut<Dealer>(dd_addr).mint_event_handle,
            ReceivedMintEvent {
                currency_code: Diem::currency_code<CoinType>(),
                destination_address: dd_addr,
                amount
            },
        );
        Diem::mint<CoinType>(tc_account, amount)
    }
    spec tiered_mint {
        pragma opaque;

        include TieredMintAbortsIf<CoinType>;

        modifies global<Dealer>(dd_addr);
        modifies global<Diem::CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures exists<Diem::CurrencyInfo<CoinType>>(@CurrencyInfo);
        modifies global<TierInfo<CoinType>>(dd_addr);
        ensures !exists<TierInfo<CoinType>>(dd_addr);
        let currency_info = global<Diem::CurrencyInfo<CoinType>>(@CurrencyInfo);
        let post post_currency_info = global<Diem::CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures result.value == amount;
        ensures post_currency_info == update_field(currency_info, total_value, currency_info.total_value + amount);
    }
    spec schema TieredMintAbortsIf<CoinType> {
        tc_account: signer;
        dd_addr: address;
        amount: u64;
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        aborts_if amount == 0 with Errors::INVALID_ARGUMENT;
        include AbortsIfNoDealer;
        aborts_if !exists<Diem::MintCapability<CoinType>>(Signer::spec_address_of(tc_account)) with Errors::REQUIRES_CAPABILITY;
        include Diem::MintAbortsIf<CoinType>{value: amount};
    }

    public fun exists_at(dd_addr: address): bool {
        exists<Dealer>(dd_addr)
    }
    spec exists_at {
        pragma opaque;
        aborts_if false;
        ensures result == exists<Dealer>(dd_addr);
    }

    // =================================================================
    // Module Specification

    spec module {} // Switch to module documentation context

    spec module {
        /// resource struct Dealer persists after publication
        invariant update forall addr: address where old(exists<Dealer>(addr)): exists<Dealer>(addr);
    }

}
