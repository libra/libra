/// The `Diem` module describes the concept of a coin in the Diem framework. It introduces the
/// resource `Diem::Diem<CoinType>`, representing a coin of given coin type.
/// The module defines functions operating on coins as well as functionality like
/// minting and burning of coins.
module DiemFramework::Diem {
    use DiemFramework::CoreAddresses;
    use DiemFramework::RegisteredCurrencies;
    use DiemFramework::Roles;
    use DiemFramework::DiemTimestamp;
    use Std::Errors;
    use Std::Event::{Self, EventHandle};
    use Std::FixedPoint32::{Self, FixedPoint32};
    use Std::Signer;
    use Std::Vector;

    /// The `Diem` resource defines the Diem coin for each currency in
    /// Diem. Each "coin" is coupled with a type `CoinType` specifying the
    /// currency of the coin, and a `value` field specifying the value
    /// of the coin (in the base units of the currency `CoinType`
    /// and specified in the `CurrencyInfo` resource for that `CoinType`
    /// published under the `@CurrencyInfo` account address).
    struct Diem<phantom CoinType> has store {
        /// The value of this coin in the base units for `CoinType`
        value: u64
    }

    /// The `MintCapability` resource defines a capability to allow minting
    /// of coins of `CoinType` currency by the holder of this capability.
    /// This capability is held only either by the `@TreasuryCompliance`
    /// account or the `DiemFramework::XDX` module (and `@DiemRoot` in testnet).
    struct MintCapability<phantom CoinType> has key, store { }

    /// The `BurnCapability` resource defines a capability to allow coins
    /// of `CoinType` currency to be burned by the holder of it.
    struct BurnCapability<phantom CoinType> has key, store { }

    /// A `MintEvent` is emitted every time a Diem coin is minted. This
    /// contains the `amount` minted (in base units of the currency being
    /// minted) along with the `currency_code` for the coin(s) being
    /// minted, and that is defined in the `currency_code` field of the
    /// `CurrencyInfo` resource for the currency.
    struct MintEvent has drop, store {
        /// Funds added to the system
        amount: u64,
        /// ASCII encoded symbol for the coin type (e.g., "XDX")
        currency_code: vector<u8>,
    }

    /// A `BurnEvent` is emitted every time a non-synthetic Diem coin
    /// (i.e., a Diem coin with false `is_synthetic` field) is
    /// burned. It contains the `amount` burned in base units for the
    /// currency, along with the `currency_code` for the coins being burned
    /// (and as defined in the `CurrencyInfo` resource for that currency).
    /// It also contains the `preburn_address` from which the coin is
    /// extracted for burning.
    struct BurnEvent has drop, store {
        /// Funds removed from the system
        amount: u64,
        /// ASCII encoded symbol for the coin type (e.g., "XDX")
        currency_code: vector<u8>,
        /// Address with the `PreburnQueue` resource that stored the now-burned funds
        preburn_address: address,
    }

    /// A `PreburnEvent` is emitted every time an `amount` of funds with
    /// a coin type `currency_code` is enqueued in the `PreburnQueue` resource under
    /// the account at the address `preburn_address`.
    struct PreburnEvent has drop, store {
        /// The amount of funds waiting to be removed (burned) from the system
        amount: u64,
        /// ASCII encoded symbol for the coin type (e.g., "XDX")
        currency_code: vector<u8>,
        /// Address with the `PreburnQueue` resource that now holds the funds
        preburn_address: address,
    }

    /// A `CancelBurnEvent` is emitted every time funds of `amount` in a `Preburn`
    /// resource held in a `PreburnQueue` at `preburn_address` is canceled (removed from the
    /// preburn queue, but not burned). The currency of the funds is given by the
    /// `currency_code` as defined in the `CurrencyInfo` for that currency.
    struct CancelBurnEvent has drop, store {
        /// The amount of funds returned
        amount: u64,
        /// ASCII encoded symbol for the coin type (e.g., "XDX")
        currency_code: vector<u8>,
        /// Address of the `PreburnQueue` resource that held the now-returned funds.
        preburn_address: address,
    }

    /// An `ToXDXExchangeRateUpdateEvent` is emitted every time the to-XDX exchange
    /// rate for the currency given by `currency_code` is updated.
    struct ToXDXExchangeRateUpdateEvent has drop, store {
        /// The currency code of the currency whose exchange rate was updated.
        currency_code: vector<u8>,
        /// The new on-chain to-XDX exchange rate between the
        /// `currency_code` currency and XDX. Represented in conversion
        /// between the (on-chain) base-units for the currency and microdiem.
        new_to_xdx_exchange_rate: u64,
    }

    /// The `CurrencyInfo<CoinType>` resource stores the various
    /// pieces of information needed for a currency (`CoinType`) that is
    /// registered on-chain. This resource _must_ be published under the
    /// address given by `@CurrencyInfo` in order for the registration of
    /// `CoinType` as a recognized currency on-chain to be successful. At
    /// the time of registration, the `MintCapability<CoinType>` and
    /// `BurnCapability<CoinType>` capabilities are returned to the caller.
    /// Unless they are specified otherwise the fields in this resource are immutable.
    struct CurrencyInfo<phantom CoinType> has key {
        /// The total value for the currency represented by `CoinType`. Mutable.
        total_value: u128,
        /// Value of funds that are in the process of being burned.  Mutable.
        preburn_value: u64,
        /// The (rough) exchange rate from `CoinType` to `XDX`. Mutable.
        to_xdx_exchange_rate: FixedPoint32,
        /// Holds whether or not this currency is synthetic (contributes to the
        /// off-chain reserve) or not. An example of such a synthetic
        ///currency would be the XDX.
        is_synthetic: bool,
        /// The scaling factor for the coin (i.e. the amount to divide by
        /// to get to the human-readable representation for this currency).
        /// e.g. 10^6 for `XUS`
        scaling_factor: u64,
        /// The smallest fractional part (number of decimal places) to be
        /// used in the human-readable representation for the currency (e.g.
        /// 10^2 for `XUS` cents)
        fractional_part: u64,
        /// The code symbol for this `CoinType`. ASCII encoded.
        /// e.g. for "XDX" this is x"584458". No character limit.
        currency_code: vector<u8>,
        /// Minting of new currency of CoinType is allowed only if this field is true.
        /// We may want to disable the ability to mint further coins of a
        /// currency while that currency is still around. This allows us to
        /// keep the currency in circulation while disallowing further
        /// creation of coins in the `CoinType` currency. Mutable.
        can_mint: bool,
        /// Event stream for minting and where `MintEvent`s will be emitted.
        mint_events: EventHandle<MintEvent>,
        /// Event stream for burning, and where `BurnEvent`s will be emitted.
        burn_events: EventHandle<BurnEvent>,
        /// Event stream for preburn requests, and where all
        /// `PreburnEvent`s for this `CoinType` will be emitted.
        preburn_events: EventHandle<PreburnEvent>,
        /// Event stream for all cancelled preburn requests for this
        /// `CoinType`.
        cancel_burn_events: EventHandle<CancelBurnEvent>,
        /// Event stream for emiting exchange rate change events
        exchange_rate_update_events: EventHandle<ToXDXExchangeRateUpdateEvent>,
    }

    /// The maximum value for `CurrencyInfo.scaling_factor`
    const MAX_SCALING_FACTOR: u64 = 10000000000;

    /// Data structure invariant for CurrencyInfo.  Asserts that `CurrencyInfo.scaling_factor`
    /// is always greater than 0 and not greater than `MAX_SCALING_FACTOR`
    spec CurrencyInfo {
        invariant 0 < scaling_factor && scaling_factor <= MAX_SCALING_FACTOR;
    }

    /// A holding area where funds that will subsequently be burned wait while their underlying
    /// assets are moved off-chain.
    /// This resource can only be created by the holder of a `BurnCapability`
    /// or during an upgrade process to the `PreburnQueue` by a designated
    /// dealer. An account that contains this address has the authority to
    /// initiate a burn request. A burn request can be resolved by the holder
    /// of a `BurnCapability` by either (1) burning the funds, or (2) returning
    /// the funds to the account that initiated the burn request.
    struct Preburn<phantom CoinType> has key, store {
        /// A single pending burn amount. This is an element in the
        /// `PreburnQueue` resource published under each Designated Dealer account.
        to_burn: Diem<CoinType>,
    }

    /// A preburn request, along with (an opaque to Move) metadata that is
    /// associated with the preburn request.
    struct PreburnWithMetadata<phantom CoinType> has store {
        preburn: Preburn<CoinType>,
        metadata: vector<u8>,
    }

    /// A queue of preburn requests. This is a FIFO queue whose elements
    /// are indexed by the value held within each preburn resource in the
    /// `preburns` field. When burning or cancelling a burn of a given
    /// `amount`, the `Preburn` resource with with the smallest index in this
    /// queue matching `amount` in its `to_burn` coin's `value` field will be
    /// removed and its contents either (1) burned, or (2) returned
    /// back to the holding DD's account balance. Every `Preburn` resource in
    /// the `PreburnQueue` must have a nonzero coin value within it.
    /// This resource can be created by either the TreasuryCompliance
    /// account, or during the upgrade process, by a designated dealer with an
    /// existing `Preburn` resource in `CoinType`
    struct PreburnQueue<phantom CoinType> has key {
        /// The queue of preburn requests
        preburns: vector<PreburnWithMetadata<CoinType>>,
    }

    spec PreburnQueue {
        /// The number of outstanding preburn requests is bounded.
        invariant len(preburns) <= MAX_OUTSTANDING_PREBURNS;
        /// No preburn request can have a zero value.
        /// The `value` field of any coin in a `Preburn` resource
        /// within this field must be nonzero.
        invariant forall i in 0..len(preburns): preburns[i].preburn.to_burn.value > 0;
    }

    /// Maximum u64 value.
    const MAX_U64: u64 = 18446744073709551615;
    /// Maximum u128 value.
    const MAX_U128: u128 = 340282366920938463463374607431768211455;

    /// A `BurnCapability` resource is in an unexpected state.
    const EBURN_CAPABILITY: u64 = 0;
    /// A property expected of a `CurrencyInfo` resource didn't hold
    const ECURRENCY_INFO: u64 = 1;
    /// A property expected of a `Preburn` resource didn't hold
    const EPREBURN: u64 = 2;
    /// The preburn slot is already occupied with coins to be burned.
    const EPREBURN_OCCUPIED: u64 = 3;
    /// A burn was attempted on `Preburn` resource that cointained no coins
    const EPREBURN_EMPTY: u64 = 4;
    /// Minting is not allowed for the specified currency
    const EMINTING_NOT_ALLOWED: u64 = 5;
    /// The currency specified is a synthetic (non-fiat) currency
    const EIS_SYNTHETIC_CURRENCY: u64 = 6;
    /// A property expected of the coin provided didn't hold
    const ECOIN: u64 = 7;
    /// The destruction of a non-zero coin was attempted. Non-zero coins must be burned.
    const EDESTRUCTION_OF_NONZERO_COIN: u64 = 8;
    /// A property expected of `MintCapability` didn't hold
    const EMINT_CAPABILITY: u64 = 9;
    /// A withdrawal greater than the value of the coin was attempted.
    const EAMOUNT_EXCEEDS_COIN_VALUE: u64 = 10;
    /// A property expected of the `PreburnQueue` resource didn't hold.
    const EPREBURN_QUEUE: u64 = 11;
    /// A preburn with a matching amount in the preburn queue was not found.
    const EPREBURN_NOT_FOUND: u64 = 12;

    /// The maximum number of preburn requests that can be outstanding for a
    /// given designated dealer/currency.
    const MAX_OUTSTANDING_PREBURNS: u64 = 256;

    /// Initialization of the `Diem` module. Initializes the set of
    /// registered currencies in the `DiemFramework::RegisteredCurrencies` on-chain
    /// config, and publishes the `CurrencyRegistrationCapability` under the
    /// `@DiemRoot`. This can only be called from genesis.
    public fun initialize(
        dr_account: &signer,
    ) {
        DiemTimestamp::assert_genesis();
        // Operational constraint
        CoreAddresses::assert_diem_root(dr_account);
        RegisteredCurrencies::initialize(dr_account);
    }
    spec initialize {
        include DiemTimestamp::AbortsIfNotGenesis;
        include CoreAddresses::AbortsIfNotDiemRoot{account: dr_account};
        include RegisteredCurrencies::InitializeAbortsIf;
        include RegisteredCurrencies::InitializeEnsures;
    }

    /// Publishes the `BurnCapability` `cap` for the `CoinType` currency under `account`. `CoinType`
    /// must be a registered currency type. The caller must pass a treasury compliance account.
    public fun publish_burn_capability<CoinType>(
        tc_account: &signer,
        cap: BurnCapability<CoinType>,
    ) {
        Roles::assert_treasury_compliance(tc_account);
        assert_is_currency<CoinType>();
        assert(
            !exists<BurnCapability<CoinType>>(Signer::address_of(tc_account)),
            Errors::already_published(EBURN_CAPABILITY)
        );
        move_to(tc_account, cap)
    }
    spec publish_burn_capability {
        aborts_if !spec_is_currency<CoinType>();
        include PublishBurnCapAbortsIfs<CoinType>;
    }
    spec schema PublishBurnCapAbortsIfs<CoinType> {
        tc_account: &signer;
        /// Must abort if tc_account does not have the TreasuryCompliance role.
        /// Only a TreasuryCompliance account can have the BurnCapability [[H3]][PERMISSION].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        aborts_if exists<BurnCapability<CoinType>>(Signer::spec_address_of(tc_account)) with Errors::ALREADY_PUBLISHED;
    }
    spec schema PublishBurnCapEnsures<CoinType> {
        tc_account: &signer;
        ensures exists<BurnCapability<CoinType>>(Signer::spec_address_of(tc_account));
    }

    /// Mints `amount` of currency. The `account` must hold a
    /// `MintCapability<CoinType>` at the top-level in order for this call
    /// to be successful.
    public fun mint<CoinType>(account: &signer, value: u64): Diem<CoinType>
    acquires CurrencyInfo, MintCapability {
        let addr = Signer::address_of(account);
        assert(exists<MintCapability<CoinType>>(addr), Errors::requires_capability(EMINT_CAPABILITY));
        mint_with_capability(
            value,
            borrow_global<MintCapability<CoinType>>(addr)
        )
    }
    spec mint {
        modifies global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures exists<CurrencyInfo<CoinType>>(@CurrencyInfo);
        /// Must abort if the account does not have the MintCapability [[H1]][PERMISSION].
        aborts_if !exists<MintCapability<CoinType>>(Signer::spec_address_of(account)) with Errors::REQUIRES_CAPABILITY;

        include MintAbortsIf<CoinType>;
        include MintEnsures<CoinType>;
    }

    /// Burns the coins held in the first `Preburn` request in the `PreburnQueue`
    /// resource held under `preburn_address` that is equal to `amount`.
    /// Calls to this functions will fail if the `account` does not have a
    /// published `BurnCapability` for the `CoinType` published under it, or if
    /// there is not a `Preburn` request in the `PreburnQueue` that does not
    /// equal `amount`.
    public fun burn<CoinType>(
        account: &signer,
        preburn_address: address,
        amount: u64,
    ) acquires BurnCapability, CurrencyInfo, PreburnQueue {
        let addr = Signer::address_of(account);
        assert(exists<BurnCapability<CoinType>>(addr), Errors::requires_capability(EBURN_CAPABILITY));
        burn_with_capability(
            preburn_address,
            borrow_global<BurnCapability<CoinType>>(addr),
            amount
        )
    }
    spec burn {
        include BurnAbortsIf<CoinType>;
        include BurnEnsures<CoinType>;
        include BurnWithResourceCapEmits<CoinType>{preburn: spec_make_preburn(amount)};
    }
    spec schema BurnAbortsIf<CoinType> {
        account: signer;
        preburn_address: address;

        /// Must abort if the account does not have the BurnCapability [[H3]][PERMISSION].
        aborts_if !exists<BurnCapability<CoinType>>(Signer::spec_address_of(account)) with Errors::REQUIRES_CAPABILITY;
        include BurnWithCapabilityAbortsIf<CoinType>;
    }
    spec schema BurnEnsures<CoinType> {
        account: signer;
        preburn_address: address;
        include BurnWithCapabilityEnsures<CoinType>;
    }
    spec schema AbortsIfNoPreburnQueue<CoinType> {
        preburn_address: address;
        aborts_if !exists<PreburnQueue<CoinType>>(preburn_address) with Errors::NOT_PUBLISHED;
    }

    /// Cancels the `Preburn` request in the `PreburnQueue` resource held
    /// under the `preburn_address` with a value equal to `amount`, and returns the coins.
    /// Calls to this will fail if the sender does not have a published
    /// `BurnCapability<CoinType>`, or if there is no preburn request
    /// outstanding in the `PreburnQueue` resource under `preburn_address` with
    /// a value equal to `amount`.
    public fun cancel_burn<CoinType>(
        account: &signer,
        preburn_address: address,
        amount: u64,
    ): Diem<CoinType> acquires BurnCapability, CurrencyInfo, PreburnQueue {
        assert_is_currency<CoinType>();
        let addr = Signer::address_of(account);
        assert(exists<BurnCapability<CoinType>>(addr), Errors::requires_capability(EBURN_CAPABILITY));
        cancel_burn_with_capability(
            preburn_address,
            borrow_global<BurnCapability<CoinType>>(addr),
            amount,
        )
    }
    spec cancel_burn {
        let currency_info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        let post post_currency_info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        modifies global<PreburnQueue<CoinType>>(preburn_address);
        modifies global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        include CancelBurnAbortsIf<CoinType>;
        include CancelBurnWithCapEnsures<CoinType>;
        include CancelBurnWithCapEmits<CoinType>;
        ensures exists<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures exists<PreburnQueue<CoinType>>(preburn_address);
        ensures post_currency_info == update_field(
            currency_info,
            preburn_value,
            post_currency_info.preburn_value
        );
        ensures result.value == amount;
        ensures result.value > 0;
    }

    spec schema CancelBurnAbortsIf<CoinType> {
        account: signer;
        preburn_address: address;
        amount: u64;
        /// Must abort if the account does not have the BurnCapability [[H3]][PERMISSION].
        aborts_if !exists<BurnCapability<CoinType>>(Signer::spec_address_of(account)) with Errors::REQUIRES_CAPABILITY;
        include CancelBurnWithCapAbortsIf<CoinType>;
    }


    /// Mint a new `Diem` coin of `CoinType` currency worth `value`. The
    /// caller must have a reference to a `MintCapability<CoinType>`. Only
    /// the treasury compliance account or the `DiemFramework::XDX` module can acquire such a
    /// reference.
    public fun mint_with_capability<CoinType>(
        value: u64,
        _capability: &MintCapability<CoinType>
    ): Diem<CoinType> acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        let currency_code = currency_code<CoinType>();
        // update market cap resource to reflect minting
        let info = borrow_global_mut<CurrencyInfo<CoinType>>(@CurrencyInfo);
        assert(info.can_mint, Errors::invalid_state(EMINTING_NOT_ALLOWED));
        assert(MAX_U128 - info.total_value >= (value as u128), Errors::limit_exceeded(ECURRENCY_INFO));
        info.total_value = info.total_value + (value as u128);
        // don't emit mint events for synthetic currenices as this does not
        // change the total value of fiat currencies held on-chain.
        if (!info.is_synthetic) {
            Event::emit_event(
                &mut info.mint_events,
                MintEvent{
                    amount: value,
                    currency_code,
                }
            );
        };

        Diem<CoinType> { value }
    }
    spec mint_with_capability {
        pragma opaque;
        modifies global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures exists<CurrencyInfo<CoinType>>(@CurrencyInfo);
        include MintAbortsIf<CoinType>;
        include MintEnsures<CoinType>;
        include MintEmits<CoinType>;
    }
    spec schema MintAbortsIf<CoinType> {
        value: u64;
        include AbortsIfNoCurrency<CoinType>;
        aborts_if !spec_currency_info<CoinType>().can_mint with Errors::INVALID_STATE;
        aborts_if spec_currency_info<CoinType>().total_value + value > max_u128() with Errors::LIMIT_EXCEEDED;
    }
    spec schema MintEnsures<CoinType> {
        value: u64;
        result: Diem<CoinType>;
        let currency_info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        let post post_currency_info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures exists<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures post_currency_info == update_field(currency_info, total_value, currency_info.total_value + value);
        ensures result.value == value;
    }
    spec schema MintEmits<CoinType> {
        value: u64;
        let currency_info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        let handle = currency_info.mint_events;
        let msg = MintEvent{
            amount: value,
            currency_code: currency_info.currency_code,
        };
        emits msg to handle if !currency_info.is_synthetic;
    }

    /// Add the `coin` to the `preburn.to_burn` field in the `Preburn` resource
    /// held in the preburn queue at the address `preburn_address` if it is
    /// empty, otherwise raise a `EPREBURN_OCCUPIED` Error. Emits a
    /// `PreburnEvent` to the `preburn_events` event stream in the
    /// `CurrencyInfo` for the `CoinType` passed in. However, if the currency
    /// being preburned is a synthetic currency (`is_synthetic = true`) then no
    /// `PreburnEvent` will be emitted.
    fun preburn_with_resource<CoinType>(
        coin: Diem<CoinType>,
        preburn: &mut Preburn<CoinType>,
        preburn_address: address,
    ) acquires CurrencyInfo {
        let coin_value = value(&coin);
        // Throw if already occupied
        assert(value(&preburn.to_burn) == 0, Errors::invalid_state(EPREBURN_OCCUPIED));
        deposit(&mut preburn.to_burn, coin);
        let currency_code = currency_code<CoinType>();
        let info = borrow_global_mut<CurrencyInfo<CoinType>>(@CurrencyInfo);
        assert(MAX_U64 - info.preburn_value >= coin_value, Errors::limit_exceeded(ECOIN));
        info.preburn_value = info.preburn_value + coin_value;
        // don't emit preburn events for synthetic currenices as this does not
        // change the total value of fiat currencies held on-chain, and
        // therefore no off-chain movement of the backing coins needs to be
        // performed.
        if (!info.is_synthetic) {
            Event::emit_event(
                &mut info.preburn_events,
                PreburnEvent{
                    amount: coin_value,
                    currency_code,
                    preburn_address,
                }
            );
        };
    }
    spec preburn_with_resource {
        modifies global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures exists<CurrencyInfo<CoinType>>(@CurrencyInfo);
        include PreburnWithResourceAbortsIf<CoinType>{amount: coin.value};
        include PreburnEnsures<CoinType>{amount: coin.value};
        include PreburnWithResourceEmits<CoinType>{amount: coin.value};
    }
    spec schema PreburnWithResourceAbortsIf<CoinType> {
        amount: u64;
        preburn: Preburn<CoinType>;
        aborts_if preburn.to_burn.value > 0 with Errors::INVALID_STATE;
        include PreburnAbortsIf<CoinType>;
    }
    spec schema PreburnAbortsIf<CoinType> {
        amount: u64;
        include AbortsIfNoCurrency<CoinType>;
        aborts_if spec_currency_info<CoinType>().preburn_value + amount > MAX_U64 with Errors::LIMIT_EXCEEDED;
    }
    spec schema PreburnEnsures<CoinType> {
        amount: u64;
        preburn: Preburn<CoinType>;
        let info = spec_currency_info<CoinType>();
        let post post_info = spec_currency_info<CoinType>();
        ensures post_info == update_field(info, preburn_value, info.preburn_value + amount);
    }
    spec schema PreburnWithResourceEmits<CoinType> {
        amount: u64;
        preburn_address: address;
        let info = spec_currency_info<CoinType>();
        let currency_code = spec_currency_code<CoinType>();
        let handle = info.preburn_events;
        let msg = PreburnEvent {
            amount,
            currency_code,
            preburn_address,
        };
        emits msg to handle if !info.is_synthetic;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Treasury Compliance specific methods for DDs
    ///////////////////////////////////////////////////////////////////////////

    /// Create a `Preburn<CoinType>` resource.
    /// This is useful for places where a module needs to be able to burn coins
    /// outside of a Designated Dealer, e.g., for transaction fees, or for the XDX reserve.
    public fun create_preburn<CoinType>(
        tc_account: &signer
    ): Preburn<CoinType> {
        Roles::assert_treasury_compliance(tc_account);
        assert_is_currency<CoinType>();
        Preburn<CoinType> { to_burn: zero<CoinType>() }
    }
    spec create_preburn {
        include CreatePreburnAbortsIf<CoinType>;
    }
    spec schema CreatePreburnAbortsIf<CoinType> {
        tc_account: signer;
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        include AbortsIfNoCurrency<CoinType>;
    }

    /// Publish an empty `PreburnQueue` resource under the Designated Dealer
    /// dealer account `account`.
    fun publish_preburn_queue<CoinType>(
        account: &signer
    ) {
        let account_addr = Signer::address_of(account);
        Roles::assert_designated_dealer(account);
        assert_is_currency<CoinType>();
        assert(
            !exists<Preburn<CoinType>>(account_addr),
            Errors::invalid_state(EPREBURN)
        );
        assert(
            !exists<PreburnQueue<CoinType>>(account_addr),
            Errors::already_published(EPREBURN_QUEUE)
        );
        move_to(account, PreburnQueue<CoinType> {
            preburns: Vector::empty()
        })
    }
    spec publish_preburn_queue {
        pragma opaque;
        let account_addr = Signer::spec_address_of(account);
        modifies global<PreburnQueue<CoinType>>(account_addr);
        // the preburn queue cannot already exist
        aborts_if exists<PreburnQueue<CoinType>>(account_addr) with Errors::ALREADY_PUBLISHED;
        // There cannot be a preburn resource published at the same time as a
        // `PreburnQueue` resource of the same currency.
        aborts_if exists<Preburn<CoinType>>(account_addr) with Errors::INVALID_STATE;
        include PublishPreburnQueueAbortsIf<CoinType>;
        include PublishPreburnQueueEnsures<CoinType>;
    }
    spec schema PublishPreburnQueueAbortsIf<CoinType> {
        account: signer;
        include Roles::AbortsIfNotDesignatedDealer;
        include AbortsIfNoCurrency<CoinType>;
    }
    spec schema PublishPreburnQueueEnsures<CoinType> {
        account: signer;
        let account_addr = Signer::spec_address_of(account);
        // The preburn queue is published at the end of this function,
        ensures exists<PreburnQueue<CoinType>>(account_addr);
        // there cannot be a preburn resource for the same currency as the account,
        ensures !exists<Preburn<CoinType>>(account_addr);
        // and the preburn queue is empty
        ensures Vector::length(global<PreburnQueue<CoinType>>(account_addr).preburns) == 0;
    }

    /// Publish a `Preburn` resource under `account`. This function is
    /// used for bootstrapping the designated dealer at account-creation
    /// time, and the association TC account `tc_account` (at `@TreasuryCompliance`) is creating
    /// this resource for the designated dealer `account`.
    public fun publish_preburn_queue_to_account<CoinType>(
        account: &signer,
        tc_account: &signer
    ) acquires CurrencyInfo {
        Roles::assert_designated_dealer(account);
        Roles::assert_treasury_compliance(tc_account);
        assert(!is_synthetic_currency<CoinType>(), Errors::invalid_argument(EIS_SYNTHETIC_CURRENCY));
        publish_preburn_queue<CoinType>(account)
    }
    spec publish_preburn_queue_to_account {
        pragma opaque;
        let account_addr = Signer::spec_address_of(account);
        modifies global<PreburnQueue<CoinType>>(account_addr);
        /// The premission "PreburnCurrency" is granted to DesignatedDealer [[H4]][PERMISSION].
        /// Must abort if the account does not have the DesignatedDealer role.
        include Roles::AbortsIfNotDesignatedDealer;
        /// PreburnQueue is published under the DesignatedDealer account.
        include PublishPreburnQueueAbortsIf<CoinType>;
        include PublishPreburnQueueEnsures<CoinType>;
        ensures exists<PreburnQueue<CoinType>>(account_addr);

        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        include AbortsIfNoCurrency<CoinType>;
        aborts_if is_synthetic_currency<CoinType>() with Errors::INVALID_ARGUMENT;
        aborts_if exists<PreburnQueue<CoinType>>(account_addr) with Errors::ALREADY_PUBLISHED;
        aborts_if exists<Preburn<CoinType>>(account_addr) with Errors::INVALID_STATE;

    }

    ///////////////////////////////////////////////////////////////////////////


    /// Upgrade a designated dealer account from using a single `Preburn`
    /// resource to using a `PreburnQueue` resource so that multiple preburn
    /// requests can be outstanding in the same currency for a designated dealer.
    fun upgrade_preburn<CoinType>(account: &signer)
    acquires Preburn, PreburnQueue {
        Roles::assert_designated_dealer(account);
        let sender = Signer::address_of(account);
        let preburn_exists = exists<Preburn<CoinType>>(sender);
        let preburn_queue_exists = exists<PreburnQueue<CoinType>>(sender);
        // The DD must already have an existing `Preburn` resource, and not a
        // `PreburnQueue` resource already, in order to be upgraded.
        if (preburn_exists && !preburn_queue_exists) {
            let Preburn { to_burn } = move_from<Preburn<CoinType>>(sender);
            publish_preburn_queue<CoinType>(account);
            // If the DD has an old preburn balance, this is converted over
            // into the new preburn queue when it's upgraded.
            if (to_burn.value > 0)  {
                add_preburn_to_queue(account, PreburnWithMetadata {
                    preburn: Preburn { to_burn },
                    metadata: x"",
                })
            } else {
                destroy_zero(to_burn)
            };
        }
    }
    spec upgrade_preburn {
        let account_addr = Signer::spec_address_of(account);
        modifies global<Preburn<CoinType>>(account_addr);
        modifies global<PreburnQueue<CoinType>>(account_addr);
        include UpgradePreburnAbortsIf<CoinType>;
        include UpgradePreburnEnsures<CoinType>;
    }
    spec schema UpgradePreburnAbortsIf<CoinType> {
        account: signer;
        let account_addr = Signer::spec_address_of(account);
        let upgrade = exists<Preburn<CoinType>>(account_addr) && !exists<PreburnQueue<CoinType>>(account_addr);
        /// Must abort if the account doesn't have the `PreburnQueue` or
        /// `Preburn` resource to satisfy [[H4]][PERMISSION] of `preburn_to`.
        include upgrade ==> PublishPreburnQueueAbortsIf<CoinType>;
        include Roles::AbortsIfNotDesignatedDealer;
    }
    spec schema UpgradePreburnEnsures<CoinType> {
        account: signer;
        let account_addr = Signer::spec_address_of(account);
        let upgrade = exists<Preburn<CoinType>>(account_addr) && !exists<PreburnQueue<CoinType>>(account_addr);
        let preburn = global<Preburn<CoinType>>(account_addr);
        ensures upgrade ==>
            !exists<Preburn<CoinType>>(account_addr) && exists<PreburnQueue<CoinType>>(account_addr);
        ensures upgrade && preburn.to_burn.value > 0 ==>
            global<PreburnQueue<CoinType>>(account_addr).preburns ==
                vec(PreburnWithMetadata { preburn, metadata: x"" });
        ensures upgrade && preburn.to_burn.value == 0 ==>
            global<PreburnQueue<CoinType>>(account_addr).preburns == vec();
    }

    /// Add the `preburn` request to the preburn queue of `account`, and check that the
    /// number of preburn requests does not exceed `MAX_OUTSTANDING_PREBURNS`.
    fun add_preburn_to_queue<CoinType>(account: &signer, preburn: PreburnWithMetadata<CoinType>)
    acquires PreburnQueue {
        let account_addr = Signer::address_of(account);
        assert(exists<PreburnQueue<CoinType>>(account_addr), Errors::invalid_state(EPREBURN_QUEUE));
        assert(value(&preburn.preburn.to_burn) > 0, Errors::invalid_argument(EPREBURN));
        let preburns = &mut borrow_global_mut<PreburnQueue<CoinType>>(account_addr).preburns;
        assert(
            Vector::length(preburns) < MAX_OUTSTANDING_PREBURNS,
            Errors::limit_exceeded(EPREBURN_QUEUE)
        );
        Vector::push_back(preburns, preburn);
    }
    spec add_preburn_to_queue {
        pragma opaque;
        let account_addr = Signer::spec_address_of(account);
        let preburns = global<PreburnQueue<CoinType>>(account_addr).preburns;
        let post post_preburns = global<PreburnQueue<CoinType>>(account_addr).preburns;
        modifies global<PreburnQueue<CoinType>>(account_addr);
        aborts_if !exists<PreburnQueue<CoinType>>(account_addr) with Errors::INVALID_STATE;
        include AddPreburnToQueueAbortsIf<CoinType>;
        ensures exists<PreburnQueue<CoinType>>(account_addr);
        ensures Vector::eq_push_back(post_preburns, preburns, preburn);
    }
    spec schema AddPreburnToQueueAbortsIf<CoinType> {
        account: signer;
        preburn: PreburnWithMetadata<CoinType>;
        let account_addr = Signer::spec_address_of(account);
        aborts_if preburn.preburn.to_burn.value == 0 with Errors::INVALID_ARGUMENT;
        aborts_if exists<PreburnQueue<CoinType>>(account_addr) &&
            Vector::length(global<PreburnQueue<CoinType>>(account_addr).preburns) >= MAX_OUTSTANDING_PREBURNS
            with Errors::LIMIT_EXCEEDED;
    }

    /// Sends `coin` to the preburn queue for `account`, where it will wait to either be burned
    /// or returned to the balance of `account`.
    /// Calls to this function will fail if:
    /// * `account` does not have a `PreburnQueue<CoinType>` resource published under it; or
    /// * the preburn queue is already at capacity (i.e., at `MAX_OUTSTANDING_PREBURNS`); or
    /// * `coin` has a `value` field of zero.
    public fun preburn_to<CoinType>(
        account: &signer,
        coin: Diem<CoinType>
    ) acquires CurrencyInfo, Preburn, PreburnQueue {
        Roles::assert_designated_dealer(account);
        // any coin that is preburned needs to have a nonzero value
        assert(value(&coin) > 0, Errors::invalid_argument(ECOIN));
        let sender = Signer::address_of(account);
        // After an upgrade a `Preburn` resource no longer exists in this
        // currency, and it is replaced with a `PreburnQueue` resource
        // for the same currency.
        upgrade_preburn<CoinType>(account);

        let preburn = PreburnWithMetadata {
            preburn: Preburn { to_burn: zero<CoinType>() },
            metadata: x"",
        };
        preburn_with_resource(coin, &mut preburn.preburn, sender);
        add_preburn_to_queue(account, preburn);
    }
    spec preburn_to {
        pragma opaque;
        include PreburnToAbortsIf<CoinType>{amount: coin.value};
        include PreburnToEnsures<CoinType>{amount: coin.value};
        let account_addr = Signer::spec_address_of(account);
        include PreburnWithResourceEmits<CoinType>{amount: coin.value, preburn_address: account_addr};
    }
    spec schema PreburnToAbortsIf<CoinType> {
        account: signer;
        amount: u64;
        let account_addr = Signer::spec_address_of(account);
        /// Must abort if the account doesn't have the PreburnQueue or Preburn resource, or has not
        /// the correct role [[H4]][PERMISSION].
        aborts_if !(exists<Preburn<CoinType>>(account_addr) || exists<PreburnQueue<CoinType>>(account_addr));
        include Roles::AbortsIfNotDesignatedDealer;
        include PreburnAbortsIf<CoinType>;
        include UpgradePreburnAbortsIf<CoinType>;
        include AddPreburnToQueueAbortsIf<CoinType>{preburn: PreburnWithMetadata{ preburn: spec_make_preburn(amount), metadata: x"" } };
    }
    spec schema PreburnToEnsures<CoinType> {
        account: signer;
        amount: u64;
        let account_addr = Signer::spec_address_of(account);
        /// Removes the preburn resource if it exists
        modifies global<Preburn<CoinType>>(account_addr);
        /// Publishes if it doesn't exists. Updates its state either way.
        modifies global<PreburnQueue<CoinType>>(account_addr);
        ensures exists<PreburnQueue<CoinType>>(account_addr);
        // The preburn amount in the currency info can be updated.
        modifies global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        include PreburnEnsures<CoinType>{preburn: spec_make_preburn(amount)};
    }

    /// Remove the oldest preburn request in the `PreburnQueue<CoinType>`
    /// resource published under `preburn_address` whose value is equal to `amount`.
    /// Calls to this function will fail if:
    /// * `preburn_address` doesn't have a `PreburnQueue<CoinType>` resource published under it; or
    /// * a preburn request with the correct value for `amount` cannot be found in the preburn queue for `preburn_address`;
    fun remove_preburn_from_queue<CoinType>(preburn_address: address, amount: u64): PreburnWithMetadata<CoinType>
    acquires PreburnQueue {
        assert(exists<PreburnQueue<CoinType>>(preburn_address), Errors::not_published(EPREBURN_QUEUE));
        // We search from the head of the queue
        let index = 0;
        let preburn_queue = &mut borrow_global_mut<PreburnQueue<CoinType>>(preburn_address).preburns;
        let queue_length = Vector::length(preburn_queue);

        while ({
            spec {
                assert index <= queue_length;
                assert forall j in 0..index: preburn_queue[j].preburn.to_burn.value != amount;
            };
            (index < queue_length)
        }) {
            let elem = Vector::borrow(preburn_queue, index);
            if (value(&elem.preburn.to_burn) == amount) {
                let preburn = Vector::remove(preburn_queue, index);
                // Make sure that the value is correct
                return preburn
            };
            index = index + 1;
        };

        spec {
            assert index == queue_length;
            assert forall j in 0..queue_length: preburn_queue[j].preburn.to_burn.value != amount;
        };

        // If we didn't return already, we couldn't find a preburn with a matching value.
        abort Errors::invalid_state(EPREBURN_NOT_FOUND)
    }
    spec remove_preburn_from_queue {
        pragma opaque;
        modifies global<PreburnQueue<CoinType>>(preburn_address);
        include RemovePreburnFromQueueAbortsIf<CoinType>;
        include RemovePreburnFromQueueEnsures<CoinType>;
        ensures result.preburn.to_burn.value == amount;
    }
    spec schema RemovePreburnFromQueueAbortsIf<CoinType> {
        preburn_address: address;
        amount: u64;
        let preburn_queue = global<PreburnQueue<CoinType>>(preburn_address).preburns;
        aborts_if !exists<PreburnQueue<CoinType>>(preburn_address) with Errors::NOT_PUBLISHED;
        aborts_if forall i in 0..len(preburn_queue): preburn_queue[i].preburn.to_burn.value != amount with Errors::INVALID_STATE;
    }
    /// > TODO: See this cannot currently be expressed in the MSL.
    /// > See https://github.com/diem/diem/issues/7615 for more information.
    spec schema RemovePreburnFromQueueEnsures<CoinType> {
        preburn_address: address;
        amount: u64;
        ensures old(exists<PreburnQueue<CoinType>>(preburn_address)) ==> exists<PreburnQueue<CoinType>>(preburn_address);
        // let preburn_queue = global<PreburnQueue<CoinType>>(preburn_address).preburns;
        // let preburn = Preburn { to_burn: Diem { value: amount }};
        // let (found, index) = Vector::index_of(preburn_queue, preburn);
        // ensures found ==> Vector::eq_remove_elem_at_index(index, preburn_queue, old(preburn_queue));
    }

    /// Permanently removes the coins in the oldest preburn request in the
    /// `PreburnQueue` resource under `preburn_address` that has a `to_burn`
    /// value of `amount` and updates the market cap accordingly.
    /// This function can only be called by the holder of a `BurnCapability<CoinType>`.
    /// Calls to this function will fail if the there is no `PreburnQueue<CoinType>`
    /// resource under `preburn_address`, or, if there is no preburn request in
    /// the preburn queue with a `to_burn` amount equal to `amount`.
    public fun burn_with_capability<CoinType>(
        preburn_address: address,
        capability: &BurnCapability<CoinType>,
        amount: u64,
    ) acquires CurrencyInfo, PreburnQueue {

        // Remove the preburn request
        let PreburnWithMetadata{ preburn, metadata: _ } = remove_preburn_from_queue<CoinType>(preburn_address, amount);

        // Burn the contained coins
        burn_with_resource_cap(&mut preburn, preburn_address, capability);

        let Preburn { to_burn } = preburn;
        destroy_zero(to_burn);
    }
    spec burn_with_capability {
        include BurnWithResourceCapEmits<CoinType>{preburn: spec_make_preburn(amount)};
        include BurnWithCapabilityAbortsIf<CoinType>;
        include BurnWithCapabilityEnsures<CoinType>;
    }
    spec schema BurnWithCapabilityAbortsIf<CoinType> {
        preburn_address: address;
        amount: u64;
        let preburn = spec_make_preburn<CoinType>(amount);
        include AbortsIfNoPreburnQueue<CoinType>;
        include RemovePreburnFromQueueAbortsIf<CoinType>;
        include BurnWithResourceCapAbortsIf<CoinType>{preburn: preburn};
    }
    spec schema BurnWithCapabilityEnsures<CoinType> {
        preburn_address: address;
        amount: u64;
        let preburn = spec_make_preburn<CoinType>(amount);
        include BurnWithResourceCapEnsures<CoinType>{preburn: preburn};
        include RemovePreburnFromQueueEnsures<CoinType>;
    }

    /// Permanently removes the coins held in the `Preburn` resource (in `to_burn` field)
    /// that was stored in a `PreburnQueue` at `preburn_address` and updates the market cap accordingly.
    /// This function can only be called by the holder of a `BurnCapability<CoinType>`.
    /// Calls to this function will fail if the preburn `to_burn` area for `CoinType` is empty.
    fun burn_with_resource_cap<CoinType>(
        preburn: &mut Preburn<CoinType>,
        preburn_address: address,
        _capability: &BurnCapability<CoinType>
    ) acquires CurrencyInfo {
        let currency_code = currency_code<CoinType>();
        // Abort if no coin present in preburn area
        assert(preburn.to_burn.value > 0, Errors::invalid_state(EPREBURN_EMPTY));
        // destroy the coin in Preburn area
        let Diem { value } = withdraw_all<CoinType>(&mut preburn.to_burn);
        // update the market cap
        assert_is_currency<CoinType>();
        let info = borrow_global_mut<CurrencyInfo<CoinType>>(@CurrencyInfo);
        assert(info.total_value >= (value as u128), Errors::limit_exceeded(ECURRENCY_INFO));
        info.total_value = info.total_value - (value as u128);
        assert(info.preburn_value >= value, Errors::limit_exceeded(EPREBURN));
        info.preburn_value = info.preburn_value - value;
        // don't emit burn events for synthetic currenices as this does not
        // change the total value of fiat currencies held on-chain.
        if (!info.is_synthetic) {
            Event::emit_event(
                &mut info.burn_events,
                BurnEvent {
                    amount: value,
                    currency_code,
                    preburn_address,
                }
            );
        };
    }
    spec burn_with_resource_cap {
        let pre_preburn = preburn;
        include BurnWithResourceCapAbortsIf<CoinType>{preburn: pre_preburn};
        include BurnWithResourceCapEnsures<CoinType>{preburn: pre_preburn};
        include BurnWithResourceCapEmits<CoinType>{preburn: pre_preburn};
    }
    spec schema BurnWithResourceCapAbortsIf<CoinType> {
        preburn: Preburn<CoinType>;
        include AbortsIfNoCurrency<CoinType>;
        let to_burn = preburn.to_burn.value;
        let info = spec_currency_info<CoinType>();
        aborts_if to_burn == 0 with Errors::INVALID_STATE;
        aborts_if info.total_value < to_burn with Errors::LIMIT_EXCEEDED;
        aborts_if info.preburn_value < to_burn with Errors::LIMIT_EXCEEDED;
    }
    spec schema BurnWithResourceCapEnsures<CoinType> {
        preburn: Preburn<CoinType>;
        ensures spec_currency_info<CoinType>().total_value
                == old(spec_currency_info<CoinType>().total_value) - preburn.to_burn.value;
        ensures spec_currency_info<CoinType>().preburn_value
                == old(spec_currency_info<CoinType>().preburn_value) - preburn.to_burn.value;
    }
    spec schema BurnWithResourceCapEmits<CoinType> {
        preburn: Preburn<CoinType>;
        preburn_address: address;
        let info = spec_currency_info<CoinType>();
        let currency_code = spec_currency_code<CoinType>();
        let handle = info.burn_events;
        emits BurnEvent {
                amount: preburn.to_burn.value,
                currency_code,
                preburn_address,
            }
            to handle if !info.is_synthetic;
    }

    /// Cancels the oldest preburn request held in the `PreburnQueue` resource under
    /// `preburn_address` with a `to_burn` amount matching `amount`. It then returns these coins to the caller.
    /// This function can only be called by the holder of a
    /// `BurnCapability<CoinType>`, and will fail if the `PreburnQueue<CoinType>` resource
    /// at `preburn_address` does not contain a preburn request of the right amount.
    public fun cancel_burn_with_capability<CoinType>(
        preburn_address: address,
        _capability: &BurnCapability<CoinType>,
        amount: u64,
    ): Diem<CoinType> acquires CurrencyInfo, PreburnQueue {

        // destroy the coin in the preburn area
        let PreburnWithMetadata{ preburn: Preburn { to_burn }, metadata: _ } = remove_preburn_from_queue<CoinType>(preburn_address, amount);

        // update the market cap
        let currency_code = currency_code<CoinType>();
        let info = borrow_global_mut<CurrencyInfo<CoinType>>(@CurrencyInfo);
        assert(info.preburn_value >= amount, Errors::limit_exceeded(EPREBURN));
        info.preburn_value = info.preburn_value - amount;
        // Don't emit cancel burn events for synthetic currencies. cancel_burn
        // shouldn't be be used for synthetic coins in the first place.
        if (!info.is_synthetic) {
            Event::emit_event(
                &mut info.cancel_burn_events,
                CancelBurnEvent {
                    amount,
                    currency_code,
                    preburn_address,
                }
            );
        };

        to_burn
    }
    spec cancel_burn_with_capability {
        modifies global<PreburnQueue<CoinType>>(preburn_address);
        modifies global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        include CancelBurnWithCapAbortsIf<CoinType>;
        include CancelBurnWithCapEnsures<CoinType>;
        include CancelBurnWithCapEmits<CoinType>;
        ensures exists<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures result.value == amount;
        ensures result.value > 0;
    }
    spec schema CancelBurnWithCapAbortsIf<CoinType> {
        preburn_address: address;
        amount: u64;
        let info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        include AbortsIfNoCurrency<CoinType>;
        include RemovePreburnFromQueueAbortsIf<CoinType>;
        aborts_if info.preburn_value < amount with Errors::LIMIT_EXCEEDED;
    }
    spec schema CancelBurnWithCapEnsures<CoinType> {
        preburn_address: address;
        amount: u64;
        include RemovePreburnFromQueueEnsures<CoinType>;
        let info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        let post post_info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures post_info == update_field(info, preburn_value, info.preburn_value - amount);
    }
    spec schema CancelBurnWithCapEmits<CoinType> {
        preburn_address: address;
        amount: u64;
        let info = spec_currency_info<CoinType>();
        let currency_code = spec_currency_code<CoinType>();
        let handle = info.cancel_burn_events;
        emits CancelBurnEvent {
               amount,
               currency_code,
               preburn_address,
           }
           to handle if !info.is_synthetic;
    }

    /// A shortcut for immediately burning a coin. This calls preburn followed by a subsequent burn, and is
    /// used for administrative burns, like unpacking an XDX coin or charging fees.
    public fun burn_now<CoinType>(
        coin: Diem<CoinType>,
        preburn: &mut Preburn<CoinType>,
        preburn_address: address,
        capability: &BurnCapability<CoinType>
    ) acquires CurrencyInfo {
        assert(coin.value > 0, Errors::invalid_argument(ECOIN));
        preburn_with_resource(coin, preburn, preburn_address);
        burn_with_resource_cap(preburn, preburn_address, capability);
    }
    spec burn_now {
        include BurnNowAbortsIf<CoinType>;
        let info = spec_currency_info<CoinType>();
        let post post_info = spec_currency_info<CoinType>();
        include PreburnWithResourceEmits<CoinType>{amount: coin.value, preburn_address: preburn_address};
        include BurnWithResourceCapEmits<CoinType>{preburn: Preburn<CoinType>{to_burn: coin}};
        ensures preburn.to_burn.value == 0;
        ensures post_info == update_field(info, total_value, info.total_value - coin.value);
    }
    spec schema BurnNowAbortsIf<CoinType> {
        coin: Diem<CoinType>;
        preburn: Preburn<CoinType>;
        aborts_if coin.value == 0 with Errors::INVALID_ARGUMENT;
        include PreburnWithResourceAbortsIf<CoinType>{amount: coin.value};
        // The aborts condition for the burn is simplified because of previous call to preburn.
        let info = spec_currency_info<CoinType>();
        aborts_if info.total_value < coin.value with Errors::LIMIT_EXCEEDED;
    }

    /// Removes and returns the `BurnCapability<CoinType>` from `account`.
    /// Calls to this function will fail if `account` does  not have a
    /// published `BurnCapability<CoinType>` resource at the top-level.
    public fun remove_burn_capability<CoinType>(account: &signer): BurnCapability<CoinType>
    acquires BurnCapability {
        let addr = Signer::address_of(account);
        assert(exists<BurnCapability<CoinType>>(addr), Errors::requires_capability(EBURN_CAPABILITY));
        move_from<BurnCapability<CoinType>>(addr)
    }
    spec remove_burn_capability {
        include AbortsIfNoBurnCapability<CoinType>;
    }
    spec schema AbortsIfNoBurnCapability<CoinType> {
        account: signer;
        aborts_if !exists<BurnCapability<CoinType>>(Signer::spec_address_of(account)) with Errors::REQUIRES_CAPABILITY;
    }

    /// Returns the total value of `Diem<CoinType>` that is waiting to be
    /// burned throughout the system (i.e. the sum of all outstanding
    /// preburn requests across all preburn resources for the `CoinType`
    /// currency).
    public fun preburn_value<CoinType>(): u64 acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        borrow_global<CurrencyInfo<CoinType>>(@CurrencyInfo).preburn_value
    }

    /// Create a new `Diem<CoinType>` with a value of `0`. Anyone can call
    /// this and it will be successful as long as `CoinType` is a registered currency.
    public fun zero<CoinType>(): Diem<CoinType> {
        assert_is_currency<CoinType>();
        Diem<CoinType> { value: 0 }
    }

    /// Returns the `value` of the passed in `coin`. The value is
    /// represented in the base units for the currency represented by
    /// `CoinType`.
    public fun value<CoinType>(coin: &Diem<CoinType>): u64 {
        coin.value
    }

    /// Removes `amount` of value from the passed in `coin`. Returns the
    /// remaining balance of the passed in `coin`, along with another coin
    /// with value equal to `amount`. Calls will fail if `amount > Diem::value(&coin)`.
    public fun split<CoinType>(coin: Diem<CoinType>, amount: u64): (Diem<CoinType>, Diem<CoinType>) {
        let other = withdraw(&mut coin, amount);
        (coin, other)
    }
    spec split {
        aborts_if coin.value < amount with Errors::LIMIT_EXCEEDED;
        ensures result_1.value == coin.value - amount;
        ensures result_2.value == amount;
    }


    /// Withdraw `amount` from the passed-in `coin`, where the original coin is modified in place.
    /// After this function is executed, the original `coin` will have
    /// `value = original_value - amount`, and the new coin will have a `value = amount`.
    /// Calls will abort if the passed-in `amount` is greater than the
    /// value of the passed-in `coin`.
    public fun withdraw<CoinType>(coin: &mut Diem<CoinType>, amount: u64): Diem<CoinType> {
        // Check that `amount` is less than the coin's value
        assert(coin.value >= amount, Errors::limit_exceeded(EAMOUNT_EXCEEDS_COIN_VALUE));
        coin.value = coin.value - amount;
        Diem { value: amount }
    }
    spec withdraw {
        pragma opaque;
        include WithdrawAbortsIf<CoinType>;
        ensures coin.value == old(coin.value) - amount;
        ensures result.value == amount;
    }
    spec schema WithdrawAbortsIf<CoinType> {
        coin: Diem<CoinType>;
        amount: u64;
        aborts_if coin.value < amount with Errors::LIMIT_EXCEEDED;
    }

    /// Return a `Diem<CoinType>` worth `coin.value` and reduces the `value` of the input `coin` to
    /// zero. Does not abort.
    public fun withdraw_all<CoinType>(coin: &mut Diem<CoinType>): Diem<CoinType> {
        let val = coin.value;
        withdraw(coin, val)
    }
    spec withdraw_all {
        pragma opaque;
        aborts_if false;
        ensures result.value == old(coin.value);
        ensures coin.value == 0;
    }

    /// Takes two coins as input, returns a single coin with the total value of both coins.
    /// Destroys on of the input coins.
    public fun join<CoinType>(coin1: Diem<CoinType>, coin2: Diem<CoinType>): Diem<CoinType>  {
        deposit(&mut coin1, coin2);
        coin1
    }
    spec join {
        pragma opaque;
        aborts_if coin1.value + coin2.value > max_u64() with Errors::LIMIT_EXCEEDED;
        ensures result.value == coin1.value + coin2.value;
    }


    /// "Merges" the two coins.
    /// The coin passed in by reference will have a value equal to the sum of the two coins
    /// The `check` coin is consumed in the process
    public fun deposit<CoinType>(coin: &mut Diem<CoinType>, check: Diem<CoinType>) {
        let Diem { value } = check;
        assert(MAX_U64 - coin.value >= value, Errors::limit_exceeded(ECOIN));
        coin.value = coin.value + value;
    }
    spec deposit {
        pragma opaque;
        include DepositAbortsIf<CoinType>;
        ensures coin.value == old(coin.value) + check.value;
    }
    spec schema DepositAbortsIf<CoinType> {
        coin: Diem<CoinType>;
        check: Diem<CoinType>;
        aborts_if coin.value + check.value > MAX_U64 with Errors::LIMIT_EXCEEDED;
    }

    /// Destroy a zero-value coin. Calls will fail if the `value` in the passed-in `coin` is non-zero
    /// so it is impossible to "burn" any non-zero amount of `Diem` without having
    /// a `BurnCapability` for the specific `CoinType`.
    public fun destroy_zero<CoinType>(coin: Diem<CoinType>) {
        let Diem { value } = coin;
        assert(value == 0, Errors::invalid_argument(EDESTRUCTION_OF_NONZERO_COIN))
    }
    spec destroy_zero {
        pragma opaque;
        aborts_if coin.value > 0 with Errors::INVALID_ARGUMENT;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Definition of Currencies
    ///////////////////////////////////////////////////////////////////////////

    /// Register the type `CoinType` as a currency. Until the type is
    /// registered as a currency it cannot be used as a coin/currency unit in Diem.
    /// The passed-in `dr_account` must be a specific address (`@CurrencyInfo`) and
    /// `dr_account` must also have the correct `DiemRoot` account role.
    /// After the first registration of `CoinType` as a
    /// currency, additional attempts to register `CoinType` as a currency
    /// will abort.
    /// When the `CoinType` is registered it publishes the
    /// `CurrencyInfo<CoinType>` resource under the `@CurrencyInfo` and
    /// adds the currency to the set of `RegisteredCurrencies`. It returns
    /// `MintCapability<CoinType>` and `BurnCapability<CoinType>` resources.
    public fun register_currency<CoinType>(
        dr_account: &signer,
        to_xdx_exchange_rate: FixedPoint32,
        is_synthetic: bool,
        scaling_factor: u64,
        fractional_part: u64,
        currency_code: vector<u8>,
    ): (MintCapability<CoinType>, BurnCapability<CoinType>)
    {
        Roles::assert_diem_root(dr_account);
        // Operational constraint that it must be stored under a specific address.
        CoreAddresses::assert_currency_info(dr_account);
        assert(
            !exists<CurrencyInfo<CoinType>>(Signer::address_of(dr_account)),
            Errors::already_published(ECURRENCY_INFO)
        );
        assert(0 < scaling_factor && scaling_factor <= MAX_SCALING_FACTOR, Errors::invalid_argument(ECURRENCY_INFO));
        move_to(dr_account, CurrencyInfo<CoinType> {
            total_value: 0,
            preburn_value: 0,
            to_xdx_exchange_rate,
            is_synthetic,
            scaling_factor,
            fractional_part,
            currency_code: copy currency_code,
            can_mint: true,
            mint_events: Event::new_event_handle<MintEvent>(dr_account),
            burn_events: Event::new_event_handle<BurnEvent>(dr_account),
            preburn_events: Event::new_event_handle<PreburnEvent>(dr_account),
            cancel_burn_events: Event::new_event_handle<CancelBurnEvent>(dr_account),
            exchange_rate_update_events: Event::new_event_handle<ToXDXExchangeRateUpdateEvent>(dr_account)
        });
        RegisteredCurrencies::add_currency_code(
            dr_account,
            currency_code,
        );
        (MintCapability<CoinType>{}, BurnCapability<CoinType>{})
    }
    spec register_currency {
        include RegisterCurrencyAbortsIf<CoinType>;
        include RegisterCurrencyEnsures<CoinType>;
    }

    spec schema RegisterCurrencyAbortsIf<CoinType> {
        dr_account: signer;
        currency_code: vector<u8>;
        scaling_factor: u64;

        /// Must abort if the signer does not have the DiemRoot role [[H8]][PERMISSION].
        include Roles::AbortsIfNotDiemRoot{account: dr_account};

        aborts_if scaling_factor == 0 || scaling_factor > MAX_SCALING_FACTOR with Errors::INVALID_ARGUMENT;
        include CoreAddresses::AbortsIfNotCurrencyInfo{account: dr_account};
        aborts_if exists<CurrencyInfo<CoinType>>(Signer::spec_address_of(dr_account))
            with Errors::ALREADY_PUBLISHED;
        include RegisteredCurrencies::AddCurrencyCodeAbortsIf;
    }

    spec schema RegisterCurrencyEnsures<CoinType> {
        ensures spec_is_currency<CoinType>();
        ensures spec_currency_info<CoinType>().total_value == 0;
    }

    /// Registers a stable currency (SCS) coin -- i.e., a non-synthetic currency.
    /// Resources are published on two distinct
    /// accounts: The `CoinInfo` is published on the Diem root account, and the mint and
    /// burn capabilities are published on a treasury compliance account.
    /// This code allows different currencies to have different treasury compliance
    /// accounts.
    public fun register_SCS_currency<CoinType>(
        dr_account: &signer,
        tc_account: &signer,
        to_xdx_exchange_rate: FixedPoint32,
        scaling_factor: u64,
        fractional_part: u64,
        currency_code: vector<u8>,
    ) {
        Roles::assert_treasury_compliance(tc_account);
        Roles::assert_diem_root(dr_account);
        let (mint_cap, burn_cap) =
            register_currency<CoinType>(
                dr_account,
                to_xdx_exchange_rate,
                false,   // is_synthetic
                scaling_factor,
                fractional_part,
                currency_code,
            );
        assert(
            !exists<MintCapability<CoinType>>(Signer::address_of(tc_account)),
            Errors::already_published(EMINT_CAPABILITY)
        );
        move_to(tc_account, mint_cap);
        publish_burn_capability<CoinType>(tc_account, burn_cap);
    }

    spec register_SCS_currency {
        include RegisterSCSCurrencyAbortsIf<CoinType>;
        include RegisterSCSCurrencyEnsures<CoinType>;
    }
    spec schema RegisterSCSCurrencyAbortsIf<CoinType> {
        tc_account: signer;
        dr_account: signer;
        currency_code: vector<u8>;
        scaling_factor: u64;

        /// Must abort if tc_account does not have the TreasuryCompliance role.
        /// Only a TreasuryCompliance account can have the MintCapability [[H1]][PERMISSION].
        /// Only a TreasuryCompliance account can have the BurnCapability [[H3]][PERMISSION].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};

        aborts_if exists<MintCapability<CoinType>>(Signer::spec_address_of(tc_account)) with Errors::ALREADY_PUBLISHED;
        include RegisterCurrencyAbortsIf<CoinType>;
        include PublishBurnCapAbortsIfs<CoinType>;
    }
    spec schema RegisterSCSCurrencyEnsures<CoinType> {
        tc_account: signer;
        ensures spec_has_mint_capability<CoinType>(Signer::spec_address_of(tc_account));
    }

    /// Returns the total amount of currency minted of type `CoinType`.
    public fun market_cap<CoinType>(): u128
    acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        borrow_global<CurrencyInfo<CoinType>>(@CurrencyInfo).total_value
    }
    /// Returns the market cap of CoinType.
    spec fun spec_market_cap<CoinType>(): u128 {
        global<CurrencyInfo<CoinType>>(@CurrencyInfo).total_value
    }

    /// Returns the value of the coin in the `FromCoinType` currency in XDX.
    /// This should only be used where a _rough_ approximation of the exchange
    /// rate is needed.
    public fun approx_xdx_for_value<FromCoinType>(from_value: u64): u64
    acquires CurrencyInfo {
        let xdx_exchange_rate = xdx_exchange_rate<FromCoinType>();
        FixedPoint32::multiply_u64(from_value, xdx_exchange_rate)
    }
    spec approx_xdx_for_value {
        pragma opaque;
        include ApproxXdmForValueAbortsIf<FromCoinType>;
        ensures result == spec_approx_xdx_for_value<FromCoinType>(from_value);
    }
    spec schema ApproxXdmForValueAbortsIf<CoinType> {
        from_value: num;
        include AbortsIfNoCurrency<CoinType>;
        let xdx_exchange_rate = spec_xdx_exchange_rate<CoinType>();
        include FixedPoint32::MultiplyAbortsIf{val: from_value, multiplier: xdx_exchange_rate};
    }

    /// Returns the value of the coin in the `FromCoinType` currency in XDX.
    /// This should only be used where a rough approximation of the exchange
    /// rate is needed.
    public fun approx_xdx_for_coin<FromCoinType>(coin: &Diem<FromCoinType>): u64
    acquires CurrencyInfo {
        let from_value = value(coin);
        approx_xdx_for_value<FromCoinType>(from_value)
    }

    /// Returns `true` if the type `CoinType` is a registered currency.
    /// Returns `false` otherwise.
    public fun is_currency<CoinType>(): bool {
        exists<CurrencyInfo<CoinType>>(@CurrencyInfo)
    }

    public fun is_SCS_currency<CoinType>(): bool acquires CurrencyInfo {
        is_currency<CoinType>() &&
        !borrow_global<CurrencyInfo<CoinType>>(@CurrencyInfo).is_synthetic
    }


    /// Returns `true` if `CoinType` is a synthetic currency as defined in
    /// its `CurrencyInfo`. Returns `false` otherwise.
    public fun is_synthetic_currency<CoinType>(): bool
    acquires CurrencyInfo {
        let addr = @CurrencyInfo;
        exists<CurrencyInfo<CoinType>>(addr) &&
            borrow_global<CurrencyInfo<CoinType>>(addr).is_synthetic
    }

    /// Returns the scaling factor for the `CoinType` currency as defined
    /// in its `CurrencyInfo`.
    public fun scaling_factor<CoinType>(): u64
    acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        borrow_global<CurrencyInfo<CoinType>>(@CurrencyInfo).scaling_factor
    }
    spec fun spec_scaling_factor<CoinType>(): u64 {
        global<CurrencyInfo<CoinType>>(@CurrencyInfo).scaling_factor
    }

    /// Returns the representable (i.e. real-world) fractional part for the
    /// `CoinType` currency as defined in its `CurrencyInfo`.
    public fun fractional_part<CoinType>(): u64
    acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        borrow_global<CurrencyInfo<CoinType>>(@CurrencyInfo).fractional_part
    }

    /// Returns the currency code for the registered currency as defined in
    /// its `CurrencyInfo` resource.
    public fun currency_code<CoinType>(): vector<u8>
    acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        *&borrow_global<CurrencyInfo<CoinType>>(@CurrencyInfo).currency_code
    }
    spec currency_code {
        pragma opaque;
        include AbortsIfNoCurrency<CoinType>;
        ensures result == spec_currency_code<CoinType>();
    }
    spec fun spec_currency_code<CoinType>(): vector<u8> {
        spec_currency_info<CoinType>().currency_code
    }

    /// Updates the `to_xdx_exchange_rate` held in the `CurrencyInfo` for
    /// `FromCoinType` to the new passed-in `xdx_exchange_rate`.
    public fun update_xdx_exchange_rate<FromCoinType>(
        tc_account: &signer,
        xdx_exchange_rate: FixedPoint32
    ) acquires CurrencyInfo {
        Roles::assert_treasury_compliance(tc_account);
        assert_is_currency<FromCoinType>();
        let currency_info = borrow_global_mut<CurrencyInfo<FromCoinType>>(@CurrencyInfo);
        currency_info.to_xdx_exchange_rate = xdx_exchange_rate;
        Event::emit_event(
            &mut currency_info.exchange_rate_update_events,
            ToXDXExchangeRateUpdateEvent {
                currency_code: *&currency_info.currency_code,
                new_to_xdx_exchange_rate: FixedPoint32::get_raw_value(*&currency_info.to_xdx_exchange_rate),
            }
        );
    }
    spec update_xdx_exchange_rate {
        include UpdateXDXExchangeRateAbortsIf<FromCoinType>;
        include UpdateXDXExchangeRateEnsures<FromCoinType>;
        include UpdateXDXExchangeRateEmits<FromCoinType>;
    }

    spec schema UpdateXDXExchangeRateAbortsIf<FromCoinType> {
        tc_account: signer;
        /// Must abort if the account does not have the TreasuryCompliance Role [[H5]][PERMISSION].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};

        include AbortsIfNoCurrency<FromCoinType>;
    }
    spec schema UpdateXDXExchangeRateEnsures<FromCoinType> {
        xdx_exchange_rate: FixedPoint32;
        ensures spec_currency_info<FromCoinType>().to_xdx_exchange_rate == xdx_exchange_rate;
    }

    spec schema UpdateXDXExchangeRateEmits<FromCoinType> {
        xdx_exchange_rate: FixedPoint32;
        let handle = global<CurrencyInfo<FromCoinType>>(@CurrencyInfo).exchange_rate_update_events;
        let msg = ToXDXExchangeRateUpdateEvent {
            currency_code: global<CurrencyInfo<FromCoinType>>(@CurrencyInfo).currency_code,
            new_to_xdx_exchange_rate: FixedPoint32::get_raw_value(xdx_exchange_rate)
        };
        emits msg to handle;
    }

    /// Returns the (rough) exchange rate between `CoinType` and `XDX`
    public fun xdx_exchange_rate<CoinType>(): FixedPoint32
    acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        *&borrow_global<CurrencyInfo<CoinType>>(@CurrencyInfo).to_xdx_exchange_rate
    }
    spec xdx_exchange_rate {
        pragma opaque;
        include AbortsIfNoCurrency<CoinType>;
        let info = global<CurrencyInfo<CoinType>>(@CurrencyInfo);
        ensures result == info.to_xdx_exchange_rate;
    }

    /// There may be situations in which we disallow the further minting of
    /// coins in the system without removing the currency. This function
    /// allows the association treasury compliance account to control whether or not further coins of
    /// `CoinType` can be minted or not. If this is called with `can_mint = true`,
    /// then minting is allowed, if `can_mint = false` then minting is
    /// disallowed until it is turned back on via this function. All coins
    /// start out in the default state of `can_mint = true`.
    public fun update_minting_ability<CoinType>(
        tc_account: &signer,
        can_mint: bool,
        )
    acquires CurrencyInfo {
        Roles::assert_treasury_compliance(tc_account);
        assert_is_currency<CoinType>();
        let currency_info = borrow_global_mut<CurrencyInfo<CoinType>>(@CurrencyInfo);
        currency_info.can_mint = can_mint;
    }
    spec update_minting_ability {
        include UpdateMintingAbilityAbortsIf<CoinType>;
        include UpdateMintingAbilityEnsures<CoinType>;
    }
    spec schema UpdateMintingAbilityAbortsIf<CoinType> {
        tc_account: signer;
        include AbortsIfNoCurrency<CoinType>;
        /// Only the TreasuryCompliance role can enable/disable minting [[H2]][PERMISSION].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
    }
    spec schema UpdateMintingAbilityEnsures<CoinType> {
        tc_account: signer;
        can_mint: bool;
        ensures spec_currency_info<CoinType>().can_mint == can_mint;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Helper functions
    ///////////////////////////////////////////////////////////////////////////

    /// Asserts that `CoinType` is a registered currency.
    public fun assert_is_currency<CoinType>() {
        assert(is_currency<CoinType>(), Errors::not_published(ECURRENCY_INFO));
    }
    spec assert_is_currency {
        pragma opaque;
        include AbortsIfNoCurrency<CoinType>;
    }
    spec schema AbortsIfNoCurrency<CoinType> {
        aborts_if !spec_is_currency<CoinType>() with Errors::NOT_PUBLISHED;
    }

    public fun assert_is_SCS_currency<CoinType>() acquires CurrencyInfo {
        assert_is_currency<CoinType>();
        assert(is_SCS_currency<CoinType>(), Errors::invalid_state(ECURRENCY_INFO));
    }
    spec schema AbortsIfNoSCSCurrency<CoinType> {
        include AbortsIfNoCurrency<CoinType>;
        aborts_if !is_SCS_currency<CoinType>() with Errors::INVALID_STATE;
    }

    // =================================================================
    // Module Specification

    spec module {} // switch documentation context back to module level

    /// # Access Control

    spec module {
        /// Only mint functions can increase the total amount of currency [[H1]][PERMISSION].
        apply TotalValueNotIncrease<CoinType> to *<CoinType>
            except mint<CoinType>, mint_with_capability<CoinType>;

        /// In order to successfully call `mint` and `mint_with_capability`, MintCapability is
        /// required. MintCapability must be only granted to a TreasuryCompliance account [[H1]][PERMISSION].
        /// Only `register_SCS_currency` creates MintCapability, which must abort if the account
        /// does not have the TreasuryCompliance role [[H1]][PERMISSION].
        apply PreserveMintCapAbsence<CoinType> to *<CoinType> except register_SCS_currency<CoinType>;
        apply Roles::AbortsIfNotTreasuryCompliance{account: tc_account} to register_SCS_currency<CoinType>;

        /// Only TreasuryCompliance can have MintCapability [[H1]][PERMISSION].
        /// If an account has MintCapability, it is a TreasuryCompliance account.
        invariant forall coin_type: type:
            forall mint_cap_owner: address where exists<MintCapability<coin_type>>(mint_cap_owner):
                Roles::spec_has_treasury_compliance_role_addr(mint_cap_owner);

        /// MintCapability is not transferrable [[J1]][PERMISSION].
        apply PreserveMintCapExistence<CoinType> to *<CoinType>;

        /// The permission "MintCurrency" is unique per currency [[I1]][PERMISSION].
        /// At most one address has a mint capability for SCS CoinType
        invariant [global, isolated]
            forall coin_type: type where is_SCS_currency<coin_type>():
                forall mint_cap_owner1: address, mint_cap_owner2: address
                     where exists<MintCapability<coin_type>>(mint_cap_owner1)
                                && exists<MintCapability<coin_type>>(mint_cap_owner2):
                          mint_cap_owner1 == mint_cap_owner2;

        /// If an address has a mint capability, it is an SCS currency.
        invariant
            forall coin_type: type, addr3: address where spec_has_mint_capability<coin_type>(addr3):
                is_SCS_currency<coin_type>();
    }

    /// ## Minting
    // > TODO These can be simplified using global invariants

    spec schema TotalValueNotIncrease<CoinType> {
        /// The total amount of currency does not increase.
        ensures old(spec_is_currency<CoinType>())
            ==> spec_currency_info<CoinType>().total_value <= old(spec_currency_info<CoinType>().total_value);
    }
    spec schema PreserveMintCapExistence<CoinType> {
        /// The existence of MintCapability is preserved.
        ensures forall addr: address:
            old(exists<MintCapability<CoinType>>(addr)) ==>
                exists<MintCapability<CoinType>>(addr);
    }
    spec schema PreserveMintCapAbsence<CoinType> {
        /// The absence of MintCapability is preserved.
        ensures forall addr: address:
            old(!exists<MintCapability<CoinType>>(addr)) ==>
                !exists<MintCapability<CoinType>>(addr);
    }

    /// ## Burning

    spec schema TotalValueNotDecrease<CoinType> {
        /// The total amount of currency does not decrease.
        ensures old(spec_is_currency<CoinType>())
            ==> spec_currency_info<CoinType>().total_value >= old(spec_currency_info<CoinType>().total_value);
    }
    spec schema PreserveBurnCapExistence<CoinType> {
        /// The existence of BurnCapability is preserved.
        ensures forall addr: address:
            old(exists<BurnCapability<CoinType>>(addr)) ==>
                exists<BurnCapability<CoinType>>(addr);
    }
    spec schema PreserveBurnCapAbsence<CoinType> {
        /// The absence of BurnCapability is preserved.
        ensures forall addr: address:
            old(!exists<BurnCapability<CoinType>>(addr)) ==>
                !exists<BurnCapability<CoinType>>(addr);
    }
    spec module {
        /// Only burn functions can decrease the total amount of currency [[H3]][PERMISSION].
        apply TotalValueNotDecrease<CoinType> to *<CoinType>
            except burn<CoinType>, burn_with_capability<CoinType>, burn_with_resource_cap<CoinType>,
            burn_now<CoinType>;

        /// In order to successfully call the burn functions, BurnCapability is required.
        /// BurnCapability must be only granted to a TreasuryCompliance account [[H3]][PERMISSION].
        /// Only `register_SCS_currency` and `publish_burn_capability` publish BurnCapability,
        /// which must abort if the account does not have the TreasuryCompliance role [[H8]][PERMISSION].
        apply PreserveBurnCapAbsence<CoinType> to *<CoinType>
            except register_SCS_currency<CoinType>, publish_burn_capability<CoinType>;
        apply Roles::AbortsIfNotTreasuryCompliance{account: tc_account} to register_SCS_currency<CoinType>;

        /// Only TreasuryCompliance can have BurnCapability [[H3]][PERMISSION].
        /// If an account has BurnCapability, it is a TreasuryCompliance account.
        invariant forall coin_type: type:
            forall addr1: address:
                exists<BurnCapability<coin_type>>(addr1) ==>
                    Roles::spec_has_treasury_compliance_role_addr(addr1);

        /// BurnCapability is not transferrable [[J3]][PERMISSION]. BurnCapability can be extracted from an
        /// account, but is always moved back to the original account. This is the case in
        /// `TransactionFee::burn_fees` which is the only user of `remove_burn_capability` and
        /// `publish_burn_capability`.
        apply PreserveBurnCapExistence<CoinType> to *<CoinType> except remove_burn_capability<CoinType>;

        // The permission "BurnCurrency" is unique per currency [[I3]][PERMISSION]. At most one BurnCapability
        // can exist for each SCS CoinType. It is because when a new CoinType is registered in
        // `register_currency`, BurnCapability<CoinType> is packed (i.e., its instance is created)
        // only one time.
    }


    /// ## Preburning

    spec schema PreburnValueNotIncrease<CoinType> {
        /// The preburn value of currency does not increase.
        ensures old(spec_is_currency<CoinType>())
            ==> spec_currency_info<CoinType>().preburn_value <= old(spec_currency_info<CoinType>().preburn_value);
    }
    spec schema PreburnValueNotDecrease<CoinType> {
        /// The the preburn value of currency does not decrease.
        ensures old(spec_is_currency<CoinType>())
            ==> spec_currency_info<CoinType>().preburn_value >= old(spec_currency_info<CoinType>().preburn_value);
    }
    spec schema PreservePreburnQueueExistence<CoinType> {
        /// The existence of the `PreburnQueue` resource is preserved.
        ensures forall addr: address:
            old(exists<PreburnQueue<CoinType>>(addr)) ==>
                exists<PreburnQueue<CoinType>>(addr);
    }
    spec schema PreservePreburnQueueAbsence<CoinType> {
        /// The absence of a `PreburnQueue` is preserved.
        /// > NB: As part of the upgrade process, we also tie this in with the
        ///       non-existence of a `Preburn` resource as well. Once the upgrade
        ///       process is complete this additional existence check can be removed.
        ensures forall addr: address:
            old(!(exists<PreburnQueue<CoinType>>(addr) || exists<Preburn<CoinType>>(addr))) ==>
                !exists<PreburnQueue<CoinType>>(addr);
    }

    spec module {
        /// Only burn functions can decrease the preburn value of currency [[H4]][PERMISSION].
        apply PreburnValueNotDecrease<CoinType> to *<CoinType>
            except burn<CoinType>, burn_with_capability<CoinType>, burn_with_resource_cap<CoinType>,
            burn_now<CoinType>, cancel_burn<CoinType>, cancel_burn_with_capability<CoinType>;

        /// Only preburn functions can increase the preburn value of currency [[H4]][PERMISSION].
        apply PreburnValueNotIncrease<CoinType> to *<CoinType>
            except preburn_to<CoinType>, preburn_with_resource<CoinType>;

        /// In order to successfully call the preburn functions, Preburn is required. Preburn must
        /// be only granted to a DesignatedDealer account [[H4]][PERMISSION]. Only `publish_preburn_queue_to_account` and `publish_preburn_queue`
        /// publishes `PreburnQueue`, which must abort if the account does not have the DesignatedDealer role [[H4]][PERMISSION].
        apply Roles::AbortsIfNotDesignatedDealer to publish_preburn_queue<CoinType>, publish_preburn_queue_to_account<CoinType>;
        apply PreservePreburnQueueAbsence<CoinType> to *<CoinType> except
            publish_preburn_queue<CoinType>,
            publish_preburn_queue_to_account<CoinType>;

        /// Only DesignatedDealer can have PreburnQueue [[H3]][PERMISSION].
        /// If an account has PreburnQueue, it is a DesignatedDealer account.
        /// > NB: during the transition this holds for both `Preburn` and `PreburnQueue` resources.
        invariant forall coin_type: type:
            forall addr1: address:
                exists<PreburnQueue<coin_type>>(addr1) || exists<Preburn<coin_type>>(addr1) ==>
                    Roles::spec_has_designated_dealer_role_addr(addr1);

        /// If there is a preburn resource published, it must have a value of zero.
        /// If there is a preburn resource published, there cannot also be a
        /// `PreburnQueue` resource published under that same account for the
        /// same currency.
        /// > NB: This invariant is part of the upgrade process, eventually
        ///       this will be removed once all DD's have been upgraded to
        ///       using the `PreburnQueue`.
        invariant forall coin_type: type, dd_addr: address
            where exists<Preburn<coin_type>>(dd_addr):
                global<Preburn<coin_type>>(dd_addr).to_burn.value == 0 &&
                !exists<PreburnQueue<coin_type>>(dd_addr);

        /// If there is a `PreburnQueue` resource published, then there cannot
        /// also be a `Preburn` resource for that same currency published under
        /// the same address.
        invariant forall coin_type: type, dd_addr: address
            where exists<PreburnQueue<coin_type>>(dd_addr):
                !exists<Preburn<coin_type>>(dd_addr);

        /// A `Preburn` resource can only be published holding a currency type.
        invariant forall addr: address, coin_type: type
            where exists<Preburn<coin_type>>(addr):
            spec_is_currency<coin_type>();

        /// A `PreburnQueue` resource can only be published holding a currency type.
        invariant forall addr: address, coin_type: type
            where exists<PreburnQueue<coin_type>>(addr):
            spec_is_currency<coin_type>();

        /// Preburn is not transferrable [[J4]][PERMISSION].
        apply PreservePreburnQueueExistence<CoinType> to *<CoinType>;

        /// resource struct `CurrencyInfo` is persistent
        invariant update forall coin_type: type, dr_addr: address
            where old(exists<CurrencyInfo<coin_type>>(dr_addr)):
                exists<CurrencyInfo<coin_type>>(dr_addr);

        /// resource struct `PreburnQueue<CoinType>` is persistent
        invariant update forall coin_type: type, tc_addr: address
            where old(exists<PreburnQueue<coin_type>>(tc_addr)):
                exists<PreburnQueue<coin_type>>(tc_addr);

        /// resource struct `MintCapability<CoinType>` is persistent
        invariant update forall coin_type: type, tc_addr: address
            where old(exists<MintCapability<coin_type>>(tc_addr)):
                exists<MintCapability<coin_type>>(tc_addr);
    }


    /// ## Update Exchange Rates
    spec schema ExchangeRateRemainsSame<CoinType> {
        /// The exchange rate to XDX stays constant.
        ensures old(spec_is_currency<CoinType>())
            ==> spec_currency_info<CoinType>().to_xdx_exchange_rate
                == old(spec_currency_info<CoinType>().to_xdx_exchange_rate);
    }
    spec module {
        /// The permission "UpdateExchangeRate(type)" is granted to TreasuryCompliance [[H5]][PERMISSION].
        apply Roles::AbortsIfNotTreasuryCompliance{account: tc_account} to update_xdx_exchange_rate<FromCoinType>;

        /// Only update_xdx_exchange_rate can change the exchange rate [[H5]][PERMISSION].
        apply ExchangeRateRemainsSame<CoinType> to *<CoinType>
            except update_xdx_exchange_rate<CoinType>;
    }

    /// # Helper Functions

    spec module {
        /// Checks whether currency is registered. Mirrors `Self::is_currency<CoinType>`.
        fun spec_is_currency<CoinType>(): bool {
            exists<CurrencyInfo<CoinType>>(@CurrencyInfo)
        }

        /// Returns currency information.
        fun spec_currency_info<CoinType>(): CurrencyInfo<CoinType> {
            global<CurrencyInfo<CoinType>>(@CurrencyInfo)
        }

        /// Specification version of `Self::approx_xdx_for_value`.
        fun spec_approx_xdx_for_value<CoinType>(value: num):  num {
            FixedPoint32::spec_multiply_u64(value, spec_xdx_exchange_rate<CoinType>())
        }

        fun spec_xdx_exchange_rate<CoinType>(): FixedPoint32 {
            global<CurrencyInfo<CoinType>>(@CurrencyInfo).to_xdx_exchange_rate
        }

        /// Checks whether the currency has a mint capability.  This is only relevant for
        /// SCS coins
        fun spec_has_mint_capability<CoinType>(addr: address): bool {
            exists<MintCapability<CoinType>>(addr)
        }

        /// Returns true if a BurnCapability for CoinType exists at addr.
        fun spec_has_burn_capability<CoinType>(addr: address): bool {
            exists<BurnCapability<CoinType>>(addr)
        }

        /// Returns the Preburn in the preburn queue.
        fun spec_make_preburn<CoinType>(amount: u64): Preburn<CoinType> {
            Preburn { to_burn: Diem { value: amount }}
        }
    }

}
