/// Module which manages account limits, like the amount of currency which can flow in or out over
/// a given time period.
module DiemFramework::AccountLimits {
    use DiemFramework::DiemTimestamp;
    use DiemFramework::Roles;
    use Std::Errors;
    use Std::Signer;

    /// An operations capability that restricts callers of this module since
    /// the operations can mutate account states.
    struct AccountLimitMutationCapability has store { }

    /// A resource specifying the account limits per-currency. There is a default
    /// "unlimited" `LimitsDefinition` resource for accounts published at`@DiemRoot`, but other
    /// accounts may have different account limit definitons. In such cases, they will have a
    /// `LimitsDefinition` published under their (root) account.
    struct LimitsDefinition<phantom CoinType> has key {
        /// The maximum inflow allowed during the specified time period.
        max_inflow: u64,
        /// The maximum outflow allowed during the specified time period.
        max_outflow: u64,
        /// Time period, specified in microseconds
        time_period: u64,
        /// The maximum amount that can be held
        max_holding: u64,
    }
    spec LimitsDefinition {
        invariant max_inflow > 0;
        invariant max_outflow > 0;
        invariant time_period > 0;
        invariant max_holding > 0;
    }

    /// A struct holding account transaction information for the time window
    /// starting at `window_start` and lasting for the `time_period` specified
    /// in the limits definition at `limit_address`.
    struct Window<phantom CoinType> has key {
        /// Time window start in microseconds
        window_start: u64,
        /// The inflow during this time window
        window_inflow: u64,
        /// The inflow during this time window
        window_outflow: u64,
        /// The balance that this account has held during this time period.
        tracked_balance: u64,
        /// address storing the LimitsDefinition resource that governs this window
        limit_address: address,
    }

    /// The `LimitsDefinition` resource is in an invalid state
    const ELIMITS_DEFINITION: u64 = 0;
    /// The `Window` resource is in an invalid state
    const EWINDOW: u64 = 1;

    /// 24 hours in microseconds
    const ONE_DAY: u64 = 86400000000;
    const MAX_U64: u64 = 18446744073709551615u64;

    /// Grant a capability to call this module. This does not necessarily
    /// need to be a unique capability.
    public fun grant_mutation_capability(dr_account: &signer): AccountLimitMutationCapability {
        DiemTimestamp::assert_genesis();
        Roles::assert_diem_root(dr_account);
        AccountLimitMutationCapability{}
    }
    spec grant_mutation_capability {
        include DiemTimestamp::AbortsIfNotGenesis;
        include Roles::AbortsIfNotDiemRoot{account: dr_account};
    }

    /// Determines if depositing `amount` of `CoinType` coins into the
    /// account at `addr` is amenable with their account limits.
    /// Returns false if this deposit violates the account limits.
    public fun update_deposit_limits<CoinType>(
        amount: u64,
        addr: address,
        _cap: &AccountLimitMutationCapability,
    ): bool acquires LimitsDefinition, Window {
        assert(exists<Window<CoinType>>(addr), Errors::not_published(EWINDOW));
        can_receive_and_update_window<CoinType>(
            amount,
            borrow_global_mut<Window<CoinType>>(addr),
        )
    }
    spec update_deposit_limits {
        pragma opaque;
        modifies global<Window<CoinType>>(addr);
        include UpdateDepositLimitsAbortsIf<CoinType>;
        include CanReceiveEnsures<CoinType>{receiving: global<Window<CoinType>>(addr)};
    }
    spec schema UpdateDepositLimitsAbortsIf<CoinType> {
        amount: u64;
        addr: address;
        include AbortsIfNoWindow<CoinType>;
        include CanReceiveAbortsIf<CoinType>{receiving: global<Window<CoinType>>(addr)};
    }
    spec schema AbortsIfNoWindow<CoinType> {
        addr: address;
        aborts_if !exists<Window<CoinType>>(addr) with Errors::NOT_PUBLISHED;
    }
    spec fun spec_update_deposit_limits<CoinType>(amount: u64, addr: address): bool {
        spec_receiving_limits_ok(global<Window<CoinType>>(addr), amount)
    }

    /// Determine if withdrawing `amount` of `CoinType` coins from
    /// the account at `addr` would violate the account limits for that account.
    /// Returns `false` if this withdrawal violates account limits.
    public fun update_withdrawal_limits<CoinType>(
        amount: u64,
        addr: address,
        _cap: &AccountLimitMutationCapability,
    ): bool acquires LimitsDefinition, Window {
        assert(exists<Window<CoinType>>(addr), Errors::not_published(EWINDOW));
        can_withdraw_and_update_window<CoinType>(
            amount,
            borrow_global_mut<Window<CoinType>>(addr),
        )
    }
    spec update_withdrawal_limits {
        pragma opaque;
        modifies global<Window<CoinType>>(addr);
        include UpdateWithdrawalLimitsAbortsIf<CoinType>;
        include CanWithdrawEnsures<CoinType>{sending: global<Window<CoinType>>(addr)};
    }
    spec schema UpdateWithdrawalLimitsAbortsIf<CoinType> {
        amount: u64;
        addr: address;
        include AbortsIfNoWindow<CoinType>;
        include CanWithdrawAbortsIf<CoinType>{sending: global<Window<CoinType>>(addr)};
    }
    spec fun spec_update_withdrawal_limits<CoinType>(amount: u64, addr: address): bool {
        spec_withdrawal_limits_ok(global<Window<CoinType>>(addr), amount)
    }

    /// All accounts that could be subject to account limits will have a
    /// `Window` for each currency they can hold published at the top level.
    /// Root accounts for multi-account entities will hold this resource at
    /// their root/parent account.
    public fun publish_window<CoinType>(
        dr_account: &signer,
        to_limit: &signer,
        limit_address: address,
    ) {
        Roles::assert_diem_root(dr_account);
        assert(exists<LimitsDefinition<CoinType>>(limit_address), Errors::not_published(ELIMITS_DEFINITION));
        Roles::assert_parent_vasp_or_child_vasp(to_limit);
        assert(
            !exists<Window<CoinType>>(Signer::address_of(to_limit)),
            Errors::already_published(EWINDOW)
        );
        move_to(
            to_limit,
            Window<CoinType> {
                window_start: current_time(),
                window_inflow: 0,
                window_outflow: 0,
                tracked_balance: 0,
                limit_address,
            }
        )
    }
    spec publish_window {
        include PublishWindowAbortsIf<CoinType>;
    }
    spec schema PublishWindowAbortsIf<CoinType> {
        dr_account: signer;
        to_limit: signer;
        limit_address: address;
        /// Only ParentVASP and ChildVASP can have the account limits [[E1]][ROLE][[E2]][ROLE][[E3]][ROLE][[E4]][ROLE][[E5]][ROLE][[E6]][ROLE][[E7]][ROLE].
        include Roles::AbortsIfNotParentVaspOrChildVasp{account: to_limit};

        include Roles::AbortsIfNotDiemRoot{account: dr_account};
        aborts_if !exists<LimitsDefinition<CoinType>>(limit_address) with Errors::NOT_PUBLISHED;
        aborts_if exists<Window<CoinType>>(Signer::spec_address_of(to_limit)) with Errors::ALREADY_PUBLISHED;
    }

    /// Unrestricted limits are represented by setting all fields in the
    /// limits definition to `MAX_U64`. Anyone can publish an unrestricted
    /// limits since no windows will point to this limits definition unless the
    /// TC account, or a caller with access to a `&AccountLimitMutationCapability` points a
    /// window to it. Additionally, the TC controls the values held within this
    /// resource once it's published.
    public fun publish_unrestricted_limits<CoinType>(publish_account: &signer) {
        assert(
            !exists<LimitsDefinition<CoinType>>(Signer::address_of(publish_account)),
            Errors::already_published(ELIMITS_DEFINITION)
        );
        move_to(
            publish_account,
            LimitsDefinition<CoinType> {
                max_inflow: MAX_U64,
                max_outflow: MAX_U64,
                max_holding: MAX_U64,
                time_period: ONE_DAY,
            }
        )
    }
    spec publish_unrestricted_limits {
        /// TODO: turned off verification until we solve the
        /// generic type/specific invariant issue. Similar to
        /// in DiemConfig, this function violates an invariant in
        /// XUS about LimitsDefinition<XUS>.
        pragma verify = false;
        include PublishUnrestrictedLimitsAbortsIf<CoinType>;
    }
    spec schema PublishUnrestrictedLimitsAbortsIf<CoinType> {
        publish_account: signer;
        aborts_if exists<LimitsDefinition<CoinType>>(Signer::spec_address_of(publish_account))
            with Errors::ALREADY_PUBLISHED;
    }
    spec schema PublishUnrestrictedLimitsEnsures<CoinType> {
        publish_account: signer;
        ensures exists<LimitsDefinition<CoinType>>(Signer::spec_address_of(publish_account));
    }

    /// Updates the `LimitsDefinition<CoinType>` resource at `limit_address`.
    /// If any of the field arguments is `0` the corresponding field is not updated.
    ///
    /// TODO: This should be specified.
    public fun update_limits_definition<CoinType>(
        tc_account: &signer,
        limit_address: address,
        new_max_inflow: u64,
        new_max_outflow: u64,
        new_max_holding_balance: u64,
        new_time_period: u64,
    ) acquires LimitsDefinition {
        Roles::assert_treasury_compliance(tc_account);
        // As we don't have Optionals for txn scripts, in update_account_limit_definition.move
        // we use 0 value to represent a None (ie no update to that variable)
        assert(exists<LimitsDefinition<CoinType>>(limit_address), Errors::not_published(ELIMITS_DEFINITION));
        let limits_def = borrow_global_mut<LimitsDefinition<CoinType>>(limit_address);
        if (new_max_inflow > 0) { limits_def.max_inflow = new_max_inflow };
        if (new_max_outflow > 0) { limits_def.max_outflow = new_max_outflow };
        if (new_max_holding_balance > 0) { limits_def.max_holding = new_max_holding_balance };
        if (new_time_period > 0) { limits_def.time_period = new_time_period };
    }

    /// Update either the `tracked_balance` or `limit_address` fields of the
    /// `Window<CoinType>` stored under `window_address`.
    /// * Since we don't track balances of accounts before they are limited, once
    ///   they do become limited the approximate balance in `CoinType` held by
    ///   the entity across all of its accounts will need to be set by the association.
    ///   if `aggregate_balance` is set to zero the field is not updated.
    /// * This updates the `limit_address` in the window resource to a new limits definition at
    ///   `new_limit_address`. If the `aggregate_balance` needs to be updated
    ///   but the `limit_address` should remain the same, the current
    ///   `limit_address` needs to be passed in for `new_limit_address`.
    /// TODO(wrwg): specify
    public fun update_window_info<CoinType>(
        tc_account: &signer,
        window_address: address,
        aggregate_balance: u64,
        new_limit_address: address,
    ) acquires Window {
        Roles::assert_treasury_compliance(tc_account);
        let window = borrow_global_mut<Window<CoinType>>(window_address);
        if (aggregate_balance != 0)  { window.tracked_balance = aggregate_balance };
        assert(exists<LimitsDefinition<CoinType>>(new_limit_address), Errors::not_published(ELIMITS_DEFINITION));
        window.limit_address = new_limit_address;
    }

    ///////////////////////////////////////////////////////////////////////////
    // Internal utiility functions
    ///////////////////////////////////////////////////////////////////////////

    /// If the time window starting at `window.window_start` and lasting for
    /// `limits_definition.time_period` has elapsed, resets the window and
    /// the inflow and outflow records.
    fun reset_window<CoinType>(window: &mut Window<CoinType>, limits_definition: &LimitsDefinition<CoinType>) {
        let current_time = DiemTimestamp::now_microseconds();
        assert(window.window_start <= MAX_U64 - limits_definition.time_period, Errors::limit_exceeded(EWINDOW));
        if (current_time > window.window_start + limits_definition.time_period) {
            window.window_start = current_time;
            window.window_inflow = 0;
            window.window_outflow = 0;
        }
    }
    spec reset_window {
        pragma opaque;
        include ResetWindowAbortsIf<CoinType>;
        include ResetWindowEnsures<CoinType>;
    }
    spec schema ResetWindowAbortsIf<CoinType> {
        window: Window<CoinType>;
        limits_definition: LimitsDefinition<CoinType>;
        include DiemTimestamp::AbortsIfNotOperating;
        aborts_if window.window_start + limits_definition.time_period > max_u64() with Errors::LIMIT_EXCEEDED;
    }
    spec schema ResetWindowEnsures<CoinType> {
        window: Window<CoinType>;
        limits_definition: LimitsDefinition<CoinType>;
        ensures window == old(spec_window_reset_with_limits(window, limits_definition));
    }
    spec module {
        fun spec_window_expired<CoinType>(
            window: Window<CoinType>,
            limits_definition: LimitsDefinition<CoinType>
        ): bool {
            DiemTimestamp::spec_now_microseconds() > window.window_start + limits_definition.time_period
        }
        fun spec_window_reset_with_limits<CoinType>(
            window: Window<CoinType>,
            limits_definition: LimitsDefinition<CoinType>
        ): Window<CoinType> {
            if (spec_window_expired<CoinType>(window, limits_definition)) {
                Window<CoinType>{
                    limit_address: window.limit_address,
                    tracked_balance: window.tracked_balance,
                    window_start: DiemTimestamp::spec_now_microseconds(),
                    window_inflow: 0,
                    window_outflow: 0
                }
            } else {
                window
            }
        }
    }

    /// Verify that the receiving account tracked by the `receiving` window
    /// can receive `amount` funds without violating requirements
    /// specified the `limits_definition` passed in.
    /// If the receipt of `amount` doesn't violate the limits `amount` of
    /// `CoinType` is recorded as received in the given `receiving` window.
    fun can_receive_and_update_window<CoinType>(
        amount: u64,
        receiving: &mut Window<CoinType>,
    ): bool acquires LimitsDefinition {
        assert(exists<LimitsDefinition<CoinType>>(receiving.limit_address), Errors::not_published(ELIMITS_DEFINITION));
        let limits_definition = borrow_global<LimitsDefinition<CoinType>>(receiving.limit_address);
        // If the limits are unrestricted then don't do any more work.
        if (is_unrestricted(limits_definition)) return true;

        reset_window(receiving, limits_definition);
        // Check that the inflow is OK
        // TODO(wrwg): instead of aborting if the below additions overflow, we should perhaps just have ok false.
        assert(receiving.window_inflow <= MAX_U64 - amount, Errors::limit_exceeded(EWINDOW));
        let inflow_ok = (receiving.window_inflow + amount) <= limits_definition.max_inflow;
        // Check that the holding after the deposit is OK
        assert(receiving.tracked_balance <= MAX_U64 - amount, Errors::limit_exceeded(EWINDOW));
        let holding_ok = (receiving.tracked_balance + amount) <= limits_definition.max_holding;
        // The account with `receiving` window can receive the payment so record it.
        if (inflow_ok && holding_ok) {
            receiving.window_inflow = receiving.window_inflow + amount;
            receiving.tracked_balance = receiving.tracked_balance + amount;
        };
        inflow_ok && holding_ok
    }
    spec can_receive_and_update_window {
        pragma opaque;
        include CanReceiveAbortsIf<CoinType>;
        include CanReceiveEnsures<CoinType>;
    }
    spec schema CanReceiveAbortsIf<CoinType> {
        amount: num;
        receiving: Window<CoinType>;
        aborts_if !exists<LimitsDefinition<CoinType>>(receiving.limit_address) with Errors::NOT_PUBLISHED;
        include !spec_window_unrestricted<CoinType>(receiving) ==> CanReceiveRestrictedAbortsIf<CoinType>;
    }
    spec schema CanReceiveRestrictedAbortsIf<CoinType> {
        amount: num;
        receiving: Window<CoinType>;
        include ResetWindowAbortsIf<CoinType>{
            window: receiving,
            limits_definition: spec_window_limits<CoinType>(receiving)
        };
        aborts_if spec_window_reset(receiving).window_inflow + amount > max_u64() with Errors::LIMIT_EXCEEDED;
        aborts_if spec_window_reset(receiving).tracked_balance + amount > max_u64() with Errors::LIMIT_EXCEEDED;
    }
    spec schema CanReceiveEnsures<CoinType> {
        amount: num;
        receiving: Window<CoinType>;
        result: bool;
        ensures result == spec_receiving_limits_ok(old(receiving), amount);
        ensures
            if (result && !spec_window_unrestricted(old(receiving)))
                receiving == spec_update_inflow(spec_window_reset(old(receiving)), amount)
            else
                receiving == spec_window_reset(old(receiving)) || receiving == old(receiving);
    }
    /// Returns the limits associated with this window.
    spec fun spec_window_limits<CoinType>(window: Window<CoinType>): LimitsDefinition<CoinType> {
        global<LimitsDefinition<CoinType>>(window.limit_address)
    }
    /// Returns true of the window has unrestricted limits.
    spec fun spec_window_unrestricted<CoinType>(window: Window<CoinType>): bool {
        spec_is_unrestricted(spec_window_limits<CoinType>(window))
    }
    /// Resets wrapping variables of the given window.
    spec fun spec_window_reset<CoinType>(window: Window<CoinType>): Window<CoinType> {
        spec_window_reset_with_limits(window, spec_window_limits<CoinType>(window))
    }
    /// Checks whether receiving limits are satisfied.
    spec fun spec_receiving_limits_ok<CoinType>(receiving: Window<CoinType>, amount: u64): bool {
        spec_window_unrestricted(receiving) ||
            spec_window_reset(receiving).window_inflow + amount
                    <= spec_window_limits(receiving).max_inflow &&
            spec_window_reset(receiving).tracked_balance + amount
                    <= spec_window_limits(receiving).max_holding
    }
    spec fun spec_update_inflow<CoinType>(receiving: Window<CoinType>, amount: u64): Window<CoinType> {
        update_field(update_field(receiving,
            window_inflow, receiving.window_inflow + amount),
            tracked_balance, receiving.tracked_balance + amount)
    }

    /// Verify that `amount` can be withdrawn from the account tracked
    /// by the `sending` window without violating any limits specified
    /// in its `limits_definition`.
    /// If the withdrawal of `amount` doesn't violate the limits `amount` of
    /// `CoinType` is recorded as withdrawn in the given `sending` window.
    fun can_withdraw_and_update_window<CoinType>(
        amount: u64,
        sending: &mut Window<CoinType>,
    ): bool acquires LimitsDefinition {
        assert(exists<LimitsDefinition<CoinType>>(sending.limit_address), Errors::not_published(ELIMITS_DEFINITION));
        let limits_definition = borrow_global<LimitsDefinition<CoinType>>(sending.limit_address);
        // If the limits are unrestricted then don't do any more work.
        if (is_unrestricted(limits_definition)) return true;

        reset_window(sending, limits_definition);
        // Check outflow is OK
        assert(sending.window_outflow <= MAX_U64 - amount, Errors::limit_exceeded(EWINDOW));
        let outflow_ok = sending.window_outflow + amount <= limits_definition.max_outflow;
        // Flow is OK, so record it.
        if (outflow_ok) {
            sending.window_outflow = sending.window_outflow + amount;
            sending.tracked_balance = if (amount >= sending.tracked_balance) 0
                                       else sending.tracked_balance - amount;
        };
        outflow_ok
    }
    spec can_withdraw_and_update_window {
        pragma opaque;
        include CanWithdrawAbortsIf<CoinType>;
        include CanWithdrawEnsures<CoinType>;
    }
    spec schema CanWithdrawAbortsIf<CoinType> {
        amount: u64;
        sending: &mut Window<CoinType>;
        aborts_if !exists<LimitsDefinition<CoinType>>(sending.limit_address) with Errors::NOT_PUBLISHED;
        include !spec_window_unrestricted(sending) ==> CanWithdrawRestrictedAbortsIf<CoinType>;
    }
    spec schema CanWithdrawRestrictedAbortsIf<CoinType> {
        amount: u64;
        sending: &mut Window<CoinType>;
        include ResetWindowAbortsIf<CoinType>{
            window: sending,
            limits_definition: spec_window_limits<CoinType>(sending)
        };
        aborts_if spec_window_reset(sending).window_outflow + amount > MAX_U64 with Errors::LIMIT_EXCEEDED;
    }
    spec schema CanWithdrawEnsures<CoinType> {
        result: bool;
        amount: u64;
        sending: &mut Window<CoinType>;
        ensures result == spec_withdrawal_limits_ok(old(sending), amount);
        ensures
            if (result && !spec_window_unrestricted(old(sending)))
                sending == spec_update_outflow(spec_window_reset(old(sending)), amount)
            else
                sending == spec_window_reset(old(sending)) || sending == old(sending);
    }
    /// Check whether withdrawal limits are satisfied.
    spec fun spec_withdrawal_limits_ok<CoinType>(sending: Window<CoinType>, amount: u64): bool {
        spec_window_unrestricted(sending) ||
        spec_window_reset(sending).window_outflow + amount <= spec_window_limits(sending).max_outflow
    }
    /// Update outflow.
    spec fun spec_update_outflow<CoinType>(sending: Window<CoinType>, amount: u64): Window<CoinType> {
        update_field(update_field(sending,
            window_outflow, sending.window_outflow + amount),
            tracked_balance, if (amount >= sending.tracked_balance) 0
                             else sending.tracked_balance - amount)
    }

    /// Determine whether the `LimitsDefinition` resource has no restrictions.
    fun is_unrestricted<CoinType>(limits_def: &LimitsDefinition<CoinType>): bool {
        limits_def.max_inflow == MAX_U64 &&
        limits_def.max_outflow == MAX_U64 &&
        limits_def.max_holding == MAX_U64 &&
        limits_def.time_period == ONE_DAY
    }
    spec is_unrestricted {
        pragma opaque;
        aborts_if false;
        ensures result == spec_is_unrestricted(limits_def);
    }
    spec module {
        /// Checks whether the limits definition is unrestricted.
        fun spec_is_unrestricted<CoinType>(limits_def: LimitsDefinition<CoinType>): bool {
            limits_def.max_inflow == max_u64() &&
            limits_def.max_outflow == max_u64() &&
            limits_def.max_holding == max_u64() &&
            limits_def.time_period == 86400000000
        }
    }

    public fun limits_definition_address<CoinType>(addr: address): address acquires Window {
        borrow_global<Window<CoinType>>(addr).limit_address
    }

    public fun has_limits_published<CoinType>(addr: address): bool {
        exists<LimitsDefinition<CoinType>>(addr)
    }

    public fun has_window_published<CoinType>(addr: address): bool {
        exists<Window<CoinType>>(addr)
    }
    spec has_window_published {
        ensures result == spec_has_window_published<CoinType>(addr);
    }
    spec module {
        fun spec_has_window_published<CoinType>(addr: address): bool {
            exists<Window<CoinType>>(addr)
        }
    }

    fun current_time(): u64 {
        if (DiemTimestamp::is_genesis()) 0 else DiemTimestamp::now_microseconds()
    }

    // =================================================================
    // Module Specification

    spec module {} // Switch to module documentation context

    spec module {
        /// `LimitsDefinition<CoinType>` persists after publication.
        invariant update
            forall addr: address, coin_type: type where old(exists<LimitsDefinition<coin_type>>(addr)):
                exists<LimitsDefinition<coin_type>>(addr);

        /// `Window<CoinType>` persists after publication
        invariant update
            forall window_addr: address, coin_type: type where old(exists<Window<coin_type>>(window_addr)):
                exists<Window<coin_type>>(window_addr);

        /// Invariant that `LimitsDefinition` exists if a `Window` exists.
        invariant
           forall window_addr: address, coin_type: type where exists<Window<coin_type>>(window_addr):
                exists<LimitsDefinition<coin_type>>(global<Window<coin_type>>(window_addr).limit_address);
    }

    /// # Access Control

    spec module {
        /// Only ParentVASP and ChildVASP can have the account limits [[E1]][ROLE][[E2]][ROLE][[E3]][ROLE][[E4]][ROLE][[E5]][ROLE][[E6]][ROLE][[E7]][ROLE].
        invariant
            forall addr: address, coin_type: type where exists<Window<coin_type>>(addr):
                exists<Roles::RoleId>(addr) &&
                (global<Roles::RoleId>(addr).role_id == Roles::PARENT_VASP_ROLE_ID ||
                    global<Roles::RoleId>(addr).role_id == Roles::CHILD_VASP_ROLE_ID);
    }

}
