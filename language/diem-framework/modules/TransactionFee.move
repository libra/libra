/// Functions to initialize, accumulated, and burn transaction fees.
module DiemFramework::TransactionFee {
    use DiemFramework::XUS::XUS;
    use DiemFramework::XDX;
    use DiemFramework::Diem::{Self, Diem, Preburn};
    use DiemFramework::Roles;
    use DiemFramework::DiemTimestamp;
    use Std::Errors;
    use Std::Signer;

    /// The `TransactionFee` resource holds a preburn resource for each
    /// fiat `CoinType` that can be collected as a transaction fee.
    struct TransactionFee<phantom CoinType> has key {
        balance: Diem<CoinType>,
        preburn: Preburn<CoinType>,
    }

    /// A `TransactionFee` resource is not in the required state
    const ETRANSACTION_FEE: u64 = 0;

    /// Called in genesis. Sets up the needed resources to collect transaction fees from the
    /// `TransactionFee` resource with the TreasuryCompliance account.
    public fun initialize(
        tc_account: &signer,
    ) {
        DiemTimestamp::assert_genesis();
        Roles::assert_treasury_compliance(tc_account);
        // accept fees in all the currencies
        add_txn_fee_currency<XUS>(tc_account);
    }
    spec initialize {
        include DiemTimestamp::AbortsIfNotGenesis;
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};
        include AddTxnFeeCurrencyAbortsIf<XUS>;
        ensures is_initialized();
        ensures spec_transaction_fee<XUS>().balance.value == 0;
    }
    spec schema AddTxnFeeCurrencyAbortsIf<CoinType> {
        include Diem::AbortsIfNoCurrency<CoinType>;
        aborts_if exists<TransactionFee<CoinType>>(@TreasuryCompliance)
            with Errors::ALREADY_PUBLISHED;
    }

    public fun is_coin_initialized<CoinType>(): bool {
        exists<TransactionFee<CoinType>>(@TreasuryCompliance)
    }

    fun is_initialized(): bool {
        is_coin_initialized<XUS>()
    }

    /// Sets up the needed transaction fee state for a given `CoinType` currency by
    /// (1) configuring `tc_account` to accept `CoinType`
    /// (2) publishing a wrapper of the `Preburn<CoinType>` resource under `tc_account`
    public fun add_txn_fee_currency<CoinType>(tc_account: &signer) {
        Roles::assert_treasury_compliance(tc_account);
        Diem::assert_is_currency<CoinType>();
        assert(
            !is_coin_initialized<CoinType>(),
            Errors::already_published(ETRANSACTION_FEE)
        );
        move_to(
            tc_account,
            TransactionFee<CoinType> {
                balance: Diem::zero(),
                preburn: Diem::create_preburn(tc_account)
            }
        )
    }

    /// Deposit `coin` into the transaction fees bucket
    public fun pay_fee<CoinType>(coin: Diem<CoinType>) acquires TransactionFee {
        DiemTimestamp::assert_operating();
        assert(is_coin_initialized<CoinType>(), Errors::not_published(ETRANSACTION_FEE));
        let fees = borrow_global_mut<TransactionFee<CoinType>>(@TreasuryCompliance);
        Diem::deposit(&mut fees.balance, coin)
    }

    spec pay_fee {
        include DiemTimestamp::AbortsIfNotOperating;
        aborts_if !is_coin_initialized<CoinType>() with Errors::NOT_PUBLISHED;
        let fees = spec_transaction_fee<CoinType>().balance;
        let post post_fees = spec_transaction_fee<CoinType>().balance;
        include Diem::DepositAbortsIf<CoinType>{coin: fees, check: coin};
        ensures post_fees.value == fees.value + coin.value;
    }

    /// Preburns the transaction fees collected in the `CoinType` currency.
    /// If the `CoinType` is XDX, it unpacks the coin and preburns the
    /// underlying fiat.
    public fun burn_fees<CoinType>(
        tc_account: &signer,
    ) acquires TransactionFee {
        DiemTimestamp::assert_operating();
        Roles::assert_treasury_compliance(tc_account);
        assert(is_coin_initialized<CoinType>(), Errors::not_published(ETRANSACTION_FEE));
        if (XDX::is_xdx<CoinType>()) {
            // TODO: Once the composition of XDX is determined fill this in to
            // unpack and burn the backing coins of the XDX coin.
            abort Errors::invalid_state(ETRANSACTION_FEE)
        } else {
            // extract fees
            let fees = borrow_global_mut<TransactionFee<CoinType>>(@TreasuryCompliance);
            let coin = Diem::withdraw_all(&mut fees.balance);
            let burn_cap = Diem::remove_burn_capability<CoinType>(tc_account);
            // burn
            Diem::burn_now(
                coin,
                &mut fees.preburn,
                @TreasuryCompliance,
                &burn_cap
            );
            Diem::publish_burn_capability(tc_account, burn_cap);
        }
    }

    spec burn_fees {
        /// Must abort if the account does not have the TreasuryCompliance role [[H3]][PERMISSION].
        include Roles::AbortsIfNotTreasuryCompliance{account: tc_account};

        include DiemTimestamp::AbortsIfNotOperating;
        aborts_if !is_coin_initialized<CoinType>() with Errors::NOT_PUBLISHED;
        include if (XDX::spec_is_xdx<CoinType>()) BurnFeesXDX else BurnFeesNotXDX<CoinType>;

        /// The correct amount of fees is burnt and subtracted from market cap.
        ensures Diem::spec_market_cap<CoinType>()
            == old(Diem::spec_market_cap<CoinType>()) - old(spec_transaction_fee<CoinType>().balance.value);
        /// All the fees is burnt so the balance becomes 0.
        ensures spec_transaction_fee<CoinType>().balance.value == 0;
    }
    /// STUB: To be filled in at a later date once the makeup of the XDX has been determined.
    ///
    /// # Specification of the case where burn type is XDX.
    spec schema BurnFeesXDX {
        tc_account: signer;
        aborts_if true with Errors::INVALID_STATE;
    }
    /// # Specification of the case where burn type is not XDX.
    spec schema BurnFeesNotXDX<CoinType> {
        tc_account: signer;
        /// Must abort if the account does not have BurnCapability [[H3]][PERMISSION].
        include Diem::AbortsIfNoBurnCapability<CoinType>{account: tc_account};

        let fees = spec_transaction_fee<CoinType>();
        include Diem::BurnNowAbortsIf<CoinType>{coin: fees.balance, preburn: fees.preburn};

        /// tc_account retrieves BurnCapability [[H3]][PERMISSION].
        /// BurnCapability is not transferrable [[J3]][PERMISSION].
        ensures exists<Diem::BurnCapability<CoinType>>(Signer::spec_address_of(tc_account));
    }

    spec module {} // Switch documentation context to module level.

    /// # Initialization

    spec module {
        /// If time has started ticking, then `TransactionFee` resources have been initialized.
        invariant DiemTimestamp::is_operating() ==> is_initialized();
    }

    /// # Helper Function

    spec fun spec_transaction_fee<CoinType>(): TransactionFee<CoinType> {
        borrow_global<TransactionFee<CoinType>>(@TreasuryCompliance)
    }
}
