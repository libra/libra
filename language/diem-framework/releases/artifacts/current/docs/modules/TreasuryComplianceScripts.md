
<a name="0x1_TreasuryComplianceScripts"></a>

# Module `0x1::TreasuryComplianceScripts`

This module holds scripts relating to treasury and compliance-related
activities in the Diem Framework.

Only accounts with a role of <code>Roles::TREASURY_COMPLIANCE</code> and
<code>Roles::DESIGNATED_DEALER</code> can (successfully) use the scripts in this
module. The exact role required for a transaction is determined on a
per-transaction basis.


-  [Function `cancel_burn_with_amount`](#0x1_TreasuryComplianceScripts_cancel_burn_with_amount)
    -  [Summary](#@Summary_0)
    -  [Technical Description](#@Technical_Description_1)
    -  [Events](#@Events_2)
    -  [Parameters](#@Parameters_3)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_4)
    -  [Related Scripts](#@Related_Scripts_5)
-  [Function `burn_with_amount`](#0x1_TreasuryComplianceScripts_burn_with_amount)
    -  [Summary](#@Summary_6)
    -  [Technical Description](#@Technical_Description_7)
    -  [Events](#@Events_8)
    -  [Parameters](#@Parameters_9)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_10)
    -  [Related Scripts](#@Related_Scripts_11)
-  [Function `preburn`](#0x1_TreasuryComplianceScripts_preburn)
    -  [Summary](#@Summary_12)
    -  [Technical Description](#@Technical_Description_13)
    -  [Events](#@Events_14)
    -  [Parameters](#@Parameters_15)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_16)
    -  [Related Scripts](#@Related_Scripts_17)
-  [Function `burn_txn_fees`](#0x1_TreasuryComplianceScripts_burn_txn_fees)
    -  [Summary](#@Summary_18)
    -  [Technical Description](#@Technical_Description_19)
    -  [Events](#@Events_20)
    -  [Parameters](#@Parameters_21)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_22)
    -  [Related Scripts](#@Related_Scripts_23)
-  [Function `tiered_mint`](#0x1_TreasuryComplianceScripts_tiered_mint)
    -  [Summary](#@Summary_24)
    -  [Technical Description](#@Technical_Description_25)
    -  [Events](#@Events_26)
    -  [Parameters](#@Parameters_27)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_28)
    -  [Related Scripts](#@Related_Scripts_29)
-  [Function `freeze_account`](#0x1_TreasuryComplianceScripts_freeze_account)
    -  [Summary](#@Summary_30)
    -  [Technical Description](#@Technical_Description_31)
    -  [Events](#@Events_32)
    -  [Parameters](#@Parameters_33)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_34)
    -  [Related Scripts](#@Related_Scripts_35)
-  [Function `unfreeze_account`](#0x1_TreasuryComplianceScripts_unfreeze_account)
    -  [Summary](#@Summary_36)
    -  [Technical Description](#@Technical_Description_37)
    -  [Events](#@Events_38)
    -  [Parameters](#@Parameters_39)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_40)
    -  [Related Scripts](#@Related_Scripts_41)
-  [Function `update_dual_attestation_limit`](#0x1_TreasuryComplianceScripts_update_dual_attestation_limit)
    -  [Summary](#@Summary_42)
    -  [Technical Description](#@Technical_Description_43)
    -  [Parameters](#@Parameters_44)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_45)
    -  [Related Scripts](#@Related_Scripts_46)
-  [Function `update_exchange_rate`](#0x1_TreasuryComplianceScripts_update_exchange_rate)
    -  [Summary](#@Summary_47)
    -  [Technical Description](#@Technical_Description_48)
    -  [Parameters](#@Parameters_49)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_50)
    -  [Related Scripts](#@Related_Scripts_51)
-  [Function `update_minting_ability`](#0x1_TreasuryComplianceScripts_update_minting_ability)
    -  [Summary](#@Summary_52)
    -  [Technical Description](#@Technical_Description_53)
    -  [Parameters](#@Parameters_54)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_55)
    -  [Related Scripts](#@Related_Scripts_56)
-  [Function `add_vasp_domain`](#0x1_TreasuryComplianceScripts_add_vasp_domain)
    -  [Summary](#@Summary_57)
    -  [Technical Description](#@Technical_Description_58)
    -  [Parameters](#@Parameters_59)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_60)
-  [Function `remove_vasp_domain`](#0x1_TreasuryComplianceScripts_remove_vasp_domain)
    -  [Summary](#@Summary_61)
    -  [Technical Description](#@Technical_Description_62)
    -  [Parameters](#@Parameters_63)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_64)


<pre><code><b>use</b> <a href="AccountFreezing.md#0x1_AccountFreezing">0x1::AccountFreezing</a>;
<b>use</b> <a href="Diem.md#0x1_Diem">0x1::Diem</a>;
<b>use</b> <a href="DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
<b>use</b> <a href="DualAttestation.md#0x1_DualAttestation">0x1::DualAttestation</a>;
<b>use</b> <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">0x1::FixedPoint32</a>;
<b>use</b> <a href="SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
<b>use</b> <a href="TransactionFee.md#0x1_TransactionFee">0x1::TransactionFee</a>;
<b>use</b> <a href="VASPDomain.md#0x1_VASPDomain">0x1::VASPDomain</a>;
</code></pre>



<a name="0x1_TreasuryComplianceScripts_cancel_burn_with_amount"></a>

## Function `cancel_burn_with_amount`


<a name="@Summary_0"></a>

### Summary

Cancels and returns the coins held in the preburn area under
<code>preburn_address</code>, which are equal to the <code>amount</code> specified in the transaction. Finds the first preburn
resource with the matching amount and returns the funds to the <code>preburn_address</code>'s balance.
Can only be successfully sent by an account with Treasury Compliance role.


<a name="@Technical_Description_1"></a>

### Technical Description

Cancels and returns all coins held in the <code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource under the <code>preburn_address</code> and
return the funds to the <code>preburn_address</code> account's <code><a href="DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Token&gt;</code>.
The transaction must be sent by an <code>account</code> with a <code><a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code>
resource published under it. The account at <code>preburn_address</code> must have a
<code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource published under it, and its value must be nonzero. The transaction removes
the entire balance held in the <code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource, and returns it back to the account's
<code><a href="DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Token&gt;</code> under <code>preburn_address</code>. Due to this, the account at
<code>preburn_address</code> must already have a balance in the <code>Token</code> currency published
before this script is called otherwise the transaction will fail.


<a name="@Events_2"></a>

### Events

The successful execution of this transaction will emit:
* A <code><a href="Diem.md#0x1_Diem_CancelBurnEvent">Diem::CancelBurnEvent</a></code> on the event handle held in the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;</code>
resource's <code>burn_events</code> published under <code>0xA550C18</code>.
* A <code><a href="DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> on the <code>preburn_address</code>'s
<code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> event handle with both the <code>payer</code> and <code>payee</code>
being <code>preburn_address</code>.


<a name="@Parameters_3"></a>

### Parameters

| Name              | Type      | Description                                                                                                                          |
| ------            | ------    | -------------                                                                                                                        |
| <code>Token</code>           | Type      | The Move type for the <code>Token</code> currenty that burning is being cancelled for. <code>Token</code> must be an already-registered currency on-chain. |
| <code>account</code>         | <code>signer</code>  | The signer of the sending account of this transaction, must have a burn capability for <code>Token</code> published under it.                   |
| <code>preburn_address</code> | <code>address</code> | The address where the coins to-be-burned are currently held.                                                                         |
| <code>amount</code>          | <code>u64</code>     | The amount to be cancelled.                                                                                                          |


<a name="@Common_Abort_Conditions_4"></a>

### Common Abort Conditions

| Error Category                | Error Reason                                     | Description                                                                                                                         |
| ----------------              | --------------                                   | -------------                                                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a></code> | <code><a href="Diem.md#0x1_Diem_EBURN_CAPABILITY">Diem::EBURN_CAPABILITY</a></code>                         | The sending <code>account</code> does not have a <code><a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code> published under it.                                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="Diem.md#0x1_Diem_EPREBURN_NOT_FOUND">Diem::EPREBURN_NOT_FOUND</a></code>                       | The <code><a href="Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource under <code>preburn_address</code> does not contain a preburn request with a value matching <code>amount</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="Diem.md#0x1_Diem_EPREBURN_QUEUE">Diem::EPREBURN_QUEUE</a></code>                           | The account at <code>preburn_address</code> does not have a <code><a href="Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource published under it.                           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                           | The specified <code>Token</code> is not a registered currency on-chain.                                                                        |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYEE_CANT_ACCEPT_CURRENCY_TYPE">DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE</a></code>  | The account at <code>preburn_address</code> doesn't have a balance resource for <code>Token</code>.                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>      | <code><a href="DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>           | The depositing of the funds held in the prebun area would exceed the <code>account</code>'s account limits.                                    |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="DualAttestation.md#0x1_DualAttestation_EPAYEE_COMPLIANCE_KEY_NOT_SET">DualAttestation::EPAYEE_COMPLIANCE_KEY_NOT_SET</a></code> | The <code>account</code> does not have a compliance key set on it but dual attestion checking was performed.                                   |


<a name="@Related_Scripts_5"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_txn_fees">TreasuryComplianceScripts::burn_txn_fees</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_with_amount">TreasuryComplianceScripts::burn_with_amount</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_preburn">TreasuryComplianceScripts::preburn</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">cancel_burn_with_amount</a>&lt;Token&gt;(account: signer, preburn_address: address, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">cancel_burn_with_amount</a>&lt;Token&gt;(account: signer, preburn_address: address, amount: u64) {
    <a href="DiemAccount.md#0x1_DiemAccount_cancel_burn">DiemAccount::cancel_burn</a>&lt;Token&gt;(&account, preburn_address, amount)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CancelBurnAbortsIf">DiemAccount::CancelBurnAbortsIf</a>&lt;Token&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEnsures">Diem::CancelBurnWithCapEnsures</a>&lt;Token&gt;;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_DepositEnsures">DiemAccount::DepositEnsures</a>&lt;Token&gt;{payee: preburn_address};
<b>let</b> total_preburn_value = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;&gt;(
    @CurrencyInfo
).preburn_value;
<b>let</b> post post_total_preburn_value = <b>global</b>&lt;<a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;&gt;(
    @CurrencyInfo
).preburn_value;
<b>let</b> balance_at_addr = <a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Token&gt;(preburn_address);
<b>let</b> post post_balance_at_addr = <a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Token&gt;(preburn_address);
</code></pre>


The total value of preburn for <code>Token</code> should decrease by the preburned amount.


<pre><code><b>ensures</b> post_total_preburn_value == total_preburn_value - amount;
</code></pre>


The balance of <code>Token</code> at <code>preburn_address</code> should increase by the preburned amount.


<pre><code><b>ensures</b> post_balance_at_addr == balance_at_addr + amount;
<b>include</b> <a href="Diem.md#0x1_Diem_CancelBurnWithCapEmits">Diem::CancelBurnWithCapEmits</a>&lt;Token&gt;;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_DepositEmits">DiemAccount::DepositEmits</a>&lt;Token&gt;{
    payer: preburn_address,
    payee: preburn_address,
    amount: amount,
    metadata: x""
};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>;
</code></pre>


**Access Control:**
Only the account with the burn capability can cancel burning [[H3]][PERMISSION].


<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoBurnCapability">Diem::AbortsIfNoBurnCapability</a>&lt;Token&gt;{account: account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_burn_with_amount"></a>

## Function `burn_with_amount`


<a name="@Summary_6"></a>

### Summary

Burns the coins held in a preburn resource in the preburn queue at the
specified preburn address, which are equal to the <code>amount</code> specified in the
transaction. Finds the first relevant outstanding preburn request with
matching amount and removes the contained coins from the system. The sending
account must be the Treasury Compliance account.
The account that holds the preburn queue resource will normally be a Designated
Dealer, but there are no enforced requirements that it be one.


<a name="@Technical_Description_7"></a>

### Technical Description

This transaction permanently destroys all the coins of <code>Token</code> type
stored in the <code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource published under the
<code>preburn_address</code> account address.

This transaction will only succeed if the sending <code>account</code> has a
<code><a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code>, and a <code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource
exists under <code>preburn_address</code>, with a non-zero <code>to_burn</code> field. After the successful execution
of this transaction the <code>total_value</code> field in the
<code><a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;</code> resource published under <code>0xA550C18</code> will be
decremented by the value of the <code>to_burn</code> field of the preburn resource
under <code>preburn_address</code> immediately before this transaction, and the
<code>to_burn</code> field of the preburn resource will have a zero value.


<a name="@Events_8"></a>

### Events

The successful execution of this transaction will emit a <code><a href="Diem.md#0x1_Diem_BurnEvent">Diem::BurnEvent</a></code> on the event handle
held in the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;</code> resource's <code>burn_events</code> published under
<code>0xA550C18</code>.


<a name="@Parameters_9"></a>

### Parameters

| Name              | Type      | Description                                                                                                        |
| ------            | ------    | -------------                                                                                                      |
| <code>Token</code>           | Type      | The Move type for the <code>Token</code> currency being burned. <code>Token</code> must be an already-registered currency on-chain.      |
| <code>tc_account</code>      | <code>signer</code>  | The signer of the sending account of this transaction, must have a burn capability for <code>Token</code> published under it. |
| <code>sliding_nonce</code>   | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                         |
| <code>preburn_address</code> | <code>address</code> | The address where the coins to-be-burned are currently held.                                                       |
| <code>amount</code>          | <code>u64</code>     | The amount to be burned.                                                                                           |


<a name="@Common_Abort_Conditions_10"></a>

### Common Abort Conditions

| Error Category                | Error Reason                            | Description                                                                                                                         |
| ----------------              | --------------                          | -------------                                                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                                                                   |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a></code> | <code><a href="Diem.md#0x1_Diem_EBURN_CAPABILITY">Diem::EBURN_CAPABILITY</a></code>                | The sending <code>account</code> does not have a <code><a href="Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code> published under it.                                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="Diem.md#0x1_Diem_EPREBURN_NOT_FOUND">Diem::EPREBURN_NOT_FOUND</a></code>              | The <code><a href="Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource under <code>preburn_address</code> does not contain a preburn request with a value matching <code>amount</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="Diem.md#0x1_Diem_EPREBURN_QUEUE">Diem::EPREBURN_QUEUE</a></code>                  | The account at <code>preburn_address</code> does not have a <code><a href="Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource published under it.                           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                  | The specified <code>Token</code> is not a registered currency on-chain.                                                                        |


<a name="@Related_Scripts_11"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_txn_fees">TreasuryComplianceScripts::burn_txn_fees</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">TreasuryComplianceScripts::cancel_burn_with_amount</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_preburn">TreasuryComplianceScripts::preburn</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_with_amount">burn_with_amount</a>&lt;Token&gt;(account: signer, sliding_nonce: u64, preburn_address: address, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_with_amount">burn_with_amount</a>&lt;Token&gt;(account: signer, sliding_nonce: u64, preburn_address: address, amount: u64) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <a href="Diem.md#0x1_Diem_burn">Diem::burn</a>&lt;Token&gt;(&account, preburn_address, amount)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ seq_nonce: sliding_nonce };
<b>include</b> <a href="Diem.md#0x1_Diem_BurnAbortsIf">Diem::BurnAbortsIf</a>&lt;Token&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_BurnEnsures">Diem::BurnEnsures</a>&lt;Token&gt;;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
<b>include</b> <a href="Diem.md#0x1_Diem_BurnWithResourceCapEmits">Diem::BurnWithResourceCapEmits</a>&lt;Token&gt;{preburn: <a href="Diem.md#0x1_Diem_spec_make_preburn">Diem::spec_make_preburn</a>(amount)};
</code></pre>


**Access Control:**
Only the account with the burn capability can burn coins [[H3]][PERMISSION].


<pre><code><b>include</b> <a href="Diem.md#0x1_Diem_AbortsIfNoBurnCapability">Diem::AbortsIfNoBurnCapability</a>&lt;Token&gt;{account: account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_preburn"></a>

## Function `preburn`


<a name="@Summary_12"></a>

### Summary

Moves a specified number of coins in a given currency from the account's
balance to its preburn area after which the coins may be burned. This
transaction may be sent by any account that holds a balance and preburn area
in the specified currency.


<a name="@Technical_Description_13"></a>

### Technical Description

Moves the specified <code>amount</code> of coins in <code>Token</code> currency from the sending <code>account</code>'s
<code><a href="DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Token&gt;</code> to the <code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> published under the same
<code>account</code>. <code>account</code> must have both of these resources published under it at the start of this
transaction in order for it to execute successfully.


<a name="@Events_14"></a>

### Events

Successful execution of this script emits two events:
* <code><a href="DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a> </code> on <code>account</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code>
handle with the <code>payee</code> and <code>payer</code> fields being <code>account</code>'s address; and
* A <code><a href="Diem.md#0x1_Diem_PreburnEvent">Diem::PreburnEvent</a></code> with <code>Token</code>'s currency code on the
<code><a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token</code>'s <code>preburn_events</code> handle for <code>Token</code> and with
<code>preburn_address</code> set to <code>account</code>'s address.


<a name="@Parameters_15"></a>

### Parameters

| Name      | Type     | Description                                                                                                                      |
| ------    | ------   | -------------                                                                                                                    |
| <code>Token</code>   | Type     | The Move type for the <code>Token</code> currency being moved to the preburn area. <code>Token</code> must be an already-registered currency on-chain. |
| <code>account</code> | <code>signer</code> | The signer of the sending account.                                                                                               |
| <code>amount</code>  | <code>u64</code>    | The amount in <code>Token</code> to be moved to the preburn area.                                                                           |


<a name="@Common_Abort_Conditions_16"></a>

### Common Abort Conditions

| Error Category           | Error Reason                                             | Description                                                                             |
| ----------------         | --------------                                           | -------------                                                                           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                                  | The <code>Token</code> is not a registered currency on-chain.                                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>  | <code>DiemAccount::EWITHDRAWAL_CAPABILITY_ALREADY_EXTRACTED</code> | The withdrawal capability for <code>account</code> has already been extracted.                     |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>                    | <code>amount</code> is greater than <code>payer</code>'s balance in <code>Token</code>.                                  |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>              | <code>account</code> doesn't hold a balance in <code>Token</code>.                                            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="Diem.md#0x1_Diem_EPREBURN">Diem::EPREBURN</a></code>                                        | <code>account</code> doesn't have a <code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource published under it.           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>  | <code><a href="Diem.md#0x1_Diem_EPREBURN_OCCUPIED">Diem::EPREBURN_OCCUPIED</a></code>                               | The <code>value</code> field in the <code><a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource under the sender is non-zero. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                                        | The <code>account</code> did not have a role assigned to it.                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>  | <code><a href="Roles.md#0x1_Roles_EDESIGNATED_DEALER">Roles::EDESIGNATED_DEALER</a></code>                              | The <code>account</code> did not have the role of DesignatedDealer.                                |


<a name="@Related_Scripts_17"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">TreasuryComplianceScripts::cancel_burn_with_amount</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_with_amount">TreasuryComplianceScripts::burn_with_amount</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_txn_fees">TreasuryComplianceScripts::burn_txn_fees</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_preburn">preburn</a>&lt;Token&gt;(account: signer, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_preburn">preburn</a>&lt;Token&gt;(account: signer, amount: u64) {
    <b>let</b> withdraw_cap = <a href="DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&account);
    <a href="DiemAccount.md#0x1_DiemAccount_preburn">DiemAccount::preburn</a>&lt;Token&gt;(&account, &withdraw_cap, amount);
    <a href="DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(withdraw_cap);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>let</b> cap = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_withdraw_cap">DiemAccount::spec_get_withdraw_cap</a>(account_addr);
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractWithdrawCapAbortsIf">DiemAccount::ExtractWithdrawCapAbortsIf</a>{sender_addr: account_addr};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_PreburnAbortsIf">DiemAccount::PreburnAbortsIf</a>&lt;Token&gt;{dd: account, cap: cap};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_PreburnEnsures">DiemAccount::PreburnEnsures</a>&lt;Token&gt;{dd: account, payer: account_addr};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_PreburnEmits">DiemAccount::PreburnEmits</a>&lt;Token&gt;{dd: account, cap: cap};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
</code></pre>


**Access Control:**
Only the account with a Preburn resource or PreburnQueue resource can preburn [[H4]][PERMISSION].


<pre><code><b>aborts_if</b> !(<b>exists</b>&lt;<a href="Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;&gt;(account_addr) || <b>exists</b>&lt;<a href="Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;&gt;(account_addr));
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_burn_txn_fees"></a>

## Function `burn_txn_fees`


<a name="@Summary_18"></a>

### Summary

Burns the transaction fees collected in the <code>CoinType</code> currency so that the
Diem association may reclaim the backing coins off-chain. May only be sent
by the Treasury Compliance account.


<a name="@Technical_Description_19"></a>

### Technical Description

Burns the transaction fees collected in <code>CoinType</code> so that the
association may reclaim the backing coins. Once this transaction has executed
successfully all transaction fees that will have been collected in
<code>CoinType</code> since the last time this script was called with that specific
currency. Both <code>balance</code> and <code>preburn</code> fields in the
<code><a href="TransactionFee.md#0x1_TransactionFee_TransactionFee">TransactionFee::TransactionFee</a>&lt;CoinType&gt;</code> resource published under the <code>0xB1E55ED</code>
account address will have a value of 0 after the successful execution of this script.


<a name="@Events_20"></a>

### Events

The successful execution of this transaction will emit a <code><a href="Diem.md#0x1_Diem_BurnEvent">Diem::BurnEvent</a></code> on the event handle
held in the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;CoinType&gt;</code> resource's <code>burn_events</code> published under
<code>0xA550C18</code>.


<a name="@Parameters_21"></a>

### Parameters

| Name         | Type     | Description                                                                                                                                         |
| ------       | ------   | -------------                                                                                                                                       |
| <code>CoinType</code>   | Type     | The Move type for the <code>CoinType</code> being added to the sending account of the transaction. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>tc_account</code> | <code>signer</code> | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                     |


<a name="@Common_Abort_Conditions_22"></a>

### Common Abort Conditions

| Error Category             | Error Reason                          | Description                                                 |
| ----------------           | --------------                        | -------------                                               |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code> | The sending account is not the Treasury Compliance account. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="TransactionFee.md#0x1_TransactionFee_ETRANSACTION_FEE">TransactionFee::ETRANSACTION_FEE</a></code>    | <code>CoinType</code> is not an accepted transaction fee currency.     |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="Diem.md#0x1_Diem_ECOIN">Diem::ECOIN</a></code>                        | The collected fees in <code>CoinType</code> are zero.                  |


<a name="@Related_Scripts_23"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_with_amount">TreasuryComplianceScripts::burn_with_amount</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">TreasuryComplianceScripts::cancel_burn_with_amount</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_txn_fees">burn_txn_fees</a>&lt;CoinType&gt;(tc_account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_burn_txn_fees">burn_txn_fees</a>&lt;CoinType&gt;(tc_account: signer) {
    <a href="TransactionFee.md#0x1_TransactionFee_burn_fees">TransactionFee::burn_fees</a>&lt;CoinType&gt;(&tc_account);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_tiered_mint"></a>

## Function `tiered_mint`


<a name="@Summary_24"></a>

### Summary

Mints a specified number of coins in a currency to a Designated Dealer. The sending account
must be the Treasury Compliance account, and coins can only be minted to a Designated Dealer
account.


<a name="@Technical_Description_25"></a>

### Technical Description

Mints <code>mint_amount</code> of coins in the <code>CoinType</code> currency to Designated Dealer account at
<code>designated_dealer_address</code>. The <code>tier_index</code> parameter specifies which tier should be used to
check verify the off-chain approval policy, and is based in part on the on-chain tier values
for the specific Designated Dealer, and the number of <code>CoinType</code> coins that have been minted to
the dealer over the past 24 hours. Every Designated Dealer has 4 tiers for each currency that
they support. The sending <code>tc_account</code> must be the Treasury Compliance account, and the
receiver an authorized Designated Dealer account.


<a name="@Events_26"></a>

### Events

Successful execution of the transaction will emit two events:
* A <code><a href="Diem.md#0x1_Diem_MintEvent">Diem::MintEvent</a></code> with the amount and currency code minted is emitted on the
<code>mint_event_handle</code> in the stored <code><a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;CoinType&gt;</code> resource stored under
<code>0xA550C18</code>; and
* A <code><a href="DesignatedDealer.md#0x1_DesignatedDealer_ReceivedMintEvent">DesignatedDealer::ReceivedMintEvent</a></code> with the amount, currency code, and Designated
Dealer's address is emitted on the <code>mint_event_handle</code> in the stored <code><a href="DesignatedDealer.md#0x1_DesignatedDealer_Dealer">DesignatedDealer::Dealer</a></code>
resource published under the <code>designated_dealer_address</code>.


<a name="@Parameters_27"></a>

### Parameters

| Name                        | Type      | Description                                                                                                |
| ------                      | ------    | -------------                                                                                              |
| <code>CoinType</code>                  | Type      | The Move type for the <code>CoinType</code> being minted. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>                | <code>signer</code>  | The signer of the sending account of this transaction. Must be the Treasury Compliance account.            |
| <code>sliding_nonce</code>             | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                 |
| <code>designated_dealer_address</code> | <code>address</code> | The address of the Designated Dealer account being minted to.                                              |
| <code>mint_amount</code>               | <code>u64</code>     | The number of coins to be minted.                                                                          |
| <code>tier_index</code>                | <code>u64</code>     | [Deprecated] The mint tier index to use for the Designated Dealer account. Will be ignored                 |


<a name="@Common_Abort_Conditions_28"></a>

### Common Abort Conditions

| Error Category                | Error Reason                                 | Description                                                                                                                  |
| ----------------              | --------------                               | -------------                                                                                                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>               | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                                                               |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>               | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not.                                   |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>               | The <code>sliding_nonce</code> is too far in the future.                                                                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>      | The <code>sliding_nonce</code> has been previously recorded.                                                                            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>    | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>        | <code>tc_account</code> is not the Treasury Compliance account.                                                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>       | <code><a href="Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>                | <code>tc_account</code> is not the Treasury Compliance account.                                                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="DesignatedDealer.md#0x1_DesignatedDealer_EINVALID_MINT_AMOUNT">DesignatedDealer::EINVALID_MINT_AMOUNT</a></code>     | <code>mint_amount</code> is zero.                                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="DesignatedDealer.md#0x1_DesignatedDealer_EDEALER">DesignatedDealer::EDEALER</a></code>                  | <code><a href="DesignatedDealer.md#0x1_DesignatedDealer_Dealer">DesignatedDealer::Dealer</a></code> or <code><a href="DesignatedDealer.md#0x1_DesignatedDealer_TierInfo">DesignatedDealer::TierInfo</a>&lt;CoinType&gt;</code> resource does not exist at <code>designated_dealer_address</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a></code> | <code><a href="Diem.md#0x1_Diem_EMINT_CAPABILITY">Diem::EMINT_CAPABILITY</a></code>                    | <code>tc_account</code> does not have a <code><a href="Diem.md#0x1_Diem_MintCapability">Diem::MintCapability</a>&lt;CoinType&gt;</code> resource published under it.                                  |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="Diem.md#0x1_Diem_EMINTING_NOT_ALLOWED">Diem::EMINTING_NOT_ALLOWED</a></code>                | Minting is not currently allowed for <code>CoinType</code> coins.                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>      | <code><a href="DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>      | The depositing of the funds would exceed the <code>account</code>'s account limits.                                                     |


<a name="@Related_Scripts_29"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_designated_dealer">AccountCreationScripts::create_designated_dealer</a></code>
* <code><a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_tiered_mint">tiered_mint</a>&lt;CoinType&gt;(tc_account: signer, sliding_nonce: u64, designated_dealer_address: address, mint_amount: u64, tier_index: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_tiered_mint">tiered_mint</a>&lt;CoinType&gt;(
    tc_account: signer,
    sliding_nonce: u64,
    designated_dealer_address: address,
    mint_amount: u64,
    tier_index: u64
) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="DiemAccount.md#0x1_DiemAccount_tiered_mint">DiemAccount::tiered_mint</a>&lt;CoinType&gt;(
        &tc_account, designated_dealer_address, mint_amount, tier_index
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{account: tc_account, seq_nonce: sliding_nonce};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TieredMintAbortsIf">DiemAccount::TieredMintAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TieredMintEnsures">DiemAccount::TieredMintEnsures</a>&lt;CoinType&gt;;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TieredMintEmits">DiemAccount::TieredMintEmits</a>&lt;CoinType&gt;;
</code></pre>


**Access Control:**
Only the Treasury Compliance account can mint [[H1]][PERMISSION].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_freeze_account"></a>

## Function `freeze_account`


<a name="@Summary_30"></a>

### Summary

Freezes the account at <code>address</code>. The sending account of this transaction
must be the Treasury Compliance account. The account being frozen cannot be
the Diem Root or Treasury Compliance account. After the successful
execution of this transaction no transactions may be sent from the frozen
account, and the frozen account may not send or receive coins.


<a name="@Technical_Description_31"></a>

### Technical Description

Sets the <code><a href="AccountFreezing.md#0x1_AccountFreezing_FreezingBit">AccountFreezing::FreezingBit</a></code> to <code><b>true</b></code> and emits a
<code><a href="AccountFreezing.md#0x1_AccountFreezing_FreezeAccountEvent">AccountFreezing::FreezeAccountEvent</a></code>. The transaction sender must be the
Treasury Compliance account, but the account at <code>to_freeze_account</code> must
not be either <code>0xA550C18</code> (the Diem Root address), or <code>0xB1E55ED</code> (the
Treasury Compliance address). Note that this is a per-account property
e.g., freezing a Parent VASP will not effect the status any of its child
accounts and vice versa.



<a name="@Events_32"></a>

### Events

Successful execution of this transaction will emit a <code><a href="AccountFreezing.md#0x1_AccountFreezing_FreezeAccountEvent">AccountFreezing::FreezeAccountEvent</a></code> on
the <code>freeze_event_handle</code> held in the <code><a href="AccountFreezing.md#0x1_AccountFreezing_FreezeEventsHolder">AccountFreezing::FreezeEventsHolder</a></code> resource published
under <code>0xA550C18</code> with the <code>frozen_address</code> being the <code>to_freeze_account</code>.


<a name="@Parameters_33"></a>

### Parameters

| Name                | Type      | Description                                                                                     |
| ------              | ------    | -------------                                                                                   |
| <code>tc_account</code>        | <code>signer</code>  | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>sliding_nonce</code>     | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                      |
| <code>to_freeze_account</code> | <code>address</code> | The account address to be frozen.                                                               |


<a name="@Common_Abort_Conditions_34"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                 | Description                                                                                |
| ----------------           | --------------                               | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>               | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>               | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>               | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>      | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>        | The sending account is not the Treasury Compliance account.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>                | The sending account is not the Treasury Compliance account.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="AccountFreezing.md#0x1_AccountFreezing_ECANNOT_FREEZE_TC">AccountFreezing::ECANNOT_FREEZE_TC</a></code>         | <code>to_freeze_account</code> was the Treasury Compliance account (<code>0xB1E55ED</code>).                     |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="AccountFreezing.md#0x1_AccountFreezing_ECANNOT_FREEZE_DIEM_ROOT">AccountFreezing::ECANNOT_FREEZE_DIEM_ROOT</a></code> | <code>to_freeze_account</code> was the Diem Root account (<code>0xA550C18</code>).                              |


<a name="@Related_Scripts_35"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_unfreeze_account">TreasuryComplianceScripts::unfreeze_account</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_freeze_account">freeze_account</a>(tc_account: signer, sliding_nonce: u64, to_freeze_account: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_freeze_account">freeze_account</a>(tc_account: signer, sliding_nonce: u64, to_freeze_account: address) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="AccountFreezing.md#0x1_AccountFreezing_freeze_account">AccountFreezing::freeze_account</a>(&tc_account, to_freeze_account);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_unfreeze_account"></a>

## Function `unfreeze_account`


<a name="@Summary_36"></a>

### Summary

Unfreezes the account at <code>address</code>. The sending account of this transaction must be the
Treasury Compliance account. After the successful execution of this transaction transactions
may be sent from the previously frozen account, and coins may be sent and received.


<a name="@Technical_Description_37"></a>

### Technical Description

Sets the <code><a href="AccountFreezing.md#0x1_AccountFreezing_FreezingBit">AccountFreezing::FreezingBit</a></code> to <code><b>false</b></code> and emits a
<code>AccountFreezing::UnFreezeAccountEvent</code>. The transaction sender must be the Treasury Compliance
account. Note that this is a per-account property so unfreezing a Parent VASP will not effect
the status any of its child accounts and vice versa.


<a name="@Events_38"></a>

### Events

Successful execution of this script will emit a <code>AccountFreezing::UnFreezeAccountEvent</code> with
the <code>unfrozen_address</code> set the <code>to_unfreeze_account</code>'s address.


<a name="@Parameters_39"></a>

### Parameters

| Name                  | Type      | Description                                                                                     |
| ------                | ------    | -------------                                                                                   |
| <code>tc_account</code>          | <code>signer</code>  | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>sliding_nonce</code>       | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                      |
| <code>to_unfreeze_account</code> | <code>address</code> | The account address to be frozen.                                                               |


<a name="@Common_Abort_Conditions_40"></a>

### Common Abort Conditions

| Error Category             | Error Reason                            | Description                                                                                |
| ----------------           | --------------                          | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | The sending account is not the Treasury Compliance account.                                |


<a name="@Related_Scripts_41"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_freeze_account">TreasuryComplianceScripts::freeze_account</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_unfreeze_account">unfreeze_account</a>(account: signer, sliding_nonce: u64, to_unfreeze_account: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_unfreeze_account">unfreeze_account</a>(account: signer, sliding_nonce: u64, to_unfreeze_account: address) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <a href="AccountFreezing.md#0x1_AccountFreezing_unfreeze_account">AccountFreezing::unfreeze_account</a>(&account, to_unfreeze_account);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_update_dual_attestation_limit"></a>

## Function `update_dual_attestation_limit`


<a name="@Summary_42"></a>

### Summary

Update the dual attestation limit on-chain. Defined in terms of micro-XDX.  The transaction can
only be sent by the Treasury Compliance account.  After this transaction all inter-VASP
payments over this limit must be checked for dual attestation.


<a name="@Technical_Description_43"></a>

### Technical Description

Updates the <code>micro_xdx_limit</code> field of the <code><a href="DualAttestation.md#0x1_DualAttestation_Limit">DualAttestation::Limit</a></code> resource published under
<code>0xA550C18</code>. The amount is set in micro-XDX.


<a name="@Parameters_44"></a>

### Parameters

| Name                  | Type     | Description                                                                                     |
| ------                | ------   | -------------                                                                                   |
| <code>tc_account</code>          | <code>signer</code> | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>sliding_nonce</code>       | <code>u64</code>    | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                      |
| <code>new_micro_xdx_limit</code> | <code>u64</code>    | The new dual attestation limit to be used on-chain.                                             |


<a name="@Common_Abort_Conditions_45"></a>

### Common Abort Conditions

| Error Category             | Error Reason                            | Description                                                                                |
| ----------------           | --------------                          | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | <code>tc_account</code> is not the Treasury Compliance account.                                       |


<a name="@Related_Scripts_46"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_exchange_rate">TreasuryComplianceScripts::update_exchange_rate</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_minting_ability">TreasuryComplianceScripts::update_minting_ability</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">update_dual_attestation_limit</a>(tc_account: signer, sliding_nonce: u64, new_micro_xdx_limit: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">update_dual_attestation_limit</a>(
        tc_account: signer,
        sliding_nonce: u64,
        new_micro_xdx_limit: u64
    ) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="DualAttestation.md#0x1_DualAttestation_set_microdiem_limit">DualAttestation::set_microdiem_limit</a>(&tc_account, new_micro_xdx_limit);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_update_exchange_rate"></a>

## Function `update_exchange_rate`


<a name="@Summary_47"></a>

### Summary

Update the rough on-chain exchange rate between a specified currency and XDX (as a conversion
to micro-XDX). The transaction can only be sent by the Treasury Compliance account. After this
transaction the updated exchange rate will be used for normalization of gas prices, and for
dual attestation checking.


<a name="@Technical_Description_48"></a>

### Technical Description

Updates the on-chain exchange rate from the given <code>Currency</code> to micro-XDX.  The exchange rate
is given by <code>new_exchange_rate_numerator/new_exchange_rate_denominator</code>.


<a name="@Parameters_49"></a>

### Parameters

| Name                            | Type     | Description                                                                                                                        |
| ------                          | ------   | -------------                                                                                                                      |
| <code>Currency</code>                      | Type     | The Move type for the <code>Currency</code> whose exchange rate is being updated. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>                    | <code>signer</code> | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                    |
| <code>sliding_nonce</code>                 | <code>u64</code>    | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for the transaction.                                                          |
| <code>new_exchange_rate_numerator</code>   | <code>u64</code>    | The numerator for the new to micro-XDX exchange rate for <code>Currency</code>.                                                               |
| <code>new_exchange_rate_denominator</code> | <code>u64</code>    | The denominator for the new to micro-XDX exchange rate for <code>Currency</code>.                                                             |


<a name="@Common_Abort_Conditions_50"></a>

### Common Abort Conditions

| Error Category             | Error Reason                            | Description                                                                                |
| ----------------           | --------------                          | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | <code>tc_account</code> is not the Treasury Compliance account.                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>           | <code>tc_account</code> is not the Treasury Compliance account.                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_EDENOMINATOR">FixedPoint32::EDENOMINATOR</a></code>            | <code>new_exchange_rate_denominator</code> is zero.                                                   |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_ERATIO_OUT_OF_RANGE">FixedPoint32::ERATIO_OUT_OF_RANGE</a></code>     | The quotient is unrepresentable as a <code><a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a></code>.                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_ERATIO_OUT_OF_RANGE">FixedPoint32::ERATIO_OUT_OF_RANGE</a></code>     | The quotient is unrepresentable as a <code><a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32">FixedPoint32</a></code>.                                       |


<a name="@Related_Scripts_51"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">TreasuryComplianceScripts::update_dual_attestation_limit</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_minting_ability">TreasuryComplianceScripts::update_minting_ability</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_exchange_rate">update_exchange_rate</a>&lt;Currency&gt;(tc_account: signer, sliding_nonce: u64, new_exchange_rate_numerator: u64, new_exchange_rate_denominator: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_exchange_rate">update_exchange_rate</a>&lt;Currency&gt;(
        tc_account: signer,
        sliding_nonce: u64,
        new_exchange_rate_numerator: u64,
        new_exchange_rate_denominator: u64,
) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <b>let</b> rate = <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_create_from_rational">FixedPoint32::create_from_rational</a>(
            new_exchange_rate_numerator,
            new_exchange_rate_denominator,
    );
    <a href="Diem.md#0x1_Diem_update_xdx_exchange_rate">Diem::update_xdx_exchange_rate</a>&lt;Currency&gt;(&tc_account, rate);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ account: tc_account, seq_nonce: sliding_nonce };
<b>include</b> <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_CreateFromRationalAbortsIf">FixedPoint32::CreateFromRationalAbortsIf</a>{
       numerator: new_exchange_rate_numerator,
       denominator: new_exchange_rate_denominator
};
<b>let</b> rate = <a href="../../../../../../move-stdlib/docs/FixedPoint32.md#0x1_FixedPoint32_spec_create_from_rational">FixedPoint32::spec_create_from_rational</a>(
        new_exchange_rate_numerator,
        new_exchange_rate_denominator
);
<b>include</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateAbortsIf">Diem::UpdateXDXExchangeRateAbortsIf</a>&lt;Currency&gt;;
<b>include</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateEnsures">Diem::UpdateXDXExchangeRateEnsures</a>&lt;Currency&gt;{xdx_exchange_rate: rate};
<b>include</b> <a href="Diem.md#0x1_Diem_UpdateXDXExchangeRateEmits">Diem::UpdateXDXExchangeRateEmits</a>&lt;Currency&gt;{xdx_exchange_rate: rate};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
</code></pre>


**Access Control:**
Only the Treasury Compliance account can update the exchange rate [[H5]][PERMISSION].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_update_minting_ability"></a>

## Function `update_minting_ability`


<a name="@Summary_52"></a>

### Summary

Script to allow or disallow minting of new coins in a specified currency.  This transaction can
only be sent by the Treasury Compliance account.  Turning minting off for a currency will have
no effect on coins already in circulation, and coins may still be removed from the system.


<a name="@Technical_Description_53"></a>

### Technical Description

This transaction sets the <code>can_mint</code> field of the <code><a href="Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Currency&gt;</code> resource
published under <code>0xA550C18</code> to the value of <code>allow_minting</code>. Minting of coins if allowed if
this field is set to <code><b>true</b></code> and minting of new coins in <code>Currency</code> is disallowed otherwise.
This transaction needs to be sent by the Treasury Compliance account.


<a name="@Parameters_54"></a>

### Parameters

| Name            | Type     | Description                                                                                                                          |
| ------          | ------   | -------------                                                                                                                        |
| <code>Currency</code>      | Type     | The Move type for the <code>Currency</code> whose minting ability is being updated. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>account</code>       | <code>signer</code> | Signer of the sending account. Must be the Diem Root account.                                                                        |
| <code>allow_minting</code> | <code>bool</code>   | Whether to allow minting of new coins in <code>Currency</code>.                                                                                 |


<a name="@Common_Abort_Conditions_55"></a>

### Common Abort Conditions

| Error Category             | Error Reason                          | Description                                          |
| ----------------           | --------------                        | -------------                                        |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code> | <code>tc_account</code> is not the Treasury Compliance account. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>               | <code>Currency</code> is not a registered currency on-chain.    |


<a name="@Related_Scripts_56"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">TreasuryComplianceScripts::update_dual_attestation_limit</a></code>
* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_exchange_rate">TreasuryComplianceScripts::update_exchange_rate</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_minting_ability">update_minting_ability</a>&lt;Currency&gt;(tc_account: signer, allow_minting: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_update_minting_ability">update_minting_ability</a>&lt;Currency&gt;(
    tc_account: signer,
    allow_minting: bool
) {
    <a href="Diem.md#0x1_Diem_update_minting_ability">Diem::update_minting_ability</a>&lt;Currency&gt;(&tc_account, allow_minting);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_add_vasp_domain"></a>

## Function `add_vasp_domain`


<a name="@Summary_57"></a>

### Summary

Add a VASP domain to parent VASP account. The transaction can only be sent by
the Treasury Compliance account.


<a name="@Technical_Description_58"></a>

### Technical Description

Adds a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code> to the <code>domains</code> field of the <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under
the account at <code>address</code>.


<a name="@Parameters_59"></a>

### Parameters

| Name         | Type         | Description                                                                                     |
| ------       | ------       | -------------                                                                                   |
| <code>tc_account</code> | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>address</code>    | <code>address</code>    | The <code>address</code> of the parent VASP account that will have have <code>domain</code> added to its domains.     |
| <code>domain</code>     | <code>vector&lt;u8&gt;</code> | The domain to be added.                                                                         |


<a name="@Common_Abort_Conditions_60"></a>

### Common Abort Conditions

| Error Category             | Error Reason                             | Description                                                                                                                            |
| ----------------           | --------------                           | -------------                                                                                                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>            | The sending account is not the Treasury Compliance account.                                                                            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>    | <code>tc_account</code> is not the Treasury Compliance account.                                                                                   |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">VASPDomain::EVASP_DOMAIN_MANAGER</a></code>        | The <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomain::VASPDomainManager</a></code> resource is not yet published under the Treasury Compliance account.                                 |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">VASPDomain::EVASP_DOMAINS_NOT_PUBLISHED</a></code> | <code>address</code> does not have a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under it.                                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code>VASPDomain::EDOMAIN_ALREADY_EXISTS</code>         | The <code>domain</code> already exists in the list of <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code>s  in the <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under <code>address</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="VASPDomain.md#0x1_VASPDomain_EINVALID_VASP_DOMAIN">VASPDomain::EINVALID_VASP_DOMAIN</a></code>        | The <code>domain</code> is greater in length than <code><a href="VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">VASPDomain::DOMAIN_LENGTH</a></code>.                                                                        |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_add_vasp_domain">add_vasp_domain</a>(tc_account: signer, address: address, domain: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_add_vasp_domain">add_vasp_domain</a> (
    tc_account: signer,
    address: address,
    domain: vector&lt;u8&gt;,
) {
    <a href="VASPDomain.md#0x1_VASPDomain_add_vasp_domain">VASPDomain::add_vasp_domain</a>(&tc_account, address, domain);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainAbortsIf">VASPDomain::AddVASPDomainAbortsIf</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainEnsures">VASPDomain::AddVASPDomainEnsures</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_AddVASPDomainEmits">VASPDomain::AddVASPDomainEmits</a>;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_remove_vasp_domain"></a>

## Function `remove_vasp_domain`


<a name="@Summary_61"></a>

### Summary

Remove a VASP domain from parent VASP account. The transaction can only be sent by
the Treasury Compliance account.


<a name="@Technical_Description_62"></a>

### Technical Description

Removes a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code> from the <code>domains</code> field of the <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under
account with <code>address</code>.


<a name="@Parameters_63"></a>

### Parameters

| Name         | Type         | Description                                                                                     |
| ------       | ------       | -------------                                                                                   |
| <code>tc_account</code> | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>address</code>    | <code>address</code>    | The <code>address</code> of parent VASP account that will update its domains.                              |
| <code>domain</code>     | <code>vector&lt;u8&gt;</code> | The domain name.                                                                                |


<a name="@Common_Abort_Conditions_64"></a>

### Common Abort Conditions

| Error Category             | Error Reason                             | Description                                                                                                                            |
| ----------------           | --------------                           | -------------                                                                                                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>            | The sending account is not the Treasury Compliance account.                                                                            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>    | <code>tc_account</code> is not the Treasury Compliance account.                                                                                   |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">VASPDomain::EVASP_DOMAIN_MANAGER</a></code>        | The <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomain::VASPDomainManager</a></code> resource is not yet published under the Treasury Compliance account.                                 |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">VASPDomain::EVASP_DOMAINS_NOT_PUBLISHED</a></code> | <code>address</code> does not have a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under it.                                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="VASPDomain.md#0x1_VASPDomain_EINVALID_VASP_DOMAIN">VASPDomain::EINVALID_VASP_DOMAIN</a></code>        | The <code>domain</code> is greater in length than <code><a href="VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">VASPDomain::DOMAIN_LENGTH</a></code>.                                                                        |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_NOT_FOUND">VASPDomain::EVASP_DOMAIN_NOT_FOUND</a></code>              | The <code>domain</code> does not exist in the list of <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code>s  in the <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under <code>address</code>. |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_remove_vasp_domain">remove_vasp_domain</a>(tc_account: signer, address: address, domain: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_remove_vasp_domain">remove_vasp_domain</a> (
    tc_account: signer,
    address: address,
    domain: vector&lt;u8&gt;,
) {
    <a href="VASPDomain.md#0x1_VASPDomain_remove_vasp_domain">VASPDomain::remove_vasp_domain</a>(&tc_account, address, domain);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
