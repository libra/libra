
<a name="0x1_PaymentScripts"></a>

# Module `0x1::PaymentScripts`

This module holds all payment related script entrypoints in the Diem Framework.
Any account that can hold a balance can use the transaction scripts within this module.


-  [Function `peer_to_peer_with_metadata`](#0x1_PaymentScripts_peer_to_peer_with_metadata)
    -  [Summary](#@Summary_0)
    -  [Technical Description](#@Technical_Description_1)
    -  [Events](#@Events_2)
    -  [Parameters](#@Parameters_3)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_4)
    -  [Related Scripts](#@Related_Scripts_5)
-  [Function `peer_to_peer_by_signers`](#0x1_PaymentScripts_peer_to_peer_by_signers)
    -  [Summary](#@Summary_6)
    -  [Technical Description](#@Technical_Description_7)
    -  [Events](#@Events_8)
    -  [Parameters](#@Parameters_9)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_10)
    -  [Related Scripts](#@Related_Scripts_11)


<pre><code><b>use</b> <a href="DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
</code></pre>



<a name="0x1_PaymentScripts_peer_to_peer_with_metadata"></a>

## Function `peer_to_peer_with_metadata`


<a name="@Summary_0"></a>

### Summary

Transfers a given number of coins in a specified currency from one account to another.
Transfers over a specified amount defined on-chain that are between two different VASPs, or
other accounts that have opted-in will be subject to on-chain checks to ensure the receiver has
agreed to receive the coins.  This transaction can be sent by any account that can hold a
balance, and to any account that can hold a balance. Both accounts must hold balances in the
currency being transacted.


<a name="@Technical_Description_1"></a>

### Technical Description


Transfers <code>amount</code> coins of type <code>Currency</code> from <code>payer</code> to <code>payee</code> with (optional) associated
<code>metadata</code> and an (optional) <code>metadata_signature</code> on the message of the form
<code>metadata</code> | <code><a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(payer)</code> | <code>amount</code> | <code><a href="DualAttestation.md#0x1_DualAttestation_DOMAIN_SEPARATOR">DualAttestation::DOMAIN_SEPARATOR</a></code>, that
has been signed by the <code>payee</code>'s private key associated with the <code>compliance_public_key</code> held in
the <code>payee</code>'s <code><a href="DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code>. Both the <code><a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_address_of">Signer::address_of</a>(payer)</code> and <code>amount</code> fields
in the <code>metadata_signature</code> must be BCS-encoded bytes, and <code>|</code> denotes concatenation.
The <code>metadata</code> and <code>metadata_signature</code> parameters are only required if <code>amount</code> >=
<code><a href="DualAttestation.md#0x1_DualAttestation_get_cur_microdiem_limit">DualAttestation::get_cur_microdiem_limit</a></code> XDX and <code>payer</code> and <code>payee</code> are distinct VASPs.
However, a transaction sender can opt in to dual attestation even when it is not required
(e.g., a DesignatedDealer -> VASP payment) by providing a non-empty <code>metadata_signature</code>.
Standardized <code>metadata</code> BCS format can be found in <code>diem_types::transaction::metadata::Metadata</code>.


<a name="@Events_2"></a>

### Events

Successful execution of this script emits two events:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a></code> on <code>payer</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code> handle; and
* A <code><a href="DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> on <code>payee</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> handle.


<a name="@Parameters_3"></a>

### Parameters

| Name                 | Type         | Description                                                                                                                  |
| ------               | ------       | -------------                                                                                                                |
| <code>Currency</code>           | Type         | The Move type for the <code>Currency</code> being sent in this transaction. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>payer</code>              | <code>signer</code>     | The signer of the sending account that coins are being transferred from.                                                     |
| <code>payee</code>              | <code>address</code>    | The address of the account the coins are being transferred to.                                                               |
| <code>metadata</code>           | <code>vector&lt;u8&gt;</code> | Optional metadata about this payment.                                                                                        |
| <code>metadata_signature</code> | <code>vector&lt;u8&gt;</code> | Optional signature over <code>metadata</code> and payment information. See                                                              |


<a name="@Common_Abort_Conditions_4"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                     | Description                                                                                                                         |
| ----------------           | --------------                                   | -------------                                                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>       | <code>payer</code> doesn't hold a balance in <code>Currency</code>.                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>             | <code>amount</code> is greater than <code>payer</code>'s balance in <code>Currency</code>.                                                                           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_ECOIN_DEPOSIT_IS_ZERO">DiemAccount::ECOIN_DEPOSIT_IS_ZERO</a></code>             | <code>amount</code> is zero.                                                                                                                   |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYEE_DOES_NOT_EXIST">DiemAccount::EPAYEE_DOES_NOT_EXIST</a></code>             | No account exists at the <code>payee</code> address.                                                                                           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYEE_CANT_ACCEPT_CURRENCY_TYPE">DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE</a></code>  | An account exists at <code>payee</code>, but it does not accept payments in <code>Currency</code>.                                                        |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="AccountFreezing.md#0x1_AccountFreezing_EACCOUNT_FROZEN">AccountFreezing::EACCOUNT_FROZEN</a></code>               | The <code>payee</code> account is frozen.                                                                                                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DualAttestation.md#0x1_DualAttestation_EMALFORMED_METADATA_SIGNATURE">DualAttestation::EMALFORMED_METADATA_SIGNATURE</a></code> | <code>metadata_signature</code> is not 64 bytes.                                                                                               |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DualAttestation.md#0x1_DualAttestation_EINVALID_METADATA_SIGNATURE">DualAttestation::EINVALID_METADATA_SIGNATURE</a></code>   | <code>metadata_signature</code> does not verify on the against the <code>payee'</code>s <code><a href="DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code> <code>compliance_public_key</code> public key. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="DiemAccount.md#0x1_DiemAccount_EWITHDRAWAL_EXCEEDS_LIMITS">DiemAccount::EWITHDRAWAL_EXCEEDS_LIMITS</a></code>        | <code>payer</code> has exceeded its daily withdrawal limits for the backing coins of XDX.                                                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>           | <code>payee</code> has exceeded its daily deposit limits for XDX.                                                                              |


<a name="@Related_Scripts_5"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_by_signers">PaymentScripts::peer_to_peer_by_signers</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_with_metadata">peer_to_peer_with_metadata</a>&lt;Currency&gt;(payer: signer, payee: address, amount: u64, metadata: vector&lt;u8&gt;, metadata_signature: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_with_metadata">peer_to_peer_with_metadata</a>&lt;Currency&gt;(
    payer: signer,
    payee: address,
    amount: u64,
    metadata: vector&lt;u8&gt;,
    metadata_signature: vector&lt;u8&gt;
) {
    <b>let</b> payer_withdrawal_cap = <a href="DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&payer);
    <a href="DiemAccount.md#0x1_DiemAccount_pay_from">DiemAccount::pay_from</a>&lt;Currency&gt;(
        &payer_withdrawal_cap, payee, amount, metadata, metadata_signature
    );
    <a href="DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(payer_withdrawal_cap);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="PaymentScripts.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt;;
<b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_AssertPaymentOkAbortsIf">DualAttestation::AssertPaymentOkAbortsIf</a>&lt;Currency&gt;{
    payer: <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(payer),
    value: amount
};
</code></pre>



</details>

<a name="0x1_PaymentScripts_peer_to_peer_by_signers"></a>

## Function `peer_to_peer_by_signers`


<a name="@Summary_6"></a>

### Summary

Transfers a given number of coins in a specified currency from one account to another by multi-agent transaction.
Transfers over a specified amount defined on-chain that are between two different VASPs, or
other accounts that have opted-in will be subject to on-chain checks to ensure the receiver has
agreed to receive the coins.  This transaction can be sent by any account that can hold a
balance, and to any account that can hold a balance. Both accounts must hold balances in the
currency being transacted.


<a name="@Technical_Description_7"></a>

### Technical Description


Transfers <code>amount</code> coins of type <code>Currency</code> from <code>payer</code> to <code>payee</code> with (optional) associated
<code>metadata</code>.
Dual attestation is not applied to this script as payee is also a signer of the transaction.
Standardized <code>metadata</code> BCS format can be found in <code>diem_types::transaction::metadata::Metadata</code>.


<a name="@Events_8"></a>

### Events

Successful execution of this script emits two events:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a></code> on <code>payer</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code> handle; and
* A <code><a href="DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> on <code>payee</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> handle.


<a name="@Parameters_9"></a>

### Parameters

| Name                 | Type         | Description                                                                                                                  |
| ------               | ------       | -------------                                                                                                                |
| <code>Currency</code>           | Type         | The Move type for the <code>Currency</code> being sent in this transaction. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>payer</code>              | <code>signer</code>     | The signer of the sending account that coins are being transferred from.                                                     |
| <code>payee</code>              | <code>signer</code>     | The signer of the receiving account that the coins are being transferred to.                                                 |
| <code>metadata</code>           | <code>vector&lt;u8&gt;</code> | Optional metadata about this payment.                                                                                        |


<a name="@Common_Abort_Conditions_10"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                     | Description                                                                                                                         |
| ----------------           | --------------                                   | -------------                                                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>       | <code>payer</code> doesn't hold a balance in <code>Currency</code>.                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>             | <code>amount</code> is greater than <code>payer</code>'s balance in <code>Currency</code>.                                                                           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_ECOIN_DEPOSIT_IS_ZERO">DiemAccount::ECOIN_DEPOSIT_IS_ZERO</a></code>             | <code>amount</code> is zero.                                                                                                                   |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYEE_DOES_NOT_EXIST">DiemAccount::EPAYEE_DOES_NOT_EXIST</a></code>             | No account exists at the <code>payee</code> address.                                                                                           |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYEE_CANT_ACCEPT_CURRENCY_TYPE">DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE</a></code>  | An account exists at <code>payee</code>, but it does not accept payments in <code>Currency</code>.                                                        |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="AccountFreezing.md#0x1_AccountFreezing_EACCOUNT_FROZEN">AccountFreezing::EACCOUNT_FROZEN</a></code>               | The <code>payee</code> account is frozen.                                                                                                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="DiemAccount.md#0x1_DiemAccount_EWITHDRAWAL_EXCEEDS_LIMITS">DiemAccount::EWITHDRAWAL_EXCEEDS_LIMITS</a></code>        | <code>payer</code> has exceeded its daily withdrawal limits for the backing coins of XDX.                                                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>           | <code>payee</code> has exceeded its daily deposit limits for XDX.                                                                              |


<a name="@Related_Scripts_11"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_by_signers">peer_to_peer_by_signers</a>&lt;Currency&gt;(payer: signer, payee: signer, amount: u64, metadata: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_by_signers">peer_to_peer_by_signers</a>&lt;Currency&gt;(
    payer: signer,
    payee: signer,
    amount: u64,
    metadata: vector&lt;u8&gt;,
) {
    <b>let</b> payer_withdrawal_cap = <a href="DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&payer);
    <a href="DiemAccount.md#0x1_DiemAccount_pay_by_signers">DiemAccount::pay_by_signers</a>&lt;Currency&gt;(
        &payer_withdrawal_cap, &payee, amount, metadata
    );
    <a href="DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(payer_withdrawal_cap);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="PaymentScripts.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt;{payee: <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(payee)};
</code></pre>




<a name="0x1_PaymentScripts_PeerToPeer"></a>


<pre><code><b>schema</b> <a href="PaymentScripts.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt; {
    payer: signer;
    payee: address;
    amount: u64;
    metadata: vector&lt;u8&gt;;
    <b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: payer};
    <b>let</b> payer_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(payer);
    <b>let</b> cap = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_withdraw_cap">DiemAccount::spec_get_withdraw_cap</a>(payer_addr);
    <b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractWithdrawCapAbortsIf">DiemAccount::ExtractWithdrawCapAbortsIf</a>{sender_addr: payer_addr};
    <b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_PayFromAbortsIf">DiemAccount::PayFromAbortsIf</a>&lt;Currency&gt;{cap: cap};
}
</code></pre>


The balances of payer and payee change by the correct amount.


<pre><code><b>schema</b> <a href="PaymentScripts.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt; {
    <b>ensures</b> payer_addr != payee
        ==&gt; <a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payer_addr)
        == <b>old</b>(<a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payer_addr)) - amount;
    <b>ensures</b> payer_addr != payee
        ==&gt; <a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee)
        == <b>old</b>(<a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee)) + amount;
    <b>ensures</b> payer_addr == payee
        ==&gt; <a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee)
        == <b>old</b>(<a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee));
    <b>aborts_with</b> [check]
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
        <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
    <b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_PayFromEmits">DiemAccount::PayFromEmits</a>&lt;Currency&gt;{cap: cap};
}
</code></pre>


**Access Control:**
Both the payer and the payee must hold the balances of the Currency. Only Designated Dealers,
Parent VASPs, and Child VASPs can hold balances [[D1]][ROLE][[D2]][ROLE][[D3]][ROLE][[D4]][ROLE][[D5]][ROLE][[D6]][ROLE][[D7]][ROLE].


<pre><code><b>schema</b> <a href="PaymentScripts.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt; {
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;&gt;(payer_addr) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;&gt;(payee) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
}
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
