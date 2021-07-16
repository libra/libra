
<a name="0x1_AccountAdministrationScripts"></a>

# Module `0x1::AccountAdministrationScripts`

This module holds transactions that can be used to administer accounts in the Diem Framework.


-  [Function `add_currency_to_account`](#0x1_AccountAdministrationScripts_add_currency_to_account)
    -  [Summary](#@Summary_0)
    -  [Technical Description](#@Technical_Description_1)
    -  [Parameters](#@Parameters_2)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_3)
    -  [Related Scripts](#@Related_Scripts_4)
-  [Function `add_recovery_rotation_capability`](#0x1_AccountAdministrationScripts_add_recovery_rotation_capability)
    -  [Summary](#@Summary_5)
    -  [Technical Description](#@Technical_Description_6)
    -  [Parameters](#@Parameters_7)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_8)
    -  [Related Scripts](#@Related_Scripts_9)
-  [Function `publish_shared_ed25519_public_key`](#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key)
    -  [Summary](#@Summary_10)
    -  [Technical Description](#@Technical_Description_11)
    -  [Parameters](#@Parameters_12)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_13)
    -  [Related Scripts](#@Related_Scripts_14)
-  [Function `rotate_authentication_key`](#0x1_AccountAdministrationScripts_rotate_authentication_key)
    -  [Summary](#@Summary_15)
    -  [Technical Description](#@Technical_Description_16)
    -  [Parameters](#@Parameters_17)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_18)
    -  [Related Scripts](#@Related_Scripts_19)
-  [Function `rotate_authentication_key_with_nonce`](#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce)
    -  [Summary](#@Summary_20)
    -  [Technical Description](#@Technical_Description_21)
    -  [Parameters](#@Parameters_22)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_23)
    -  [Related Scripts](#@Related_Scripts_24)
-  [Function `rotate_authentication_key_with_nonce_admin`](#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin)
    -  [Summary](#@Summary_25)
    -  [Technical Description](#@Technical_Description_26)
    -  [Parameters](#@Parameters_27)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_28)
    -  [Related Scripts](#@Related_Scripts_29)
-  [Function `rotate_authentication_key_with_recovery_address`](#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address)
    -  [Summary](#@Summary_30)
    -  [Technical Description](#@Technical_Description_31)
    -  [Parameters](#@Parameters_32)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_33)
    -  [Related Scripts](#@Related_Scripts_34)
-  [Function `rotate_dual_attestation_info`](#0x1_AccountAdministrationScripts_rotate_dual_attestation_info)
    -  [Summary](#@Summary_35)
    -  [Technical Description](#@Technical_Description_36)
    -  [Events](#@Events_37)
    -  [Parameters](#@Parameters_38)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_39)
    -  [Related Scripts](#@Related_Scripts_40)
-  [Function `rotate_shared_ed25519_public_key`](#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key)
    -  [Summary](#@Summary_41)
    -  [Technical Description](#@Technical_Description_42)
    -  [Parameters](#@Parameters_43)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_44)
    -  [Related Scripts](#@Related_Scripts_45)
-  [Function `create_recovery_address`](#0x1_AccountAdministrationScripts_create_recovery_address)
    -  [Summary](#@Summary_46)
    -  [Technical Description](#@Technical_Description_47)
    -  [Parameters](#@Parameters_48)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_49)
    -  [Related Scripts](#@Related_Scripts_50)
-  [Function `create_vasp_domains`](#0x1_AccountAdministrationScripts_create_vasp_domains)
    -  [Summary](#@Summary_51)
    -  [Technical Description](#@Technical_Description_52)
    -  [Parameters](#@Parameters_53)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_54)


<pre><code><b>use</b> <a href="DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
<b>use</b> <a href="DualAttestation.md#0x1_DualAttestation">0x1::DualAttestation</a>;
<b>use</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress">0x1::RecoveryAddress</a>;
<b>use</b> <a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey">0x1::SharedEd25519PublicKey</a>;
<b>use</b> <a href="SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
<b>use</b> <a href="VASPDomain.md#0x1_VASPDomain">0x1::VASPDomain</a>;
</code></pre>



<a name="0x1_AccountAdministrationScripts_add_currency_to_account"></a>

## Function `add_currency_to_account`


<a name="@Summary_0"></a>

### Summary

Adds a zero <code>Currency</code> balance to the sending <code>account</code>. This will enable <code>account</code> to
send, receive, and hold <code><a href="Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;Currency&gt;</code> coins. This transaction can be
successfully sent by any account that is allowed to hold balances
(e.g., VASP, Designated Dealer).


<a name="@Technical_Description_1"></a>

### Technical Description

After the successful execution of this transaction the sending account will have a
<code><a href="DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;</code> resource with zero balance published under it. Only
accounts that can hold balances can send this transaction, the sending account cannot
already have a <code><a href="DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;</code> published under it.


<a name="@Parameters_2"></a>

### Parameters

| Name       | Type     | Description                                                                                                                                         |
| ------     | ------   | -------------                                                                                                                                       |
| <code>Currency</code> | Type     | The Move type for the <code>Currency</code> being added to the sending account of the transaction. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>account</code>  | <code>signer</code> | The signer of the sending account of the transaction.                                                                                               |


<a name="@Common_Abort_Conditions_3"></a>

### Common Abort Conditions

| Error Category              | Error Reason                             | Description                                                                |
| ----------------            | --------------                           | -------------                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                  | The <code>Currency</code> is not a registered currency on-chain.                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="DiemAccount.md#0x1_DiemAccount_EROLE_CANT_STORE_BALANCE">DiemAccount::EROLE_CANT_STORE_BALANCE</a></code> | The sending <code>account</code>'s role does not permit balances.                     |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EADD_EXISTING_CURRENCY">DiemAccount::EADD_EXISTING_CURRENCY</a></code>   | A balance for <code>Currency</code> is already published under the sending <code>account</code>. |


<a name="@Related_Scripts_4"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_currency_to_account">add_currency_to_account</a>&lt;Currency&gt;(account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_currency_to_account">add_currency_to_account</a>&lt;Currency&gt;(account: signer) {
    <a href="DiemAccount.md#0x1_DiemAccount_add_currency">DiemAccount::add_currency</a>&lt;Currency&gt;(&account);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_AddCurrencyAbortsIf">DiemAccount::AddCurrencyAbortsIf</a>&lt;Currency&gt;;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_AddCurrencyEnsures">DiemAccount::AddCurrencyEnsures</a>&lt;Currency&gt;{addr: <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account)};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
</code></pre>


**Access Control:**
The account must be allowed to hold balances. Only Designated Dealers, Parent VASPs,
and Child VASPs can hold balances [[D1]][ROLE][[D2]][ROLE][[D3]][ROLE][[D4]][ROLE][[D5]][ROLE][[D6]][ROLE][[D7]][ROLE].


<pre><code><b>aborts_if</b> !<a href="Roles.md#0x1_Roles_can_hold_balance">Roles::can_hold_balance</a>(account) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_add_recovery_rotation_capability"></a>

## Function `add_recovery_rotation_capability`


<a name="@Summary_5"></a>

### Summary

Stores the sending accounts ability to rotate its authentication key with a designated recovery
account. Both the sending and recovery accounts need to belong to the same VASP and
both be VASP accounts. After this transaction both the sending account and the
specified recovery account can rotate the sender account's authentication key.


<a name="@Technical_Description_6"></a>

### Technical Description

Adds the <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> for the sending account
(<code>to_recover_account</code>) to the <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource under
<code>recovery_address</code>. After this transaction has been executed successfully the account at
<code>recovery_address</code> and the <code>to_recover_account</code> may rotate the authentication key of
<code>to_recover_account</code> (the sender of this transaction).

The sending account of this transaction (<code>to_recover_account</code>) must not have previously given away its unique key
rotation capability, and must be a VASP account. The account at <code>recovery_address</code>
must also be a VASP account belonging to the same VASP as the <code>to_recover_account</code>.
Additionally the account at <code>recovery_address</code> must have already initialized itself as
a recovery account address using the <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code> transaction script.

The sending account's (<code>to_recover_account</code>) key rotation capability is
removed in this transaction and stored in the <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code>
resource stored under the account at <code>recovery_address</code>.


<a name="@Parameters_7"></a>

### Parameters

| Name                 | Type      | Description                                                                                               |
| ------               | ------    | -------------                                                                                             |
| <code>to_recover_account</code> | <code>signer</code>  | The signer of the sending account of this transaction.                                                    |
| <code>recovery_address</code>   | <code>address</code> | The account address where the <code>to_recover_account</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> will be stored. |


<a name="@Common_Abort_Conditions_8"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                              | Description                                                                                       |
| ----------------           | --------------                                            | -------------                                                                                     |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>to_recover_account</code> has already delegated/extracted its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.    |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_ERECOVERY_ADDRESS">RecoveryAddress::ERECOVERY_ADDRESS</a></code>                      | <code>recovery_address</code> does not have a <code><a href="RecoveryAddress.md#0x1_RecoveryAddress">RecoveryAddress</a></code> resource published under it.                 |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_EINVALID_KEY_ROTATION_DELEGATION">RecoveryAddress::EINVALID_KEY_ROTATION_DELEGATION</a></code>       | <code>to_recover_account</code> and <code>recovery_address</code> do not belong to the same VASP.                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code> <a href="RecoveryAddress.md#0x1_RecoveryAddress_EMAX_KEYS_REGISTERED">RecoveryAddress::EMAX_KEYS_REGISTERED</a></code>                  | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_MAX_REGISTERED_KEYS">RecoveryAddress::MAX_REGISTERED_KEYS</a></code> have already been registered with this <code>recovery_address</code>. |


<a name="@Related_Scripts_9"></a>

### Related Scripts

* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">add_recovery_rotation_capability</a>(to_recover_account: signer, recovery_address: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">add_recovery_rotation_capability</a>(to_recover_account: signer, recovery_address: address) {
    <a href="RecoveryAddress.md#0x1_RecoveryAddress_add_rotation_capability">RecoveryAddress::add_rotation_capability</a>(
        <a href="DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&to_recover_account), recovery_address
    )
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: to_recover_account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>{account: to_recover_account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityEnsures">DiemAccount::ExtractKeyRotationCapabilityEnsures</a>{account: to_recover_account};
<b>let</b> addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(to_recover_account);
<b>let</b> rotation_cap = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(addr);
<b>include</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress_AddRotationCapabilityAbortsIf">RecoveryAddress::AddRotationCapabilityAbortsIf</a>{
    to_recover: rotation_cap
};
<b>ensures</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(recovery_address)[
    len(<a href="RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(recovery_address)) - 1] == rotation_cap;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key"></a>

## Function `publish_shared_ed25519_public_key`


<a name="@Summary_10"></a>

### Summary

Rotates the authentication key of the sending account to the newly-specified ed25519 public key and
publishes a new shared authentication key derived from that public key under the sender's account.
Any account can send this transaction.


<a name="@Technical_Description_11"></a>

### Technical Description

Rotates the authentication key of the sending account to the
[authentication key derived from <code>public_key</code>](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys)
and publishes a <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource
containing the 32-byte ed25519 <code>public_key</code> and the <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> for
<code>account</code> under <code>account</code>.


<a name="@Parameters_12"></a>

### Parameters

| Name         | Type         | Description                                                                                        |
| ------       | ------       | -------------                                                                                      |
| <code>account</code>    | <code>signer</code>     | The signer of the sending account of the transaction.                                              |
| <code>public_key</code> | <code>vector&lt;u8&gt;</code> | A valid 32-byte Ed25519 public key for <code>account</code>'s authentication key to be rotated to and stored. |


<a name="@Common_Abort_Conditions_13"></a>

### Common Abort Conditions

| Error Category              | Error Reason                                               | Description                                                                                         |
| ----------------            | --------------                                             | -------------                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>     | <code><a href="DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> resource.       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_ESHARED_KEY">SharedEd25519PublicKey::ESHARED_KEY</a></code>                      | The <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource is already published under <code>account</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_EMALFORMED_PUBLIC_KEY">SharedEd25519PublicKey::EMALFORMED_PUBLIC_KEY</a></code>            | <code>public_key</code> is an invalid ed25519 public key.                                                      |


<a name="@Related_Scripts_14"></a>

### Related Scripts

* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key">AccountAdministrationScripts::rotate_shared_ed25519_public_key</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">publish_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">publish_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;) {
    <a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_publish">SharedEd25519PublicKey::publish</a>(&account, public_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_PublishAbortsIf">SharedEd25519PublicKey::PublishAbortsIf</a>{key: public_key};
<b>include</b> <a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_PublishEnsures">SharedEd25519PublicKey::PublishEnsures</a>{key: public_key};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key"></a>

## Function `rotate_authentication_key`


<a name="@Summary_15"></a>

### Summary

Rotates the <code>account</code>'s authentication key to the supplied new authentication key. May be sent by any account.


<a name="@Technical_Description_16"></a>

### Technical Description

Rotate the <code>account</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>authentication_key</code>
field to <code>new_key</code>. <code>new_key</code> must be a valid authentication key that
corresponds to an ed25519 public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
and <code>account</code> must not have previously delegated its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_17"></a>

### Parameters

| Name      | Type         | Description                                       |
| ------    | ------       | -------------                                     |
| <code>account</code> | <code>signer</code>     | Signer of the sending account of the transaction. |
| <code>new_key</code> | <code>vector&lt;u8&gt;</code> | New authentication key to be used for <code>account</code>.  |


<a name="@Common_Abort_Conditions_18"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                              | Description                                                                         |
| ----------------           | --------------                                            | -------------                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>              | <code>new_key</code> was an invalid length.                                                    |


<a name="@Related_Scripts_19"></a>

### Related Scripts

* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">AccountAdministrationScripts::rotate_authentication_key_with_nonce</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key">rotate_authentication_key</a>(account: signer, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key">rotate_authentication_key</a>(account: signer, new_key: vector&lt;u8&gt;) {
    <b>let</b> key_rotation_capability = <a href="DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account);
    <a href="DiemAccount.md#0x1_DiemAccount_rotate_authentication_key">DiemAccount::rotate_authentication_key</a>(&key_rotation_capability, new_key);
    <a href="DiemAccount.md#0x1_DiemAccount_restore_key_rotation_capability">DiemAccount::restore_key_rotation_capability</a>(key_rotation_capability);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>let</b> key_rotation_capability = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyAbortsIf">DiemAccount::RotateAuthenticationKeyAbortsIf</a>{cap: key_rotation_capability, new_authentication_key: new_key};
</code></pre>


This rotates the authentication key of <code>account</code> to <code>new_key</code>


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyEnsures">DiemAccount::RotateAuthenticationKeyEnsures</a>{addr: account_addr, new_authentication_key: new_key};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>


**Access Control:**
The account can rotate its own authentication key unless
it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_AbortsIfDelegatedKeyRotationCapability">DiemAccount::AbortsIfDelegatedKeyRotationCapability</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce"></a>

## Function `rotate_authentication_key_with_nonce`


<a name="@Summary_20"></a>

### Summary

Rotates the sender's authentication key to the supplied new authentication key. May be sent by
any account that has a sliding nonce resource published under it (usually this is Treasury
Compliance or Diem Root accounts).


<a name="@Technical_Description_21"></a>

### Technical Description

Rotates the <code>account</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>authentication_key</code>
field to <code>new_key</code>. <code>new_key</code> must be a valid authentication key that
corresponds to an ed25519 public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
and <code>account</code> must not have previously delegated its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_22"></a>

### Parameters

| Name            | Type         | Description                                                                |
| ------          | ------       | -------------                                                              |
| <code>account</code>       | <code>signer</code>     | Signer of the sending account of the transaction.                          |
| <code>sliding_nonce</code> | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction. |
| <code>new_key</code>       | <code>vector&lt;u8&gt;</code> | New authentication key to be used for <code>account</code>.                           |


<a name="@Common_Abort_Conditions_23"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                               | Description                                                                                |
| ----------------           | --------------                                             | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                             | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                             | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                             | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>                    | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>              | <code>new_key</code> was an invalid length.                                                           |


<a name="@Related_Scripts_24"></a>

### Related Scripts

* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">rotate_authentication_key_with_nonce</a>(account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">rotate_authentication_key_with_nonce</a>(account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <b>let</b> key_rotation_capability = <a href="DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account);
    <a href="DiemAccount.md#0x1_DiemAccount_rotate_authentication_key">DiemAccount::rotate_authentication_key</a>(&key_rotation_capability, new_key);
    <a href="DiemAccount.md#0x1_DiemAccount_restore_key_rotation_capability">DiemAccount::restore_key_rotation_capability</a>(key_rotation_capability);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ seq_nonce: sliding_nonce };
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>let</b> key_rotation_capability = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyAbortsIf">DiemAccount::RotateAuthenticationKeyAbortsIf</a>{cap: key_rotation_capability, new_authentication_key: new_key};
</code></pre>


This rotates the authentication key of <code>account</code> to <code>new_key</code>


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyEnsures">DiemAccount::RotateAuthenticationKeyEnsures</a>{addr: account_addr, new_authentication_key: new_key};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
</code></pre>


**Access Control:**
The account can rotate its own authentication key unless
it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_AbortsIfDelegatedKeyRotationCapability">DiemAccount::AbortsIfDelegatedKeyRotationCapability</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin"></a>

## Function `rotate_authentication_key_with_nonce_admin`


<a name="@Summary_25"></a>

### Summary

Rotates the specified account's authentication key to the supplied new authentication key. May
only be sent by the Diem Root account as a write set transaction.


<a name="@Technical_Description_26"></a>

### Technical Description

Rotate the <code>account</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>authentication_key</code> field to <code>new_key</code>.
<code>new_key</code> must be a valid authentication key that corresponds to an ed25519
public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
and <code>account</code> must not have previously delegated its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_27"></a>

### Parameters

| Name            | Type         | Description                                                                                       |
| ------          | ------       | -------------                                                                                     |
| <code>dr_account</code>    | <code>signer</code>     | The signer of the sending account of the write set transaction. May only be the Diem Root signer. |
| <code>account</code>       | <code>signer</code>     | Signer of account specified in the <code>execute_as</code> field of the write set transaction.               |
| <code>sliding_nonce</code> | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction for Diem Root.          |
| <code>new_key</code>       | <code>vector&lt;u8&gt;</code> | New authentication key to be used for <code>account</code>.                                                  |


<a name="@Common_Abort_Conditions_28"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                              | Description                                                                                                |
| ----------------           | --------------                                            | -------------                                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                            | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                            | The <code>sliding_nonce</code> in <code>dr_account</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                            | The <code>sliding_nonce</code> in <code>dr_account</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>                   | The <code>sliding_nonce</code> in<code> dr_account</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.                        |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>              | <code>new_key</code> was an invalid length.                                                                           |


<a name="@Related_Scripts_29"></a>

### Related Scripts

* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">AccountAdministrationScripts::rotate_authentication_key_with_nonce</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">rotate_authentication_key_with_nonce_admin</a>(dr_account: signer, account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">rotate_authentication_key_with_nonce_admin</a>(dr_account: signer, account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <b>let</b> key_rotation_capability = <a href="DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account);
    <a href="DiemAccount.md#0x1_DiemAccount_rotate_authentication_key">DiemAccount::rotate_authentication_key</a>(&key_rotation_capability, new_key);
    <a href="DiemAccount.md#0x1_DiemAccount_restore_key_rotation_capability">DiemAccount::restore_key_rotation_capability</a>(key_rotation_capability);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ account: dr_account, seq_nonce: sliding_nonce };
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>let</b> key_rotation_capability = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyAbortsIf">DiemAccount::RotateAuthenticationKeyAbortsIf</a>{cap: key_rotation_capability, new_authentication_key: new_key};
</code></pre>


This rotates the authentication key of <code>account</code> to <code>new_key</code>


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyEnsures">DiemAccount::RotateAuthenticationKeyEnsures</a>{addr: account_addr, new_authentication_key: new_key};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can process the admin scripts [[H9]][PERMISSION].


<pre><code><b>requires</b> <a href="Roles.md#0x1_Roles_has_diem_root_role">Roles::has_diem_root_role</a>(dr_account);
</code></pre>


This is ensured by DiemAccount::writeset_prologue.
The account can rotate its own authentication key unless
it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_AbortsIfDelegatedKeyRotationCapability">DiemAccount::AbortsIfDelegatedKeyRotationCapability</a>{account: account};
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address"></a>

## Function `rotate_authentication_key_with_recovery_address`


<a name="@Summary_30"></a>

### Summary

Rotates the authentication key of a specified account that is part of a recovery address to a
new authentication key. Only used for accounts that are part of a recovery address (see
<code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code> for account restrictions).


<a name="@Technical_Description_31"></a>

### Technical Description

Rotates the authentication key of the <code>to_recover</code> account to <code>new_key</code> using the
<code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> stored in the <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource
published under <code>recovery_address</code>. <code>new_key</code> must be a valide authentication key as described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
This transaction can be sent either by the <code>to_recover</code> account, or by the account where the
<code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource is published that contains <code>to_recover</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_32"></a>

### Parameters

| Name               | Type         | Description                                                                                                                   |
| ------             | ------       | -------------                                                                                                                 |
| <code>account</code>          | <code>signer</code>     | Signer of the sending account of the transaction.                                                                             |
| <code>recovery_address</code> | <code>address</code>    | Address where <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> that holds <code>to_recover</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> is published. |
| <code>to_recover</code>       | <code>address</code>    | The address of the account whose authentication key will be updated.                                                          |
| <code>new_key</code>          | <code>vector&lt;u8&gt;</code> | New authentication key to be used for the account at the <code>to_recover</code> address.                                                |


<a name="@Common_Abort_Conditions_33"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                 | Description                                                                                                                                         |
| ----------------           | --------------                               | -------------                                                                                                                                       |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_ERECOVERY_ADDRESS">RecoveryAddress::ERECOVERY_ADDRESS</a></code>         | <code>recovery_address</code> does not have a <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource published under it.                                                  |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_ECANNOT_ROTATE_KEY">RecoveryAddress::ECANNOT_ROTATE_KEY</a></code>        | The address of <code>account</code> is not <code>recovery_address</code> or <code>to_recover</code>.                                                                                 |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_EACCOUNT_NOT_RECOVERABLE">RecoveryAddress::EACCOUNT_NOT_RECOVERABLE</a></code>  | <code>to_recover</code>'s <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>  is not in the <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code>  resource published under <code>recovery_address</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code> | <code>new_key</code> was an invalid length.                                                                                                                    |


<a name="@Related_Scripts_34"></a>

### Related Scripts

* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">AccountAdministrationScripts::rotate_authentication_key_with_nonce</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">rotate_authentication_key_with_recovery_address</a>(account: signer, recovery_address: address, to_recover: address, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">rotate_authentication_key_with_recovery_address</a>(
        account: signer,
        recovery_address: address,
        to_recover: address,
        new_key: vector&lt;u8&gt;
        ) {
    <a href="RecoveryAddress.md#0x1_RecoveryAddress_rotate_authentication_key">RecoveryAddress::rotate_authentication_key</a>(&account, recovery_address, to_recover, new_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress_RotateAuthenticationKeyAbortsIf">RecoveryAddress::RotateAuthenticationKeyAbortsIf</a>;
<b>include</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress_RotateAuthenticationKeyEnsures">RecoveryAddress::RotateAuthenticationKeyEnsures</a>;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>


**Access Control:**
The delegatee at the recovery address has to hold the key rotation capability for
the address to recover. The address of the transaction signer has to be either
the delegatee's address or the address to recover [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>aborts_if</b> !<a href="RecoveryAddress.md#0x1_RecoveryAddress_spec_holds_key_rotation_cap_for">RecoveryAddress::spec_holds_key_rotation_cap_for</a>(recovery_address, to_recover) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
<b>aborts_if</b> !(account_addr == recovery_address || account_addr == to_recover) <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_dual_attestation_info"></a>

## Function `rotate_dual_attestation_info`


<a name="@Summary_35"></a>

### Summary

Updates the url used for off-chain communication, and the public key used to verify dual
attestation on-chain. Transaction can be sent by any account that has dual attestation
information published under it. In practice the only such accounts are Designated Dealers and
Parent VASPs.


<a name="@Technical_Description_36"></a>

### Technical Description

Updates the <code>base_url</code> and <code>compliance_public_key</code> fields of the <code><a href="DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code>
resource published under <code>account</code>. The <code>new_key</code> must be a valid ed25519 public key.


<a name="@Events_37"></a>

### Events

Successful execution of this transaction emits two events:
* A <code><a href="DualAttestation.md#0x1_DualAttestation_ComplianceKeyRotationEvent">DualAttestation::ComplianceKeyRotationEvent</a></code> containing the new compliance public key, and
the blockchain time at which the key was updated emitted on the <code><a href="DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code>
<code>compliance_key_rotation_events</code> handle published under <code>account</code>; and
* A <code><a href="DualAttestation.md#0x1_DualAttestation_BaseUrlRotationEvent">DualAttestation::BaseUrlRotationEvent</a></code> containing the new base url to be used for
off-chain communication, and the blockchain time at which the url was updated emitted on the
<code><a href="DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code> <code>base_url_rotation_events</code> handle published under <code>account</code>.


<a name="@Parameters_38"></a>

### Parameters

| Name      | Type         | Description                                                               |
| ------    | ------       | -------------                                                             |
| <code>account</code> | <code>signer</code>     | Signer of the sending account of the transaction.                         |
| <code>new_url</code> | <code>vector&lt;u8&gt;</code> | ASCII-encoded url to be used for off-chain communication with <code>account</code>.  |
| <code>new_key</code> | <code>vector&lt;u8&gt;</code> | New ed25519 public key to be used for on-chain dual attestation checking. |


<a name="@Common_Abort_Conditions_39"></a>

### Common Abort Conditions

| Error Category             | Error Reason                           | Description                                                                |
| ----------------           | --------------                         | -------------                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="DualAttestation.md#0x1_DualAttestation_ECREDENTIAL">DualAttestation::ECREDENTIAL</a></code>         | A <code><a href="DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code> resource is not published under <code>account</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="DualAttestation.md#0x1_DualAttestation_EINVALID_PUBLIC_KEY">DualAttestation::EINVALID_PUBLIC_KEY</a></code> | <code>new_key</code> is not a valid ed25519 public key.                               |


<a name="@Related_Scripts_40"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_designated_dealer">AccountCreationScripts::create_designated_dealer</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">rotate_dual_attestation_info</a>(account: signer, new_url: vector&lt;u8&gt;, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">rotate_dual_attestation_info</a>(account: signer, new_url: vector&lt;u8&gt;, new_key: vector&lt;u8&gt;) {
    <a href="DualAttestation.md#0x1_DualAttestation_rotate_base_url">DualAttestation::rotate_base_url</a>(&account, new_url);
    <a href="DualAttestation.md#0x1_DualAttestation_rotate_compliance_public_key">DualAttestation::rotate_compliance_public_key</a>(&account, new_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_RotateBaseUrlAbortsIf">DualAttestation::RotateBaseUrlAbortsIf</a>;
<b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_RotateBaseUrlEnsures">DualAttestation::RotateBaseUrlEnsures</a>;
<b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_RotateCompliancePublicKeyAbortsIf">DualAttestation::RotateCompliancePublicKeyAbortsIf</a>;
<b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_RotateCompliancePublicKeyEnsures">DualAttestation::RotateCompliancePublicKeyEnsures</a>;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
<b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_RotateBaseUrlEmits">DualAttestation::RotateBaseUrlEmits</a>;
<b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_RotateCompliancePublicKeyEmits">DualAttestation::RotateCompliancePublicKeyEmits</a>;
</code></pre>


**Access Control:**
Only the account having Credential can rotate the info.
Credential is granted to either a Parent VASP or a designated dealer [[H17]][PERMISSION].


<pre><code><b>include</b> <a href="DualAttestation.md#0x1_DualAttestation_AbortsIfNoCredential">DualAttestation::AbortsIfNoCredential</a>{addr: <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account)};
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key"></a>

## Function `rotate_shared_ed25519_public_key`


<a name="@Summary_41"></a>

### Summary

Rotates the authentication key in a <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey">SharedEd25519PublicKey</a></code>. This transaction can be sent by
any account that has previously published a shared ed25519 public key using
<code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">AccountAdministrationScripts::publish_shared_ed25519_public_key</a></code>.


<a name="@Technical_Description_42"></a>

### Technical Description

<code>public_key</code> must be a valid ed25519 public key.  This transaction first rotates the public key stored in <code>account</code>'s
<code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource to <code>public_key</code>, after which it
rotates the <code>account</code>'s authentication key to the new authentication key derived from <code>public_key</code> as defined
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys)
using the <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> stored in <code>account</code>'s <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code>.


<a name="@Parameters_43"></a>

### Parameters

| Name         | Type         | Description                                           |
| ------       | ------       | -------------                                         |
| <code>account</code>    | <code>signer</code>     | The signer of the sending account of the transaction. |
| <code>public_key</code> | <code>vector&lt;u8&gt;</code> | 32-byte Ed25519 public key.                           |


<a name="@Common_Abort_Conditions_44"></a>

### Common Abort Conditions

| Error Category             | Error Reason                                    | Description                                                                                   |
| ----------------           | --------------                                  | -------------                                                                                 |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_ESHARED_KEY">SharedEd25519PublicKey::ESHARED_KEY</a></code>           | A <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource is not published under <code>account</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_EMALFORMED_PUBLIC_KEY">SharedEd25519PublicKey::EMALFORMED_PUBLIC_KEY</a></code> | <code>public_key</code> is an invalid ed25519 public key.                                                |


<a name="@Related_Scripts_45"></a>

### Related Scripts

* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">AccountAdministrationScripts::publish_shared_ed25519_public_key</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key">rotate_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key">rotate_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;) {
    <a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_rotate_key">SharedEd25519PublicKey::rotate_key</a>(&account, public_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_RotateKeyAbortsIf">SharedEd25519PublicKey::RotateKeyAbortsIf</a>{new_public_key: public_key};
<b>include</b> <a href="SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_RotateKeyEnsures">SharedEd25519PublicKey::RotateKeyEnsures</a>{new_public_key: public_key};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_create_recovery_address"></a>

## Function `create_recovery_address`


<a name="@Summary_46"></a>

### Summary

Initializes the sending account as a recovery address that may be used by
other accounts belonging to the same VASP as <code>account</code>.
The sending account must be a VASP account, and can be either a child or parent VASP account.
Multiple recovery addresses can exist for a single VASP, but accounts in
each must be disjoint.


<a name="@Technical_Description_47"></a>

### Technical Description

Publishes a <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource under <code>account</code>. It then
extracts the <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> for <code>account</code> and adds
it to the resource. After the successful execution of this transaction
other accounts may add their key rotation to this resource so that <code>account</code>
may be used as a recovery account for those accounts.


<a name="@Parameters_48"></a>

### Parameters

| Name      | Type     | Description                                           |
| ------    | ------   | -------------                                         |
| <code>account</code> | <code>signer</code> | The signer of the sending account of the transaction. |


<a name="@Common_Abort_Conditions_49"></a>

### Common Abort Conditions

| Error Category              | Error Reason                                               | Description                                                                                   |
| ----------------            | --------------                                             | -------------                                                                                 |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>     | <code><a href="DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_ENOT_A_VASP">RecoveryAddress::ENOT_A_VASP</a></code>                             | <code>account</code> is not a VASP account.                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_EKEY_ROTATION_DEPENDENCY_CYCLE">RecoveryAddress::EKEY_ROTATION_DEPENDENCY_CYCLE</a></code>          | A key rotation recovery cycle would be created by adding <code>account</code>'s key rotation capability. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_ERECOVERY_ADDRESS">RecoveryAddress::ERECOVERY_ADDRESS</a></code>                       | A <code><a href="RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource has already been published under <code>account</code>.     |


<a name="@Related_Scripts_50"></a>

### Related Scripts

* <code>Script::add_recovery_rotation_capability</code>
* <code>Script::rotate_authentication_key_with_recovery_address</code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_recovery_address">create_recovery_address</a>(account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_recovery_address">create_recovery_address</a>(account: signer) {
    <a href="RecoveryAddress.md#0x1_RecoveryAddress_publish">RecoveryAddress::publish</a>(&account, <a href="DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account))
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityEnsures">DiemAccount::ExtractKeyRotationCapabilityEnsures</a>;
<b>let</b> account_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>let</b> rotation_cap = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress_PublishAbortsIf">RecoveryAddress::PublishAbortsIf</a>{
    recovery_account: account,
    rotation_cap: rotation_cap
};
<b>ensures</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress_spec_is_recovery_address">RecoveryAddress::spec_is_recovery_address</a>(account_addr);
<b>ensures</b> len(<a href="RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(account_addr)) == 1;
<b>ensures</b> <a href="RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(account_addr)[0] == rotation_cap;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_create_vasp_domains"></a>

## Function `create_vasp_domains`


<a name="@Summary_51"></a>

### Summary

Publishes a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource under a parent VASP account.
The sending account must be a parent VASP account.


<a name="@Technical_Description_52"></a>

### Technical Description

Publishes a <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource under <code>account</code>.
The The <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource's <code>domains</code> field is a vector
of VASPDomain, and will be empty on at the end of processing this transaction.


<a name="@Parameters_53"></a>

### Parameters

| Name      | Type     | Description                                           |
| ------    | ------   | -------------                                         |
| <code>account</code> | <code>signer</code> | The signer of the sending account of the transaction. |


<a name="@Common_Abort_Conditions_54"></a>

### Common Abort Conditions

| Error Category              | Error Reason              | Description                                                                    |
| ----------------            | --------------            | -------------                                                                  |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS">VASPDomain::EVASP_DOMAINS</a></code> | A <code><a href="VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource has already been published under <code>account</code>. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="Roles.md#0x1_Roles_EPARENT_VASP">Roles::EPARENT_VASP</a></code>     | The sending <code>account</code> was not a parent VASP account.                           |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_vasp_domains">create_vasp_domains</a>(account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_vasp_domains">create_vasp_domains</a>(account: signer) {
    <a href="VASPDomain.md#0x1_VASPDomain_publish_vasp_domains">VASPDomain::publish_vasp_domains</a>(&account)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> vasp_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotParentVasp">Roles::AbortsIfNotParentVasp</a>;
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsAbortsIf">VASPDomain::PublishVASPDomainsAbortsIf</a> { vasp_addr };
<b>include</b> <a href="VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsEnsures">VASPDomain::PublishVASPDomainsEnsures</a> { vasp_addr };
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
