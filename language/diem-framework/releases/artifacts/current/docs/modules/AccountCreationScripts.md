
<a name="0x1_AccountCreationScripts"></a>

# Module `0x1::AccountCreationScripts`



-  [Function `create_child_vasp_account`](#0x1_AccountCreationScripts_create_child_vasp_account)
    -  [Summary](#@Summary_0)
    -  [Technical Description](#@Technical_Description_1)
    -  [Events](#@Events_2)
    -  [Parameters](#@Parameters_3)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_4)
    -  [Related Scripts](#@Related_Scripts_5)
-  [Function `create_validator_operator_account`](#0x1_AccountCreationScripts_create_validator_operator_account)
    -  [Summary](#@Summary_6)
    -  [Technical Description](#@Technical_Description_7)
    -  [Events](#@Events_8)
    -  [Parameters](#@Parameters_9)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_10)
    -  [Related Scripts](#@Related_Scripts_11)
-  [Function `create_validator_account`](#0x1_AccountCreationScripts_create_validator_account)
    -  [Summary](#@Summary_12)
    -  [Technical Description](#@Technical_Description_13)
    -  [Events](#@Events_14)
    -  [Parameters](#@Parameters_15)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_16)
    -  [Related Scripts](#@Related_Scripts_17)
-  [Function `create_parent_vasp_account`](#0x1_AccountCreationScripts_create_parent_vasp_account)
    -  [Summary](#@Summary_18)
    -  [Technical Description](#@Technical_Description_19)
    -  [Events](#@Events_20)
    -  [Parameters](#@Parameters_21)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_22)
    -  [Related Scripts](#@Related_Scripts_23)
-  [Function `create_designated_dealer`](#0x1_AccountCreationScripts_create_designated_dealer)
    -  [Summary](#@Summary_24)
    -  [Technical Description](#@Technical_Description_25)
    -  [Events](#@Events_26)
    -  [Parameters](#@Parameters_27)
    -  [Common Abort Conditions](#@Common_Abort_Conditions_28)
    -  [Related Scripts](#@Related_Scripts_29)


<pre><code><b>use</b> <a href="DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
<b>use</b> <a href="SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
</code></pre>



<a name="0x1_AccountCreationScripts_create_child_vasp_account"></a>

## Function `create_child_vasp_account`


<a name="@Summary_0"></a>

### Summary

Creates a Child VASP account with its parent being the sending account of the transaction.
The sender of the transaction must be a Parent VASP account.


<a name="@Technical_Description_1"></a>

### Technical Description

Creates a <code>ChildVASP</code> account for the sender <code>parent_vasp</code> at <code>child_address</code> with a balance of
<code>child_initial_balance</code> in <code>CoinType</code> and an initial authentication key of
<code>auth_key_prefix | child_address</code>. Authentication key prefixes, and how to construct them from an ed25519 public key is described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).

If <code>add_all_currencies</code> is true, the child address will have a zero balance in all available
currencies in the system.

The new account will be a child account of the transaction sender, which must be a
Parent VASP account. The child account will be recorded against the limit of
child accounts of the creating Parent VASP account.


<a name="@Events_2"></a>

### Events

Successful execution will emit:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>child_address</code>,
and the <code>rold_id</code> field being <code><a href="Roles.md#0x1_Roles_CHILD_VASP_ROLE_ID">Roles::CHILD_VASP_ROLE_ID</a></code>. This is emitted on the
<code><a href="DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.

Successful execution with a <code>child_initial_balance</code> greater than zero will additionaly emit:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a></code> with the <code>payee</code> field being <code>child_address</code>.
This is emitted on the Parent VASP's <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code> handle.
* A <code><a href="DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> with the  <code>payer</code> field being the Parent VASP's address.
This is emitted on the new Child VASPS's <code><a href="DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> handle.


<a name="@Parameters_3"></a>

### Parameters

| Name                    | Type         | Description                                                                                                                                 |
| ------                  | ------       | -------------                                                                                                                               |
| <code>CoinType</code>              | Type         | The Move type for the <code>CoinType</code> that the child account should be created with. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>parent_vasp</code>           | <code>signer</code>     | The reference of the sending account. Must be a Parent VASP account.                                                                        |
| <code>child_address</code>         | <code>address</code>    | Address of the to-be-created Child VASP account.                                                                                            |
| <code>auth_key_prefix</code>       | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account.                                                    |
| <code>add_all_currencies</code>    | <code>bool</code>       | Whether to publish balance resources for all known currencies when the account is created.                                                  |
| <code>child_initial_balance</code> | <code>u64</code>        | The initial balance in <code>CoinType</code> to give the child account when it's created.                                                              |


<a name="@Common_Abort_Conditions_4"></a>

### Common Abort Conditions

| Error Category              | Error Reason                                             | Description                                                                              |
| ----------------            | --------------                                           | -------------                                                                            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>            | The <code>auth_key_prefix</code> was not of length 32.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="Roles.md#0x1_Roles_EPARENT_VASP">Roles::EPARENT_VASP</a></code>                                    | The sending account wasn't a Parent VASP account.                                        |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                                        | The <code>child_address</code> address is already taken.                                            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>    | <code><a href="VASP.md#0x1_VASP_ETOO_MANY_CHILDREN">VASP::ETOO_MANY_CHILDREN</a></code>                               | The sending account has reached the maximum number of allowed child accounts.            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                                  | The <code>CoinType</code> is not a registered currency on-chain.                                    |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a></code>     | <code>DiemAccount::EWITHDRAWAL_CAPABILITY_ALREADY_EXTRACTED</code> | The withdrawal capability for the sending account has already been extracted.            |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>              | The sending account doesn't have a balance in <code>CoinType</code>.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>    | <code><a href="DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>                    | The sending account doesn't have at least <code>child_initial_balance</code> of <code>CoinType</code> balance. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="DiemAccount.md#0x1_DiemAccount_ECANNOT_CREATE_AT_VM_RESERVED">DiemAccount::ECANNOT_CREATE_AT_VM_RESERVED</a></code>            | The <code>child_address</code> is the reserved address 0x0.                                         |


<a name="@Related_Scripts_5"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_child_vasp_account">create_child_vasp_account</a>&lt;CoinType&gt;(parent_vasp: signer, child_address: address, auth_key_prefix: vector&lt;u8&gt;, add_all_currencies: bool, child_initial_balance: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_child_vasp_account">create_child_vasp_account</a>&lt;CoinType&gt;(
    parent_vasp: signer,
    child_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    add_all_currencies: bool,
    child_initial_balance: u64
) {
    <a href="DiemAccount.md#0x1_DiemAccount_create_child_vasp_account">DiemAccount::create_child_vasp_account</a>&lt;CoinType&gt;(
        &parent_vasp,
        child_address,
        auth_key_prefix,
        add_all_currencies,
    );
    // Give the newly created child `child_initial_balance` coins
    <b>if</b> (child_initial_balance &gt; 0) {
        <b>let</b> vasp_withdrawal_cap = <a href="DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&parent_vasp);
        <a href="DiemAccount.md#0x1_DiemAccount_pay_from">DiemAccount::pay_from</a>&lt;CoinType&gt;(
            &vasp_withdrawal_cap, child_address, child_initial_balance, x"", x""
        );
        <a href="DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(vasp_withdrawal_cap);
    };
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: parent_vasp};
<b>let</b> parent_addr = <a href="../../../../../../move-stdlib/docs/Signer.md#0x1_Signer_spec_address_of">Signer::spec_address_of</a>(parent_vasp);
<b>let</b> parent_cap = <a href="DiemAccount.md#0x1_DiemAccount_spec_get_withdraw_cap">DiemAccount::spec_get_withdraw_cap</a>(parent_addr);
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateChildVASPAccountAbortsIf">DiemAccount::CreateChildVASPAccountAbortsIf</a>&lt;CoinType&gt;{
    parent: parent_vasp, new_account_address: child_address};
<b>aborts_if</b> child_initial_balance &gt; max_u64() <b>with</b> <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
<b>include</b> (child_initial_balance &gt; 0) ==&gt;
    <a href="DiemAccount.md#0x1_DiemAccount_ExtractWithdrawCapAbortsIf">DiemAccount::ExtractWithdrawCapAbortsIf</a>{sender_addr: parent_addr};
<b>include</b> (child_initial_balance &gt; 0) ==&gt; <a href="DualAttestation.md#0x1_DualAttestation_AssertPaymentOkAbortsIf">DualAttestation::AssertPaymentOkAbortsIf</a>&lt;CoinType&gt;{
    payer: parent_addr,
    payee: child_address,
    metadata: x"",
    metadata_signature: x"",
    value: child_initial_balance
};
<b>include</b> (child_initial_balance) &gt; 0 ==&gt;
    <a href="DiemAccount.md#0x1_DiemAccount_PayFromAbortsIfRestricted">DiemAccount::PayFromAbortsIfRestricted</a>&lt;CoinType&gt;{
        cap: parent_cap,
        payee: child_address,
        amount: child_initial_balance,
        metadata: x"",
    };
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateChildVASPAccountEnsures">DiemAccount::CreateChildVASPAccountEnsures</a>&lt;CoinType&gt;{
    parent_addr: parent_addr,
    child_addr: child_address,
};
<b>ensures</b> <a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;CoinType&gt;(child_address) == child_initial_balance;
<b>ensures</b> <a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;CoinType&gt;(parent_addr)
    == <b>old</b>(<a href="DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;CoinType&gt;(parent_addr)) - child_initial_balance;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>


**Access Control:**
Only Parent VASP accounts can create Child VASP accounts [[A7]][ROLE].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotParentVasp">Roles::AbortsIfNotParentVasp</a>{account: parent_vasp};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_validator_operator_account"></a>

## Function `create_validator_operator_account`


<a name="@Summary_6"></a>

### Summary

Creates a Validator Operator account. This transaction can only be sent by the Diem
Root account.


<a name="@Technical_Description_7"></a>

### Technical Description

Creates an account with a Validator Operator role at <code>new_account_address</code>, with authentication key
<code>auth_key_prefix</code> | <code>new_account_address</code>. It publishes a
<code><a href="ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource with the specified <code>human_name</code>.
This script does not assign the validator operator to any validator accounts but only creates the account.
Authentication key prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).


<a name="@Events_8"></a>

### Events

Successful execution will emit:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>new_account_address</code>,
and the <code>rold_id</code> field being <code><a href="Roles.md#0x1_Roles_VALIDATOR_OPERATOR_ROLE_ID">Roles::VALIDATOR_OPERATOR_ROLE_ID</a></code>. This is emitted on the
<code><a href="DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_9"></a>

### Parameters

| Name                  | Type         | Description                                                                              |
| ------                | ------       | -------------                                                                            |
| <code>dr_account</code>          | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Diem Root signer.     |
| <code>sliding_nonce</code>       | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.               |
| <code>new_account_address</code> | <code>address</code>    | Address of the to-be-created Validator account.                                          |
| <code>auth_key_prefix</code>     | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account. |
| <code>human_name</code>          | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the validator.                                              |


<a name="@Common_Abort_Conditions_10"></a>

### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>            | The sending account is not the Diem Root account.                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="Roles.md#0x1_Roles_EDIEM_ROOT">Roles::EDIEM_ROOT</a></code>                    | The sending account is not the Diem Root account.                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>new_account_address</code> address is already taken.                                        |


<a name="@Related_Scripts_11"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_validator_operator_account">create_validator_operator_account</a>(dr_account: signer, sliding_nonce: u64, new_account_address: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_validator_operator_account">create_validator_operator_account</a>(
    dr_account: signer,
    sliding_nonce: u64,
    new_account_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;
) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <a href="DiemAccount.md#0x1_DiemAccount_create_validator_operator_account">DiemAccount::create_validator_operator_account</a>(
        &dr_account,
        new_account_address,
        auth_key_prefix,
        human_name,
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>

Only Diem root may create Validator Operator accounts
Authentication: ValidatorAccountAbortsIf includes AbortsIfNotDiemRoot.
Checks that above table includes all error categories.
The verifier finds an abort that is not documented, and cannot occur in practice:
* REQUIRES_ROLE comes from <code><a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a></code>. However, assert_diem_root checks the literal
Diem root address before checking the role, and the role abort is unreachable in practice, since
only Diem root has the Diem root role.


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: dr_account};
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{seq_nonce: sliding_nonce, account: dr_account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateValidatorOperatorAccountAbortsIf">DiemAccount::CreateValidatorOperatorAccountAbortsIf</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateValidatorOperatorAccountEnsures">DiemAccount::CreateValidatorOperatorAccountEnsures</a>;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can create Validator Operator accounts [[A4]][ROLE].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_validator_account"></a>

## Function `create_validator_account`


<a name="@Summary_12"></a>

### Summary

Creates a Validator account. This transaction can only be sent by the Diem
Root account.


<a name="@Technical_Description_13"></a>

### Technical Description

Creates an account with a Validator role at <code>new_account_address</code>, with authentication key
<code>auth_key_prefix</code> | <code>new_account_address</code>. It publishes a
<code><a href="ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource with empty <code>config</code>, and
<code>operator_account</code> fields. The <code>human_name</code> field of the
<code><a href="ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> is set to the passed in <code>human_name</code>.
This script does not add the validator to the validator set or the system,
but only creates the account.
Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).


<a name="@Events_14"></a>

### Events

Successful execution will emit:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>new_account_address</code>,
and the <code>rold_id</code> field being <code><a href="Roles.md#0x1_Roles_VALIDATOR_ROLE_ID">Roles::VALIDATOR_ROLE_ID</a></code>. This is emitted on the
<code><a href="DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_15"></a>

### Parameters

| Name                  | Type         | Description                                                                              |
| ------                | ------       | -------------                                                                            |
| <code>dr_account</code>          | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Diem Root signer.     |
| <code>sliding_nonce</code>       | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.               |
| <code>new_account_address</code> | <code>address</code>    | Address of the to-be-created Validator account.                                          |
| <code>auth_key_prefix</code>     | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account. |
| <code>human_name</code>          | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the validator.                                              |


<a name="@Common_Abort_Conditions_16"></a>

### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>            | The sending account is not the Diem Root account.                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="Roles.md#0x1_Roles_EDIEM_ROOT">Roles::EDIEM_ROOT</a></code>                    | The sending account is not the Diem Root account.                                         |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>new_account_address</code> address is already taken.                                        |


<a name="@Related_Scripts_17"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="ValidatorAdministrationScripts.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_validator_account">create_validator_account</a>(dr_account: signer, sliding_nonce: u64, new_account_address: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_validator_account">create_validator_account</a>(
    dr_account: signer,
    sliding_nonce: u64,
    new_account_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;,
) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <a href="DiemAccount.md#0x1_DiemAccount_create_validator_account">DiemAccount::create_validator_account</a>(
        &dr_account,
        new_account_address,
        auth_key_prefix,
        human_name,
    );
  }
</code></pre>



</details>

<details>
<summary>Specification</summary>

Only Diem root may create Validator accounts
Authentication: ValidatorAccountAbortsIf includes AbortsIfNotDiemRoot.
Checks that above table includes all error categories.
The verifier finds an abort that is not documented, and cannot occur in practice:
* REQUIRES_ROLE comes from <code><a href="Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a></code>. However, assert_diem_root checks the literal
Diem root address before checking the role, and the role abort is unreachable in practice, since
only Diem root has the Diem root role.


<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: dr_account};
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{seq_nonce: sliding_nonce, account: dr_account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateValidatorAccountAbortsIf">DiemAccount::CreateValidatorAccountAbortsIf</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateValidatorAccountEnsures">DiemAccount::CreateValidatorAccountEnsures</a>;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can create Validator accounts [[A3]][ROLE].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_parent_vasp_account"></a>

## Function `create_parent_vasp_account`


<a name="@Summary_18"></a>

### Summary

Creates a Parent VASP account with the specified human name. Must be called by the Treasury Compliance account.


<a name="@Technical_Description_19"></a>

### Technical Description

Creates an account with the Parent VASP role at <code>address</code> with authentication key
<code>auth_key_prefix</code> | <code>new_account_address</code> and a 0 balance of type <code>CoinType</code>. If
<code>add_all_currencies</code> is true, 0 balances for all available currencies in the system will
also be added. This can only be invoked by an TreasuryCompliance account.
<code>sliding_nonce</code> is a unique nonce for operation, see <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> for details.
Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).


<a name="@Events_20"></a>

### Events

Successful execution will emit:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>new_account_address</code>,
and the <code>rold_id</code> field being <code><a href="Roles.md#0x1_Roles_PARENT_VASP_ROLE_ID">Roles::PARENT_VASP_ROLE_ID</a></code>. This is emitted on the
<code><a href="DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_21"></a>

### Parameters

| Name                  | Type         | Description                                                                                                                                                    |
| ------                | ------       | -------------                                                                                                                                                  |
| <code>CoinType</code>            | Type         | The Move type for the <code>CoinType</code> currency that the Parent VASP account should be initialized with. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>          | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                                |
| <code>sliding_nonce</code>       | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                                                                     |
| <code>new_account_address</code> | <code>address</code>    | Address of the to-be-created Parent VASP account.                                                                                                              |
| <code>auth_key_prefix</code>     | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account.                                                                       |
| <code>human_name</code>          | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the Parent VASP.                                                                                                                  |
| <code>add_all_currencies</code>  | <code>bool</code>       | Whether to publish balance resources for all known currencies when the account is created.                                                                     |


<a name="@Common_Abort_Conditions_22"></a>

### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | The sending account is not the Treasury Compliance account.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>           | The sending account is not the Treasury Compliance account.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                 | The <code>CoinType</code> is not a registered currency on-chain.                                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>new_account_address</code> address is already taken.                                        |


<a name="@Related_Scripts_23"></a>

### Related Scripts

* <code><a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_parent_vasp_account">create_parent_vasp_account</a>&lt;CoinType&gt;(tc_account: signer, sliding_nonce: u64, new_account_address: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;, add_all_currencies: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_parent_vasp_account">create_parent_vasp_account</a>&lt;CoinType&gt;(
    tc_account: signer,
    sliding_nonce: u64,
    new_account_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;,
    add_all_currencies: bool
) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="DiemAccount.md#0x1_DiemAccount_create_parent_vasp_account">DiemAccount::create_parent_vasp_account</a>&lt;CoinType&gt;(
        &tc_account,
        new_account_address,
        auth_key_prefix,
        human_name,
        add_all_currencies
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{account: tc_account, seq_nonce: sliding_nonce};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateParentVASPAccountAbortsIf">DiemAccount::CreateParentVASPAccountAbortsIf</a>&lt;CoinType&gt;{creator_account: tc_account};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateParentVASPAccountEnsures">DiemAccount::CreateParentVASPAccountEnsures</a>&lt;CoinType&gt;;
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>;
</code></pre>


**Access Control:**
Only the Treasury Compliance account can create Parent VASP accounts [[A6]][ROLE].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_designated_dealer"></a>

## Function `create_designated_dealer`


<a name="@Summary_24"></a>

### Summary

Creates a Designated Dealer account with the provided information, and initializes it with
default mint tiers. The transaction can only be sent by the Treasury Compliance account.


<a name="@Technical_Description_25"></a>

### Technical Description

Creates an account with the Designated Dealer role at <code>addr</code> with authentication key
<code>auth_key_prefix</code> | <code>addr</code> and a 0 balance of type <code>Currency</code>. If <code>add_all_currencies</code> is true,
0 balances for all available currencies in the system will also be added. This can only be
invoked by an account with the TreasuryCompliance role.
Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).

At the time of creation the account is also initialized with default mint tiers of (500_000,
5000_000, 50_000_000, 500_000_000), and preburn areas for each currency that is added to the
account.


<a name="@Events_26"></a>

### Events

Successful execution will emit:
* A <code><a href="DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>addr</code>,
and the <code>rold_id</code> field being <code><a href="Roles.md#0x1_Roles_DESIGNATED_DEALER_ROLE_ID">Roles::DESIGNATED_DEALER_ROLE_ID</a></code>. This is emitted on the
<code><a href="DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_27"></a>

### Parameters

| Name                 | Type         | Description                                                                                                                                         |
| ------               | ------       | -------------                                                                                                                                       |
| <code>Currency</code>           | Type         | The Move type for the <code>Currency</code> that the Designated Dealer should be initialized with. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>         | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                     |
| <code>sliding_nonce</code>      | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                                                          |
| <code>addr</code>               | <code>address</code>    | Address of the to-be-created Designated Dealer account.                                                                                             |
| <code>auth_key_prefix</code>    | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account.                                                            |
| <code>human_name</code>         | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the Designated Dealer.                                                                                                 |
| <code>add_all_currencies</code> | <code>bool</code>       | Whether to publish preburn, balance, and tier info resources for all known (SCS) currencies or just <code>Currency</code> when the account is created.         |



<a name="@Common_Abort_Conditions_28"></a>

### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | The sending account is not the Treasury Compliance account.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>           | The sending account is not the Treasury Compliance account.                                |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                 | The <code>Currency</code> is not a registered currency on-chain.                                      |
| <code><a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>addr</code> address is already taken.                                                       |


<a name="@Related_Scripts_29"></a>

### Related Scripts

* <code><a href="TreasuryComplianceScripts.md#0x1_TreasuryComplianceScripts_tiered_mint">TreasuryComplianceScripts::tiered_mint</a></code>
* <code><a href="PaymentScripts.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>
* <code><a href="AccountAdministrationScripts.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_designated_dealer">create_designated_dealer</a>&lt;Currency&gt;(tc_account: signer, sliding_nonce: u64, addr: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;, add_all_currencies: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="AccountCreationScripts.md#0x1_AccountCreationScripts_create_designated_dealer">create_designated_dealer</a>&lt;Currency&gt;(
    tc_account: signer,
    sliding_nonce: u64,
    addr: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;,
    add_all_currencies: bool,
) {
    <a href="SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="DiemAccount.md#0x1_DiemAccount_create_designated_dealer">DiemAccount::create_designated_dealer</a>&lt;Currency&gt;(
        &tc_account,
        addr,
        auth_key_prefix,
        human_name,
        add_all_currencies
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{account: tc_account, seq_nonce: sliding_nonce};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateDesignatedDealerAbortsIf">DiemAccount::CreateDesignatedDealerAbortsIf</a>&lt;Currency&gt;{
    creator_account: tc_account, new_account_address: addr};
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_CreateDesignatedDealerEnsures">DiemAccount::CreateDesignatedDealerEnsures</a>&lt;Currency&gt;{new_account_address: addr};
<b>aborts_with</b> [check]
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="../../../../../../move-stdlib/docs/Errors.md#0x1_Errors_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>{new_account_address: addr};
</code></pre>


**Access Control:**
Only the Treasury Compliance account can create Designated Dealer accounts [[A5]][ROLE].


<pre><code><b>include</b> <a href="Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
