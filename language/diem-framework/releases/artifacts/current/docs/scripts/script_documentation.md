
<a name="@Overview_of_Diem_Transaction_Scripts_0"></a>

# Overview of Diem Transaction Scripts


-  [Introduction](#@Introduction_1)
    -  [Predefined Statuses](#@Predefined_Statuses_2)
    -  [Move Aborts](#@Move_Aborts_3)
        -  [Move Explain](#@Move_Explain_4)
    -  [Specifications](#@Specifications_5)
-  [Transaction Script Summaries](#@Transaction_Script_Summaries_6)
    -  [Account Creation](#@Account_Creation_7)
        -  [Script create_child_vasp_account](#@Script_create_child_vasp_account_8)
        -  [Script create_validator_operator_account](#@Script_create_validator_operator_account_9)
        -  [Script create_validator_account](#@Script_create_validator_account_10)
        -  [Script create_parent_vasp_account](#@Script_create_parent_vasp_account_11)
        -  [Script create_designated_dealer](#@Script_create_designated_dealer_12)
    -  [Account Administration](#@Account_Administration_13)
        -  [Script add_currency_to_account](#@Script_add_currency_to_account_14)
        -  [Script add_recovery_rotation_capability](#@Script_add_recovery_rotation_capability_15)
        -  [Script publish_shared_ed25519_public_key](#@Script_publish_shared_ed25519_public_key_16)
        -  [Script rotate_authentication_key](#@Script_rotate_authentication_key_17)
        -  [Script rotate_authentication_key_with_nonce](#@Script_rotate_authentication_key_with_nonce_18)
        -  [Script rotate_authentication_key_with_nonce_admin](#@Script_rotate_authentication_key_with_nonce_admin_19)
        -  [Script rotate_authentication_key_with_recovery_address](#@Script_rotate_authentication_key_with_recovery_address_20)
        -  [Script rotate_dual_attestation_info](#@Script_rotate_dual_attestation_info_21)
        -  [Script rotate_shared_ed25519_public_key](#@Script_rotate_shared_ed25519_public_key_22)
    -  [Payments](#@Payments_23)
        -  [Script peer_to_peer_with_metadata](#@Script_peer_to_peer_with_metadata_24)
    -  [Validator and Validator Operator Administration](#@Validator_and_Validator_Operator_Administration_25)
        -  [Script add_validator_and_reconfigure](#@Script_add_validator_and_reconfigure_26)
        -  [Script register_validator_config](#@Script_register_validator_config_27)
        -  [Script remove_validator_and_reconfigure](#@Script_remove_validator_and_reconfigure_28)
        -  [Script set_validator_config_and_reconfigure](#@Script_set_validator_config_and_reconfigure_29)
        -  [Script set_validator_operator](#@Script_set_validator_operator_30)
        -  [Script set_validator_operator_with_nonce_admin](#@Script_set_validator_operator_with_nonce_admin_31)
    -  [Treasury and Compliance Operations](#@Treasury_and_Compliance_Operations_32)
        -  [Script preburn](#@Script_preburn_33)
        -  [Script burn_with_amount](#@Script_burn_with_amount_34)
        -  [Script cancel_burn_with_amount](#@Script_cancel_burn_with_amount_35)
        -  [Script burn_txn_fees](#@Script_burn_txn_fees_36)
        -  [Script tiered_mint](#@Script_tiered_mint_37)
        -  [Script freeze_account](#@Script_freeze_account_38)
        -  [Script unfreeze_account](#@Script_unfreeze_account_39)
        -  [Script update_dual_attestation_limit](#@Script_update_dual_attestation_limit_40)
        -  [Script update_exchange_rate](#@Script_update_exchange_rate_41)
        -  [Script update_minting_ability](#@Script_update_minting_ability_42)
    -  [System Administration](#@System_Administration_43)
        -  [Script update_diem_version](#@Script_update_diem_version_44)
-  [Transaction Scripts](#@Transaction_Scripts_45)
    -  [Account Creation](#@Account_Creation_46)
        -  [Module `0x1::AccountCreationScripts`](#0x1_AccountCreationScripts)
    -  [Account Administration](#@Account_Administration_77)
        -  [Module `0x1::AccountAdministrationScripts`](#0x1_AccountAdministrationScripts)
    -  [Payments](#@Payments_133)
        -  [Module `0x1::PaymentScripts`](#0x1_PaymentScripts)
    -  [Validator and Validator Operator Administration](#@Validator_and_Validator_Operator_Administration_146)
        -  [Module `0x1::ValidatorAdministrationScripts`](#0x1_ValidatorAdministrationScripts)
    -  [Treasury and Compliance Operations](#@Treasury_and_Compliance_Operations_177)
        -  [Module `0x1::TreasuryComplianceScripts`](#0x1_TreasuryComplianceScripts)
    -  [System Administration](#@System_Administration_243)
        -  [Module `0x1::SystemAdministrationScripts`](#0x1_SystemAdministrationScripts)
    -  [Index](#@Index_260)



<a name="@Introduction_1"></a>

## Introduction


On-chain state is updated via the execution of transaction scripts sent from
accounts that exist on-chain. This page documents each allowed transaction
script on Diem, and the common state changes that can be performed to the
blockchain via these transaction scripts along with their arguments and common
error conditions.

The execution of a transaction script can result in a number of different error
conditions and statuses being returned for each transaction that is committed
on-chain. These statuses and errors can be categorized into two buckets:
* [Predefined statuses](#predefined-statuses): are specific statuses that are returned from the VM, e.g., <code>OutOfGas</code>, or <code>Executed</code>; and
* [Move Abort errors](#move-aborts): are errors that are raised from the Move modules and/or scripts published on-chain.

There are also a number of statuses that can be returned at the time of
submission of the transaction to the system through JSON-RPC, these are detailed in the
[JSON-RPC specification](https://github.com/diem/diem/blob/main/json-rpc/docs/method_submit.md#errors).


<a name="@Predefined_Statuses_2"></a>

### Predefined Statuses


The predefined set of runtime statuses that can be returned to the user as a
result of executing any transaction script is given by the following table:

| Name                     | Description                                                                                              |
| ----                     | ---                                                                                                      |
| <code>Executed</code>               | The transaction was executed successfully.                                                               |
| <code>OutOfGas</code>               | The transaction ran out of gas during execution.                                                         |
| <code>MiscellaneousError</code>     | The transaction was malformed, e.g., an argument was not in BCS format. Possible, but unlikely to occur. |
| <code>ExecutionFailure{ ...}</code> | The transaction encountered an uncaught error. Possible, but unlikely to occur.                          |

**This set of statuses is considered stable**, and they should not be expected to
change. Any changes will be publicized and an upgrade process will be outlined
if/when these statuses or their meanings are updated.


<a name="@Move_Aborts_3"></a>

### Move Aborts


Each Move abort error status consists of two pieces of data:
* The Move <code>location</code> where the abort was raised. This can be either from within a <code>Script</code> or from within a specific <code>Module</code>.
* The <code>abort_code</code> that was raised.

The <code>abort_code</code> is a <code>u64</code> that is constructed from two values:
1. The **error category** which is encoded in the lower 8 bits of the code. Error categories are
declared in the <code><a href="">Errors</a></code> module and are globally unique across the Diem framework. There is a limited
fixed set of predefined categories, and the framework is guaranteed to use these consistently.
2. The **error reason** which is encoded in the remaining 56 bits of the code. The reason is a unique
number relative to the module which raised the error and can be used to obtain more information about
the error at hand. It should primarily be used for diagnosis purposes. Error reasons may change over time as the
framework evolves.

The most common set of Move abort errors that can be returned depend on the transaction script
and they are therefore detailed in the documentation for each transaction
script. Each abort condition is broken down into its category, reason, and a
description of the error in the context of the particular transaction script
e.g.,

| Error Category           | Error Reason                                | Description                                               |
| ----------------         | --------------                              | -------------                                             |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code> | <code>payer</code> doesn't hold a balance in <code>Currency</code>.             |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>       | <code>amount</code> is greater than <code>payer</code>'s balance in <code>Currency</code>. |

For each of these tables, the **error categories should be considered stable**;
any changes to these categories will be be well-publicized in advance. On the
other hand, the **error reasons should be considered only semi-stable**; changes
to these may occur without notice, but changes are not expected to be common.


<a name="@Move_Explain_4"></a>

#### Move Explain


The abort conditions detailed in each transaction script are not meant to
be complete, but the list of error categories are. Additionally, any abort conditions
raised will have a human readable explanation attached to it (if possible) in the
[response](https://github.com/diem/diem/blob/main/json-rpc/docs/type_transaction.md#type-moveabortexplanation)
from a
[JSON-RPC query for a committed transaction](https://github.com/diem/diem/blob/main/json-rpc/json-rpc-spec.md).
These explanations are based off of the human-understandable explanations provided by the
[Move Explain](https://github.com/diem/diem/tree/main/language/tools/move-explain)
tool which can also be called on the command-line.


<a name="@Specifications_5"></a>

### Specifications


Transaction scripts come together with formal specifications. See [this document](./spec_documentation.md)
for a discussion of specifications and pointers to further documentation.

---

<a name="@Transaction_Script_Summaries_6"></a>

## Transaction Script Summaries

---

The set of transaction scripts that are allowed to be sent to the blockchain
can be categorized into six different buckets:
* [Account Creation](#account-creation)
* [Account Administration](#account-administration)
* [Payments](#payments)
* [Validator and Validator Operator Administration](#validator-and-validator-operator-administration)
* [Treasury and Compliance Operations](#treasury-and-compliance-operations)
* [System Administration](#system-administration)

This section contains a brief summary for each along with a link to the script's
detailed documentation. The entire list of detailed documentation for each
transaction script categorized in the same manner as here can be found in the
[transaction scripts](#transaction-scripts) section in this document.


<a name="@Account_Creation_7"></a>

### Account Creation


---

<a name="@Script_create_child_vasp_account_8"></a>

#### Script create_child_vasp_account


Creates a Child VASP account with its parent being the sending account of the transaction.
The sender of the transaction must be a Parent VASP account.

Script documentation: <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>

---

<a name="@Script_create_validator_operator_account_9"></a>

#### Script create_validator_operator_account


Creates a Validator Operator account. This transaction can only be sent by the Diem
Root account.

Script documentation: <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>

---

<a name="@Script_create_validator_account_10"></a>

#### Script create_validator_account


Creates a Validator account. This transaction can only be sent by the Diem
Root account.

Script documentation: <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>

---

<a name="@Script_create_parent_vasp_account_11"></a>

#### Script create_parent_vasp_account


Creates a Parent VASP account with the specified human name. Must be called by the Treasury Compliance account.

Script documentation: <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>


---

<a name="@Script_create_designated_dealer_12"></a>

#### Script create_designated_dealer


Creates a Designated Dealer account with the provided information, and initializes it with
default mint tiers. The transaction can only be sent by the Treasury Compliance account.

Script documentation: <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_designated_dealer">AccountCreationScripts::create_designated_dealer</a></code>



<a name="@Account_Administration_13"></a>

### Account Administration


---

<a name="@Script_add_currency_to_account_14"></a>

#### Script add_currency_to_account


Adds a zero <code>Currency</code> balance to the sending <code>account</code>. This will enable <code>account</code> to
send, receive, and hold <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;Currency&gt;</code> coins. This transaction can be
successfully sent by any account that is allowed to hold balances
(e.g., VASP, Designated Dealer).

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>


---

<a name="@Script_add_recovery_rotation_capability_15"></a>

#### Script add_recovery_rotation_capability


Stores the sending accounts ability to rotate its authentication key with a designated recovery
account. Both the sending and recovery accounts need to belong to the same VASP and
both be VASP accounts. After this transaction both the sending account and the
specified recovery account can rotate the sender account's authentication key.

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code>


---

<a name="@Script_publish_shared_ed25519_public_key_16"></a>

#### Script publish_shared_ed25519_public_key


Rotates the authentication key of the sending account to the
newly-specified public key and publishes a new shared authentication key
under the sender's account. Any account can send this transaction.

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">AccountAdministrationScripts::publish_shared_ed25519_public_key</a></code>


---

<a name="@Script_rotate_authentication_key_17"></a>

#### Script rotate_authentication_key


Rotates the transaction sender's authentication key to the supplied new authentication key. May
be sent by any account.

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>


---

<a name="@Script_rotate_authentication_key_with_nonce_18"></a>

#### Script rotate_authentication_key_with_nonce


Rotates the sender's authentication key to the supplied new authentication key. May be sent by
any account that has a sliding nonce resource published under it (usually this is Treasury
Compliance or Diem Root accounts).

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">AccountAdministrationScripts::rotate_authentication_key_with_nonce</a></code>


---

<a name="@Script_rotate_authentication_key_with_nonce_admin_19"></a>

#### Script rotate_authentication_key_with_nonce_admin


Rotates the specified account's authentication key to the supplied new authentication key. May
only be sent by the Diem Root account as a write set transaction.


Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin</a></code>


---

<a name="@Script_rotate_authentication_key_with_recovery_address_20"></a>

#### Script rotate_authentication_key_with_recovery_address


Rotates the authentication key of a specified account that is part of a recovery address to a
new authentication key. Only used for accounts that are part of a recovery address (see
<code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code> for account restrictions).

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


---

<a name="@Script_rotate_dual_attestation_info_21"></a>

#### Script rotate_dual_attestation_info


Updates the url used for off-chain communication, and the public key used to verify dual
attestation on-chain. Transaction can be sent by any account that has dual attestation
information published under it. In practice the only such accounts are Designated Dealers and
Parent VASPs.

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


---

<a name="@Script_rotate_shared_ed25519_public_key_22"></a>

#### Script rotate_shared_ed25519_public_key


Rotates the authentication key in a <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey">SharedEd25519PublicKey</a></code>. This transaction can be sent by
any account that has previously published a shared ed25519 public key using
<code><a href="script_documentation.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">AccountAdministrationScripts::publish_shared_ed25519_public_key</a></code>.

Script documentation: <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key">AccountAdministrationScripts::rotate_shared_ed25519_public_key</a></code>


<a name="@Payments_23"></a>

### Payments


---

<a name="@Script_peer_to_peer_with_metadata_24"></a>

#### Script peer_to_peer_with_metadata


Transfers a given number of coins in a specified currency from one account to another.
Transfers over a specified amount defined on-chain that are between two different VASPs, or
other accounts that have opted-in will be subject to on-chain checks to ensure the receiver has
agreed to receive the coins.  This transaction can be sent by any account that can hold a
balance, and to any account that can hold a balance. Both accounts must hold balances in the
currency being transacted.

Script documentation: <code><a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>



<a name="@Validator_and_Validator_Operator_Administration_25"></a>

### Validator and Validator Operator Administration


---

<a name="@Script_add_validator_and_reconfigure_26"></a>

#### Script add_validator_and_reconfigure


Adds a validator account to the validator set, and triggers a
reconfiguration of the system to admit the account to the validator set for the system. This
transaction can only be successfully called by the Diem Root account.

Script documentation: <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>


---

<a name="@Script_register_validator_config_27"></a>

#### Script register_validator_config


Updates a validator's configuration. This does not reconfigure the system and will not update
the configuration in the validator set that is seen by other validators in the network. Can
only be successfully sent by a Validator Operator account that is already registered with a
validator.

Script documentation: <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>


---

<a name="@Script_remove_validator_and_reconfigure_28"></a>

#### Script remove_validator_and_reconfigure


This script removes a validator account from the validator set, and triggers a reconfiguration
of the system to remove the validator from the system. This transaction can only be
successfully called by the Diem Root account.

Script documentation: <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>


---

<a name="@Script_set_validator_config_and_reconfigure_29"></a>

#### Script set_validator_config_and_reconfigure


Updates a validator's configuration, and triggers a reconfiguration of the system to update the
validator set with this new validator configuration.  Can only be successfully sent by a
Validator Operator account that is already registered with a validator.

Script documentation: <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


---

<a name="@Script_set_validator_operator_30"></a>

#### Script set_validator_operator


Sets the validator operator for a validator in the validator's configuration resource "locally"
and does not reconfigure the system. Changes from this transaction will not picked up by the
system until a reconfiguration of the system is triggered. May only be sent by an account with
Validator role.

Script documentation: <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>


---

<a name="@Script_set_validator_operator_with_nonce_admin_31"></a>

#### Script set_validator_operator_with_nonce_admin


Sets the validator operator for a validator in the validator's configuration resource "locally"
and does not reconfigure the system. Changes from this transaction will not picked up by the
system until a reconfiguration of the system is triggered. May only be sent by the Diem Root
account as a write set transaction.

Script documentation: <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>



<a name="@Treasury_and_Compliance_Operations_32"></a>

### Treasury and Compliance Operations


---

<a name="@Script_preburn_33"></a>

#### Script preburn


Moves a specified number of coins in a given currency from the account's
balance to its preburn area after which the coins may be burned. This
transaction may be sent by any account that holds a balance and preburn area
in the specified currency.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_preburn">TreasuryComplianceScripts::preburn</a></code>


---

<a name="@Script_burn_with_amount_34"></a>

#### Script burn_with_amount


Burns the coins held in a preburn resource in the preburn queue at the
specified preburn address, which are equal to the <code>amount</code> specified in the
transaction. Finds the first relevant outstanding preburn request with
matching amount and removes the contained coins from the system. The sending
account must be the Treasury Compliance account.
The account that holds the preburn queue resource will normally be a Designated
Dealer, but there are no enforced requirements that it be one.

Script documentation: <code>TreasuryComplianceScripts::burn</code>


---

<a name="@Script_cancel_burn_with_amount_35"></a>

#### Script cancel_burn_with_amount


Cancels and returns the coins held in the preburn area under
<code>preburn_address</code>, which are equal to the <code>amount</code> specified in the transaction. Finds the first preburn
resource with the matching amount and returns the funds to the <code>preburn_address</code>'s balance.
Can only be successfully sent by an account with Treasury Compliance role.

Script documentation: <code>TreasuryComplianceScripts::cancel_burn</code>


---

<a name="@Script_burn_txn_fees_36"></a>

#### Script burn_txn_fees


Burns the transaction fees collected in the <code>CoinType</code> currency so that the
Diem association may reclaim the backing coins off-chain. May only be sent
by the Treasury Compliance account.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_txn_fees">TreasuryComplianceScripts::burn_txn_fees</a></code>


---

<a name="@Script_tiered_mint_37"></a>

#### Script tiered_mint


Mints a specified number of coins in a currency to a Designated Dealer. The sending account
must be the Treasury Compliance account, and coins can only be minted to a Designated Dealer
account.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_tiered_mint">TreasuryComplianceScripts::tiered_mint</a></code>


---

<a name="@Script_freeze_account_38"></a>

#### Script freeze_account


Freezes the account at <code>address</code>. The sending account of this transaction
must be the Treasury Compliance account. The account being frozen cannot be
the Diem Root or Treasury Compliance account. After the successful
execution of this transaction no transactions may be sent from the frozen
account, and the frozen account may not send or receive coins.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_freeze_account">TreasuryComplianceScripts::freeze_account</a></code>


---

<a name="@Script_unfreeze_account_39"></a>

#### Script unfreeze_account


Unfreezes the account at <code>address</code>. The sending account of this transaction must be the
Treasury Compliance account. After the successful execution of this transaction transactions
may be sent from the previously frozen account, and coins may be sent and received.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_unfreeze_account">TreasuryComplianceScripts::unfreeze_account</a></code>


---

<a name="@Script_update_dual_attestation_limit_40"></a>

#### Script update_dual_attestation_limit


Update the dual attestation limit on-chain. Defined in terms of micro-XDX.  The transaction can
only be sent by the Treasury Compliance account.  After this transaction all inter-VASP
payments over this limit must be checked for dual attestation.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">TreasuryComplianceScripts::update_dual_attestation_limit</a></code>


---

<a name="@Script_update_exchange_rate_41"></a>

#### Script update_exchange_rate


Update the rough on-chain exchange rate between a specified currency and XDX (as a conversion
to micro-XDX). The transaction can only be sent by the Treasury Compliance account. After this
transaction the updated exchange rate will be used for normalization of gas prices, and for
dual attestation checking.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_exchange_rate">TreasuryComplianceScripts::update_exchange_rate</a></code>


---

<a name="@Script_update_minting_ability_42"></a>

#### Script update_minting_ability


Script to allow or disallow minting of new coins in a specified currency.  This transaction can
only be sent by the Treasury Compliance account.  Turning minting off for a currency will have
no effect on coins already in circulation, and coins may still be removed from the system.

Script documentation: <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_minting_ability">TreasuryComplianceScripts::update_minting_ability</a></code>



<a name="@System_Administration_43"></a>

### System Administration


---

<a name="@Script_update_diem_version_44"></a>

#### Script update_diem_version


Updates the Diem major version that is stored on-chain and is used by the VM.  This
transaction can only be sent from the Diem Root account.

Script documentation: <code><a href="script_documentation.md#0x1_SystemAdministrationScripts_update_diem_version">SystemAdministrationScripts::update_diem_version</a></code>



---

<a name="@Transaction_Scripts_45"></a>

## Transaction Scripts

---


<a name="@Account_Creation_46"></a>

### Account Creation



<a name="0x1_AccountCreationScripts"></a>

#### Module `0x1::AccountCreationScripts`



<pre><code><b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
</code></pre>



<a name="0x1_AccountCreationScripts_create_child_vasp_account"></a>

##### Function `create_child_vasp_account`


<a name="@Summary_47"></a>

###### Summary

Creates a Child VASP account with its parent being the sending account of the transaction.
The sender of the transaction must be a Parent VASP account.


<a name="@Technical_Description_48"></a>

###### Technical Description

Creates a <code>ChildVASP</code> account for the sender <code>parent_vasp</code> at <code>child_address</code> with a balance of
<code>child_initial_balance</code> in <code>CoinType</code> and an initial authentication key of
<code>auth_key_prefix | child_address</code>. Authentication key prefixes, and how to construct them from an ed25519 public key is described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).

If <code>add_all_currencies</code> is true, the child address will have a zero balance in all available
currencies in the system.

The new account will be a child account of the transaction sender, which must be a
Parent VASP account. The child account will be recorded against the limit of
child accounts of the creating Parent VASP account.


<a name="@Events_49"></a>

###### Events

Successful execution will emit:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>child_address</code>,
and the <code>rold_id</code> field being <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_CHILD_VASP_ROLE_ID">Roles::CHILD_VASP_ROLE_ID</a></code>. This is emitted on the
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.

Successful execution with a <code>child_initial_balance</code> greater than zero will additionaly emit:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a></code> with the <code>payee</code> field being <code>child_address</code>.
This is emitted on the Parent VASP's <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code> handle.
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> with the  <code>payer</code> field being the Parent VASP's address.
This is emitted on the new Child VASPS's <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> handle.


<a name="@Parameters_50"></a>

###### Parameters

| Name                    | Type         | Description                                                                                                                                 |
| ------                  | ------       | -------------                                                                                                                               |
| <code>CoinType</code>              | Type         | The Move type for the <code>CoinType</code> that the child account should be created with. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>parent_vasp</code>           | <code>signer</code>     | The reference of the sending account. Must be a Parent VASP account.                                                                        |
| <code>child_address</code>         | <code>address</code>    | Address of the to-be-created Child VASP account.                                                                                            |
| <code>auth_key_prefix</code>       | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account.                                                    |
| <code>add_all_currencies</code>    | <code>bool</code>       | Whether to publish balance resources for all known currencies when the account is created.                                                  |
| <code>child_initial_balance</code> | <code>u64</code>        | The initial balance in <code>CoinType</code> to give the child account when it's created.                                                              |


<a name="@Common_Abort_Conditions_51"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                                             | Description                                                                              |
| ----------------            | --------------                                           | -------------                                                                            |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>            | The <code>auth_key_prefix</code> was not of length 32.                                              |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EPARENT_VASP">Roles::EPARENT_VASP</a></code>                                    | The sending account wasn't a Parent VASP account.                                        |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                                        | The <code>child_address</code> address is already taken.                                            |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASP.md#0x1_VASP_ETOO_MANY_CHILDREN">VASP::ETOO_MANY_CHILDREN</a></code>                               | The sending account has reached the maximum number of allowed child accounts.            |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                                  | The <code>CoinType</code> is not a registered currency on-chain.                                    |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>     | <code>DiemAccount::EWITHDRAWAL_CAPABILITY_ALREADY_EXTRACTED</code> | The withdrawal capability for the sending account has already been extracted.            |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>              | The sending account doesn't have a balance in <code>CoinType</code>.                                |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>                    | The sending account doesn't have at least <code>child_initial_balance</code> of <code>CoinType</code> balance. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ECANNOT_CREATE_AT_VM_RESERVED">DiemAccount::ECANNOT_CREATE_AT_VM_RESERVED</a></code>            | The <code>child_address</code> is the reserved address 0x0.                                         |


<a name="@Related_Scripts_52"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_child_vasp_account">create_child_vasp_account</a>&lt;CoinType&gt;(parent_vasp: signer, child_address: address, auth_key_prefix: vector&lt;u8&gt;, add_all_currencies: bool, child_initial_balance: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_child_vasp_account">create_child_vasp_account</a>&lt;CoinType&gt;(
    parent_vasp: signer,
    child_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    add_all_currencies: bool,
    child_initial_balance: u64
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_create_child_vasp_account">DiemAccount::create_child_vasp_account</a>&lt;CoinType&gt;(
        &parent_vasp,
        child_address,
        auth_key_prefix,
        add_all_currencies,
    );
    // Give the newly created child `child_initial_balance` coins
    <b>if</b> (child_initial_balance &gt; 0) {
        <b>let</b> vasp_withdrawal_cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&parent_vasp);
        <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_pay_from">DiemAccount::pay_from</a>&lt;CoinType&gt;(
            &vasp_withdrawal_cap, child_address, child_initial_balance, x"", x""
        );
        <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(vasp_withdrawal_cap);
    };
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: parent_vasp};
<b>let</b> parent_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(parent_vasp);
<b>let</b> parent_cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_withdraw_cap">DiemAccount::spec_get_withdraw_cap</a>(parent_addr);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateChildVASPAccountAbortsIf">DiemAccount::CreateChildVASPAccountAbortsIf</a>&lt;CoinType&gt;{
    parent: parent_vasp, new_account_address: child_address};
<b>aborts_if</b> child_initial_balance &gt; max_u64() <b>with</b> <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
<b>include</b> (child_initial_balance &gt; 0) ==&gt;
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractWithdrawCapAbortsIf">DiemAccount::ExtractWithdrawCapAbortsIf</a>{sender_addr: parent_addr};
<b>include</b> (child_initial_balance &gt; 0) ==&gt; <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_AssertPaymentOkAbortsIf">DualAttestation::AssertPaymentOkAbortsIf</a>&lt;CoinType&gt;{
    payer: parent_addr,
    payee: child_address,
    metadata: x"",
    metadata_signature: x"",
    value: child_initial_balance
};
<b>include</b> (child_initial_balance) &gt; 0 ==&gt;
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_PayFromAbortsIfRestricted">DiemAccount::PayFromAbortsIfRestricted</a>&lt;CoinType&gt;{
        cap: parent_cap,
        payee: child_address,
        amount: child_initial_balance,
        metadata: x"",
    };
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateChildVASPAccountEnsures">DiemAccount::CreateChildVASPAccountEnsures</a>&lt;CoinType&gt;{
    parent_addr: parent_addr,
    child_addr: child_address,
};
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;CoinType&gt;(child_address) == child_initial_balance;
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;CoinType&gt;(parent_addr)
    == <b>old</b>(<a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;CoinType&gt;(parent_addr)) - child_initial_balance;
<b>aborts_with</b> [check]
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>


**Access Control:**
Only Parent VASP accounts can create Child VASP accounts [[A7]][ROLE].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotParentVasp">Roles::AbortsIfNotParentVasp</a>{account: parent_vasp};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_validator_operator_account"></a>

##### Function `create_validator_operator_account`


<a name="@Summary_53"></a>

###### Summary

Creates a Validator Operator account. This transaction can only be sent by the Diem
Root account.


<a name="@Technical_Description_54"></a>

###### Technical Description

Creates an account with a Validator Operator role at <code>new_account_address</code>, with authentication key
<code>auth_key_prefix</code> | <code>new_account_address</code>. It publishes a
<code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource with the specified <code>human_name</code>.
This script does not assign the validator operator to any validator accounts but only creates the account.
Authentication key prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).


<a name="@Events_55"></a>

###### Events

Successful execution will emit:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>new_account_address</code>,
and the <code>rold_id</code> field being <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_VALIDATOR_OPERATOR_ROLE_ID">Roles::VALIDATOR_OPERATOR_ROLE_ID</a></code>. This is emitted on the
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_56"></a>

###### Parameters

| Name                  | Type         | Description                                                                              |
| ------                | ------       | -------------                                                                            |
| <code>dr_account</code>          | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Diem Root signer.     |
| <code>sliding_nonce</code>       | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.               |
| <code>new_account_address</code> | <code>address</code>    | Address of the to-be-created Validator account.                                          |
| <code>auth_key_prefix</code>     | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account. |
| <code>human_name</code>          | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the validator.                                              |


<a name="@Common_Abort_Conditions_57"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>            | The sending account is not the Diem Root account.                                         |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EDIEM_ROOT">Roles::EDIEM_ROOT</a></code>                    | The sending account is not the Diem Root account.                                         |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>new_account_address</code> address is already taken.                                        |


<a name="@Related_Scripts_58"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">create_validator_operator_account</a>(dr_account: signer, sliding_nonce: u64, new_account_address: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">create_validator_operator_account</a>(
    dr_account: signer,
    sliding_nonce: u64,
    new_account_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_create_validator_operator_account">DiemAccount::create_validator_operator_account</a>(
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
* REQUIRES_ROLE comes from <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a></code>. However, assert_diem_root checks the literal
Diem root address before checking the role, and the role abort is unreachable in practice, since
only Diem root has the Diem root role.


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{seq_nonce: sliding_nonce, account: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateValidatorOperatorAccountAbortsIf">DiemAccount::CreateValidatorOperatorAccountAbortsIf</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateValidatorOperatorAccountEnsures">DiemAccount::CreateValidatorOperatorAccountEnsures</a>;
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can create Validator Operator accounts [[A4]][ROLE].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_validator_account"></a>

##### Function `create_validator_account`


<a name="@Summary_59"></a>

###### Summary

Creates a Validator account. This transaction can only be sent by the Diem
Root account.


<a name="@Technical_Description_60"></a>

###### Technical Description

Creates an account with a Validator role at <code>new_account_address</code>, with authentication key
<code>auth_key_prefix</code> | <code>new_account_address</code>. It publishes a
<code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource with empty <code>config</code>, and
<code>operator_account</code> fields. The <code>human_name</code> field of the
<code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> is set to the passed in <code>human_name</code>.
This script does not add the validator to the validator set or the system,
but only creates the account.
Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).


<a name="@Events_61"></a>

###### Events

Successful execution will emit:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>new_account_address</code>,
and the <code>rold_id</code> field being <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_VALIDATOR_ROLE_ID">Roles::VALIDATOR_ROLE_ID</a></code>. This is emitted on the
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_62"></a>

###### Parameters

| Name                  | Type         | Description                                                                              |
| ------                | ------       | -------------                                                                            |
| <code>dr_account</code>          | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Diem Root signer.     |
| <code>sliding_nonce</code>       | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.               |
| <code>new_account_address</code> | <code>address</code>    | Address of the to-be-created Validator account.                                          |
| <code>auth_key_prefix</code>     | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account. |
| <code>human_name</code>          | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the validator.                                              |


<a name="@Common_Abort_Conditions_63"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>            | The sending account is not the Diem Root account.                                         |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EDIEM_ROOT">Roles::EDIEM_ROOT</a></code>                    | The sending account is not the Diem Root account.                                         |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>new_account_address</code> address is already taken.                                        |


<a name="@Related_Scripts_64"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">create_validator_account</a>(dr_account: signer, sliding_nonce: u64, new_account_address: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">create_validator_account</a>(
    dr_account: signer,
    sliding_nonce: u64,
    new_account_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_create_validator_account">DiemAccount::create_validator_account</a>(
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
* REQUIRES_ROLE comes from <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_assert_diem_root">Roles::assert_diem_root</a></code>. However, assert_diem_root checks the literal
Diem root address before checking the role, and the role abort is unreachable in practice, since
only Diem root has the Diem root role.


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{seq_nonce: sliding_nonce, account: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateValidatorAccountAbortsIf">DiemAccount::CreateValidatorAccountAbortsIf</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateValidatorAccountEnsures">DiemAccount::CreateValidatorAccountEnsures</a>;
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can create Validator accounts [[A3]][ROLE].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_parent_vasp_account"></a>

##### Function `create_parent_vasp_account`


<a name="@Summary_65"></a>

###### Summary

Creates a Parent VASP account with the specified human name. Must be called by the Treasury Compliance account.


<a name="@Technical_Description_66"></a>

###### Technical Description

Creates an account with the Parent VASP role at <code>address</code> with authentication key
<code>auth_key_prefix</code> | <code>new_account_address</code> and a 0 balance of type <code>CoinType</code>. If
<code>add_all_currencies</code> is true, 0 balances for all available currencies in the system will
also be added. This can only be invoked by an TreasuryCompliance account.
<code>sliding_nonce</code> is a unique nonce for operation, see <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> for details.
Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).


<a name="@Events_67"></a>

###### Events

Successful execution will emit:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>new_account_address</code>,
and the <code>rold_id</code> field being <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_PARENT_VASP_ROLE_ID">Roles::PARENT_VASP_ROLE_ID</a></code>. This is emitted on the
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_68"></a>

###### Parameters

| Name                  | Type         | Description                                                                                                                                                    |
| ------                | ------       | -------------                                                                                                                                                  |
| <code>CoinType</code>            | Type         | The Move type for the <code>CoinType</code> currency that the Parent VASP account should be initialized with. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>          | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                                |
| <code>sliding_nonce</code>       | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                                                                     |
| <code>new_account_address</code> | <code>address</code>    | Address of the to-be-created Parent VASP account.                                                                                                              |
| <code>auth_key_prefix</code>     | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account.                                                                       |
| <code>human_name</code>          | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the Parent VASP.                                                                                                                  |
| <code>add_all_currencies</code>  | <code>bool</code>       | Whether to publish balance resources for all known currencies when the account is created.                                                                     |


<a name="@Common_Abort_Conditions_69"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | The sending account is not the Treasury Compliance account.                                |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>           | The sending account is not the Treasury Compliance account.                                |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                 | The <code>CoinType</code> is not a registered currency on-chain.                                      |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>new_account_address</code> address is already taken.                                        |


<a name="@Related_Scripts_70"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">create_parent_vasp_account</a>&lt;CoinType&gt;(tc_account: signer, sliding_nonce: u64, new_account_address: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;, add_all_currencies: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">create_parent_vasp_account</a>&lt;CoinType&gt;(
    tc_account: signer,
    sliding_nonce: u64,
    new_account_address: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;,
    add_all_currencies: bool
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_create_parent_vasp_account">DiemAccount::create_parent_vasp_account</a>&lt;CoinType&gt;(
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



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{account: tc_account, seq_nonce: sliding_nonce};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateParentVASPAccountAbortsIf">DiemAccount::CreateParentVASPAccountAbortsIf</a>&lt;CoinType&gt;{creator_account: tc_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateParentVASPAccountEnsures">DiemAccount::CreateParentVASPAccountEnsures</a>&lt;CoinType&gt;;
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>;
</code></pre>


**Access Control:**
Only the Treasury Compliance account can create Parent VASP accounts [[A6]][ROLE].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>

<a name="0x1_AccountCreationScripts_create_designated_dealer"></a>

##### Function `create_designated_dealer`


<a name="@Summary_71"></a>

###### Summary

Creates a Designated Dealer account with the provided information, and initializes it with
default mint tiers. The transaction can only be sent by the Treasury Compliance account.


<a name="@Technical_Description_72"></a>

###### Technical Description

Creates an account with the Designated Dealer role at <code>addr</code> with authentication key
<code>auth_key_prefix</code> | <code>addr</code> and a 0 balance of type <code>Currency</code>. If <code>add_all_currencies</code> is true,
0 balances for all available currencies in the system will also be added. This can only be
invoked by an account with the TreasuryCompliance role.
Authentication keys, prefixes, and how to construct them from an ed25519 public key are described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).

At the time of creation the account is also initialized with default mint tiers of (500_000,
5000_000, 50_000_000, 500_000_000), and preburn areas for each currency that is added to the
account.


<a name="@Events_73"></a>

###### Events

Successful execution will emit:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateAccountEvent">DiemAccount::CreateAccountEvent</a></code> with the <code>created</code> field being <code>addr</code>,
and the <code>rold_id</code> field being <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_DESIGNATED_DEALER_ROLE_ID">Roles::DESIGNATED_DEALER_ROLE_ID</a></code>. This is emitted on the
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AccountOperationsCapability">DiemAccount::AccountOperationsCapability</a></code> <code>creation_events</code> handle.


<a name="@Parameters_74"></a>

###### Parameters

| Name                 | Type         | Description                                                                                                                                         |
| ------               | ------       | -------------                                                                                                                                       |
| <code>Currency</code>           | Type         | The Move type for the <code>Currency</code> that the Designated Dealer should be initialized with. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>         | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                     |
| <code>sliding_nonce</code>      | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                                                          |
| <code>addr</code>               | <code>address</code>    | Address of the to-be-created Designated Dealer account.                                                                                             |
| <code>auth_key_prefix</code>    | <code>vector&lt;u8&gt;</code> | The authentication key prefix that will be used initially for the newly created account.                                                            |
| <code>human_name</code>         | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the Designated Dealer.                                                                                                 |
| <code>add_all_currencies</code> | <code>bool</code>       | Whether to publish preburn, balance, and tier info resources for all known (SCS) currencies or just <code>Currency</code> when the account is created.         |



<a name="@Common_Abort_Conditions_75"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                            | Description                                                                                |
| ----------------            | --------------                          | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | The sending account is not the Treasury Compliance account.                                |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>           | The sending account is not the Treasury Compliance account.                                |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                 | The <code>Currency</code> is not a registered currency on-chain.                                      |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                       | The <code>addr</code> address is already taken.                                                       |


<a name="@Related_Scripts_76"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_tiered_mint">TreasuryComplianceScripts::tiered_mint</a></code>
* <code><a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_designated_dealer">create_designated_dealer</a>&lt;Currency&gt;(tc_account: signer, sliding_nonce: u64, addr: address, auth_key_prefix: vector&lt;u8&gt;, human_name: vector&lt;u8&gt;, add_all_currencies: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountCreationScripts_create_designated_dealer">create_designated_dealer</a>&lt;Currency&gt;(
    tc_account: signer,
    sliding_nonce: u64,
    addr: address,
    auth_key_prefix: vector&lt;u8&gt;,
    human_name: vector&lt;u8&gt;,
    add_all_currencies: bool,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_create_designated_dealer">DiemAccount::create_designated_dealer</a>&lt;Currency&gt;(
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



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{account: tc_account, seq_nonce: sliding_nonce};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateDesignatedDealerAbortsIf">DiemAccount::CreateDesignatedDealerAbortsIf</a>&lt;Currency&gt;{
    creator_account: tc_account, new_account_address: addr};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CreateDesignatedDealerEnsures">DiemAccount::CreateDesignatedDealerEnsures</a>&lt;Currency&gt;{new_account_address: addr};
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_MakeAccountEmits">DiemAccount::MakeAccountEmits</a>{new_account_address: addr};
</code></pre>


**Access Control:**
Only the Treasury Compliance account can create Designated Dealer accounts [[A5]][ROLE].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>


---

<a name="@Account_Administration_77"></a>

### Account Administration



<a name="0x1_AccountAdministrationScripts"></a>

#### Module `0x1::AccountAdministrationScripts`

This module holds transactions that can be used to administer accounts in the Diem Framework.


<pre><code><b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation">0x1::DualAttestation</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress">0x1::RecoveryAddress</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey">0x1::SharedEd25519PublicKey</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain">0x1::VASPDomain</a>;
</code></pre>



<a name="0x1_AccountAdministrationScripts_add_currency_to_account"></a>

##### Function `add_currency_to_account`


<a name="@Summary_78"></a>

###### Summary

Adds a zero <code>Currency</code> balance to the sending <code>account</code>. This will enable <code>account</code> to
send, receive, and hold <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Diem">Diem::Diem</a>&lt;Currency&gt;</code> coins. This transaction can be
successfully sent by any account that is allowed to hold balances
(e.g., VASP, Designated Dealer).


<a name="@Technical_Description_79"></a>

###### Technical Description

After the successful execution of this transaction the sending account will have a
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;</code> resource with zero balance published under it. Only
accounts that can hold balances can send this transaction, the sending account cannot
already have a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;</code> published under it.


<a name="@Parameters_80"></a>

###### Parameters

| Name       | Type     | Description                                                                                                                                         |
| ------     | ------   | -------------                                                                                                                                       |
| <code>Currency</code> | Type     | The Move type for the <code>Currency</code> being added to the sending account of the transaction. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>account</code>  | <code>signer</code> | The signer of the sending account of the transaction.                                                                                               |


<a name="@Common_Abort_Conditions_81"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                             | Description                                                                |
| ----------------            | --------------                           | -------------                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                  | The <code>Currency</code> is not a registered currency on-chain.                      |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EROLE_CANT_STORE_BALANCE">DiemAccount::EROLE_CANT_STORE_BALANCE</a></code> | The sending <code>account</code>'s role does not permit balances.                     |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EADD_EXISTING_CURRENCY">DiemAccount::EADD_EXISTING_CURRENCY</a></code>   | A balance for <code>Currency</code> is already published under the sending <code>account</code>. |


<a name="@Related_Scripts_82"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_add_currency_to_account">add_currency_to_account</a>&lt;Currency&gt;(account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_add_currency_to_account">add_currency_to_account</a>&lt;Currency&gt;(account: signer) {
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_add_currency">DiemAccount::add_currency</a>&lt;Currency&gt;(&account);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AddCurrencyAbortsIf">DiemAccount::AddCurrencyAbortsIf</a>&lt;Currency&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AddCurrencyEnsures">DiemAccount::AddCurrencyEnsures</a>&lt;Currency&gt;{addr: <a href="_spec_address_of">Signer::spec_address_of</a>(account)};
<b>aborts_with</b> [check]
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
</code></pre>


**Access Control:**
The account must be allowed to hold balances. Only Designated Dealers, Parent VASPs,
and Child VASPs can hold balances [[D1]][ROLE][[D2]][ROLE][[D3]][ROLE][[D4]][ROLE][[D5]][ROLE][[D6]][ROLE][[D7]][ROLE].


<pre><code><b>aborts_if</b> !<a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_can_hold_balance">Roles::can_hold_balance</a>(account) <b>with</b> <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_add_recovery_rotation_capability"></a>

##### Function `add_recovery_rotation_capability`


<a name="@Summary_83"></a>

###### Summary

Stores the sending accounts ability to rotate its authentication key with a designated recovery
account. Both the sending and recovery accounts need to belong to the same VASP and
both be VASP accounts. After this transaction both the sending account and the
specified recovery account can rotate the sender account's authentication key.


<a name="@Technical_Description_84"></a>

###### Technical Description

Adds the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> for the sending account
(<code>to_recover_account</code>) to the <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource under
<code>recovery_address</code>. After this transaction has been executed successfully the account at
<code>recovery_address</code> and the <code>to_recover_account</code> may rotate the authentication key of
<code>to_recover_account</code> (the sender of this transaction).

The sending account of this transaction (<code>to_recover_account</code>) must not have previously given away its unique key
rotation capability, and must be a VASP account. The account at <code>recovery_address</code>
must also be a VASP account belonging to the same VASP as the <code>to_recover_account</code>.
Additionally the account at <code>recovery_address</code> must have already initialized itself as
a recovery account address using the <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code> transaction script.

The sending account's (<code>to_recover_account</code>) key rotation capability is
removed in this transaction and stored in the <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code>
resource stored under the account at <code>recovery_address</code>.


<a name="@Parameters_85"></a>

###### Parameters

| Name                 | Type      | Description                                                                                               |
| ------               | ------    | -------------                                                                                             |
| <code>to_recover_account</code> | <code>signer</code>  | The signer of the sending account of this transaction.                                                    |
| <code>recovery_address</code>   | <code>address</code> | The account address where the <code>to_recover_account</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> will be stored. |


<a name="@Common_Abort_Conditions_86"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                              | Description                                                                                       |
| ----------------           | --------------                                            | -------------                                                                                     |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>to_recover_account</code> has already delegated/extracted its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.    |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_ERECOVERY_ADDRESS">RecoveryAddress::ERECOVERY_ADDRESS</a></code>                      | <code>recovery_address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress">RecoveryAddress</a></code> resource published under it.                 |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_EINVALID_KEY_ROTATION_DELEGATION">RecoveryAddress::EINVALID_KEY_ROTATION_DELEGATION</a></code>       | <code>to_recover_account</code> and <code>recovery_address</code> do not belong to the same VASP.                       |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_EMAX_KEYS_REGISTERED">RecoveryAddress::EMAX_KEYS_REGISTERED</a></code>                  | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_MAX_REGISTERED_KEYS">RecoveryAddress::MAX_REGISTERED_KEYS</a></code> have already been registered with this <code>recovery_address</code>. |


<a name="@Related_Scripts_87"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_create_recovery_address">AccountAdministrationScripts::create_recovery_address</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">add_recovery_rotation_capability</a>(to_recover_account: signer, recovery_address: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">add_recovery_rotation_capability</a>(to_recover_account: signer, recovery_address: address) {
    <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_add_rotation_capability">RecoveryAddress::add_rotation_capability</a>(
        <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&to_recover_account), recovery_address
    )
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: to_recover_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>{account: to_recover_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityEnsures">DiemAccount::ExtractKeyRotationCapabilityEnsures</a>{account: to_recover_account};
<b>let</b> addr = <a href="_spec_address_of">Signer::spec_address_of</a>(to_recover_account);
<b>let</b> rotation_cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(addr);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_AddRotationCapabilityAbortsIf">RecoveryAddress::AddRotationCapabilityAbortsIf</a>{
    to_recover: rotation_cap
};
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(recovery_address)[
    len(<a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(recovery_address)) - 1] == rotation_cap;
<b>aborts_with</b> [check]
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key"></a>

##### Function `publish_shared_ed25519_public_key`


<a name="@Summary_88"></a>

###### Summary

Rotates the authentication key of the sending account to the newly-specified ed25519 public key and
publishes a new shared authentication key derived from that public key under the sender's account.
Any account can send this transaction.


<a name="@Technical_Description_89"></a>

###### Technical Description

Rotates the authentication key of the sending account to the
[authentication key derived from <code>public_key</code>](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys)
and publishes a <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource
containing the 32-byte ed25519 <code>public_key</code> and the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> for
<code>account</code> under <code>account</code>.


<a name="@Parameters_90"></a>

###### Parameters

| Name         | Type         | Description                                                                                        |
| ------       | ------       | -------------                                                                                      |
| <code>account</code>    | <code>signer</code>     | The signer of the sending account of the transaction.                                              |
| <code>public_key</code> | <code>vector&lt;u8&gt;</code> | A valid 32-byte Ed25519 public key for <code>account</code>'s authentication key to be rotated to and stored. |


<a name="@Common_Abort_Conditions_91"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                                               | Description                                                                                         |
| ----------------            | --------------                                             | -------------                                                                                       |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> resource.       |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_ESHARED_KEY">SharedEd25519PublicKey::ESHARED_KEY</a></code>                      | The <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource is already published under <code>account</code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_EMALFORMED_PUBLIC_KEY">SharedEd25519PublicKey::EMALFORMED_PUBLIC_KEY</a></code>            | <code>public_key</code> is an invalid ed25519 public key.                                                      |


<a name="@Related_Scripts_92"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key">AccountAdministrationScripts::rotate_shared_ed25519_public_key</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">publish_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">publish_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_publish">SharedEd25519PublicKey::publish</a>(&account, public_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_PublishAbortsIf">SharedEd25519PublicKey::PublishAbortsIf</a>{key: public_key};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_PublishEnsures">SharedEd25519PublicKey::PublishEnsures</a>{key: public_key};
<b>aborts_with</b> [check]
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key"></a>

##### Function `rotate_authentication_key`


<a name="@Summary_93"></a>

###### Summary

Rotates the <code>account</code>'s authentication key to the supplied new authentication key. May be sent by any account.


<a name="@Technical_Description_94"></a>

###### Technical Description

Rotate the <code>account</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>authentication_key</code>
field to <code>new_key</code>. <code>new_key</code> must be a valid authentication key that
corresponds to an ed25519 public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
and <code>account</code> must not have previously delegated its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_95"></a>

###### Parameters

| Name      | Type         | Description                                       |
| ------    | ------       | -------------                                     |
| <code>account</code> | <code>signer</code>     | Signer of the sending account of the transaction. |
| <code>new_key</code> | <code>vector&lt;u8&gt;</code> | New authentication key to be used for <code>account</code>.  |


<a name="@Common_Abort_Conditions_96"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                              | Description                                                                         |
| ----------------           | --------------                                            | -------------                                                                       |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>              | <code>new_key</code> was an invalid length.                                                    |


<a name="@Related_Scripts_97"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">AccountAdministrationScripts::rotate_authentication_key_with_nonce</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">rotate_authentication_key</a>(account: signer, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">rotate_authentication_key</a>(account: signer, new_key: vector&lt;u8&gt;) {
    <b>let</b> key_rotation_capability = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_rotate_authentication_key">DiemAccount::rotate_authentication_key</a>(&key_rotation_capability, new_key);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_restore_key_rotation_capability">DiemAccount::restore_key_rotation_capability</a>(key_rotation_capability);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>let</b> key_rotation_capability = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyAbortsIf">DiemAccount::RotateAuthenticationKeyAbortsIf</a>{cap: key_rotation_capability, new_authentication_key: new_key};
</code></pre>


This rotates the authentication key of <code>account</code> to <code>new_key</code>


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyEnsures">DiemAccount::RotateAuthenticationKeyEnsures</a>{addr: account_addr, new_authentication_key: new_key};
<b>aborts_with</b> [check]
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>


**Access Control:**
The account can rotate its own authentication key unless
it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AbortsIfDelegatedKeyRotationCapability">DiemAccount::AbortsIfDelegatedKeyRotationCapability</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce"></a>

##### Function `rotate_authentication_key_with_nonce`


<a name="@Summary_98"></a>

###### Summary

Rotates the sender's authentication key to the supplied new authentication key. May be sent by
any account that has a sliding nonce resource published under it (usually this is Treasury
Compliance or Diem Root accounts).


<a name="@Technical_Description_99"></a>

###### Technical Description

Rotates the <code>account</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>authentication_key</code>
field to <code>new_key</code>. <code>new_key</code> must be a valid authentication key that
corresponds to an ed25519 public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
and <code>account</code> must not have previously delegated its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_100"></a>

###### Parameters

| Name            | Type         | Description                                                                |
| ------          | ------       | -------------                                                              |
| <code>account</code>       | <code>signer</code>     | Signer of the sending account of the transaction.                          |
| <code>sliding_nonce</code> | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction. |
| <code>new_key</code>       | <code>vector&lt;u8&gt;</code> | New authentication key to be used for <code>account</code>.                           |


<a name="@Common_Abort_Conditions_101"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                               | Description                                                                                |
| ----------------           | --------------                                             | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                             | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                             | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                             | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>                    | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.       |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>              | <code>new_key</code> was an invalid length.                                                           |


<a name="@Related_Scripts_102"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">rotate_authentication_key_with_nonce</a>(account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">rotate_authentication_key_with_nonce</a>(account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <b>let</b> key_rotation_capability = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_rotate_authentication_key">DiemAccount::rotate_authentication_key</a>(&key_rotation_capability, new_key);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_restore_key_rotation_capability">DiemAccount::restore_key_rotation_capability</a>(key_rotation_capability);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ seq_nonce: sliding_nonce };
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>let</b> key_rotation_capability = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyAbortsIf">DiemAccount::RotateAuthenticationKeyAbortsIf</a>{cap: key_rotation_capability, new_authentication_key: new_key};
</code></pre>


This rotates the authentication key of <code>account</code> to <code>new_key</code>


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyEnsures">DiemAccount::RotateAuthenticationKeyEnsures</a>{addr: account_addr, new_authentication_key: new_key};
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
</code></pre>


**Access Control:**
The account can rotate its own authentication key unless
it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AbortsIfDelegatedKeyRotationCapability">DiemAccount::AbortsIfDelegatedKeyRotationCapability</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin"></a>

##### Function `rotate_authentication_key_with_nonce_admin`


<a name="@Summary_103"></a>

###### Summary

Rotates the specified account's authentication key to the supplied new authentication key. May
only be sent by the Diem Root account as a write set transaction.


<a name="@Technical_Description_104"></a>

###### Technical Description

Rotate the <code>account</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>authentication_key</code> field to <code>new_key</code>.
<code>new_key</code> must be a valid authentication key that corresponds to an ed25519
public key as described [here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys),
and <code>account</code> must not have previously delegated its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_105"></a>

###### Parameters

| Name            | Type         | Description                                                                                       |
| ------          | ------       | -------------                                                                                     |
| <code>dr_account</code>    | <code>signer</code>     | The signer of the sending account of the write set transaction. May only be the Diem Root signer. |
| <code>account</code>       | <code>signer</code>     | Signer of account specified in the <code>execute_as</code> field of the write set transaction.               |
| <code>sliding_nonce</code> | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction for Diem Root.          |
| <code>new_key</code>       | <code>vector&lt;u8&gt;</code> | New authentication key to be used for <code>account</code>.                                                  |


<a name="@Common_Abort_Conditions_106"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                              | Description                                                                                                |
| ----------------           | --------------                                            | -------------                                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                            | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                            | The <code>sliding_nonce</code> in <code>dr_account</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                            | The <code>sliding_nonce</code> in <code>dr_account</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>                   | The <code>sliding_nonce</code> in<code> dr_account</code> has been previously recorded.                                          |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.                        |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code>              | <code>new_key</code> was an invalid length.                                                                           |


<a name="@Related_Scripts_107"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">AccountAdministrationScripts::rotate_authentication_key_with_nonce</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">AccountAdministrationScripts::rotate_authentication_key_with_recovery_address</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">rotate_authentication_key_with_nonce_admin</a>(dr_account: signer, account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">rotate_authentication_key_with_nonce_admin</a>(dr_account: signer, account: signer, sliding_nonce: u64, new_key: vector&lt;u8&gt;) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <b>let</b> key_rotation_capability = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_rotate_authentication_key">DiemAccount::rotate_authentication_key</a>(&key_rotation_capability, new_key);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_restore_key_rotation_capability">DiemAccount::restore_key_rotation_capability</a>(key_rotation_capability);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ account: dr_account, seq_nonce: sliding_nonce };
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>let</b> key_rotation_capability = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyAbortsIf">DiemAccount::RotateAuthenticationKeyAbortsIf</a>{cap: key_rotation_capability, new_authentication_key: new_key};
</code></pre>


This rotates the authentication key of <code>account</code> to <code>new_key</code>


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_RotateAuthenticationKeyEnsures">DiemAccount::RotateAuthenticationKeyEnsures</a>{addr: account_addr, new_authentication_key: new_key};
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can process the admin scripts [[H9]][PERMISSION].


<pre><code><b>requires</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_has_diem_root_role">Roles::has_diem_root_role</a>(dr_account);
</code></pre>


This is ensured by DiemAccount::writeset_prologue.
The account can rotate its own authentication key unless
it has delegrated the capability [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_AbortsIfDelegatedKeyRotationCapability">DiemAccount::AbortsIfDelegatedKeyRotationCapability</a>{account: account};
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address"></a>

##### Function `rotate_authentication_key_with_recovery_address`


<a name="@Summary_108"></a>

###### Summary

Rotates the authentication key of a specified account that is part of a recovery address to a
new authentication key. Only used for accounts that are part of a recovery address (see
<code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_recovery_rotation_capability">AccountAdministrationScripts::add_recovery_rotation_capability</a></code> for account restrictions).


<a name="@Technical_Description_109"></a>

###### Technical Description

Rotates the authentication key of the <code>to_recover</code> account to <code>new_key</code> using the
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> stored in the <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource
published under <code>recovery_address</code>. <code>new_key</code> must be a valide authentication key as described
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys).
This transaction can be sent either by the <code>to_recover</code> account, or by the account where the
<code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource is published that contains <code>to_recover</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.


<a name="@Parameters_110"></a>

###### Parameters

| Name               | Type         | Description                                                                                                                   |
| ------             | ------       | -------------                                                                                                                 |
| <code>account</code>          | <code>signer</code>     | Signer of the sending account of the transaction.                                                                             |
| <code>recovery_address</code> | <code>address</code>    | Address where <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> that holds <code>to_recover</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> is published. |
| <code>to_recover</code>       | <code>address</code>    | The address of the account whose authentication key will be updated.                                                          |
| <code>new_key</code>          | <code>vector&lt;u8&gt;</code> | New authentication key to be used for the account at the <code>to_recover</code> address.                                                |


<a name="@Common_Abort_Conditions_111"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                 | Description                                                                                                                                         |
| ----------------           | --------------                               | -------------                                                                                                                                       |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_ERECOVERY_ADDRESS">RecoveryAddress::ERECOVERY_ADDRESS</a></code>         | <code>recovery_address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource published under it.                                                  |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_ECANNOT_ROTATE_KEY">RecoveryAddress::ECANNOT_ROTATE_KEY</a></code>        | The address of <code>account</code> is not <code>recovery_address</code> or <code>to_recover</code>.                                                                                 |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_EACCOUNT_NOT_RECOVERABLE">RecoveryAddress::EACCOUNT_NOT_RECOVERABLE</a></code>  | <code>to_recover</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>  is not in the <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code>  resource published under <code>recovery_address</code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EMALFORMED_AUTHENTICATION_KEY">DiemAccount::EMALFORMED_AUTHENTICATION_KEY</a></code> | <code>new_key</code> was an invalid length.                                                                                                                    |


<a name="@Related_Scripts_112"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key">AccountAdministrationScripts::rotate_authentication_key</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce">AccountAdministrationScripts::rotate_authentication_key_with_nonce</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_nonce_admin">AccountAdministrationScripts::rotate_authentication_key_with_nonce_admin</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">rotate_authentication_key_with_recovery_address</a>(account: signer, recovery_address: address, to_recover: address, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_authentication_key_with_recovery_address">rotate_authentication_key_with_recovery_address</a>(
        account: signer,
        recovery_address: address,
        to_recover: address,
        new_key: vector&lt;u8&gt;
        ) {
    <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_rotate_authentication_key">RecoveryAddress::rotate_authentication_key</a>(&account, recovery_address, to_recover, new_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RotateAuthenticationKeyAbortsIf">RecoveryAddress::RotateAuthenticationKeyAbortsIf</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RotateAuthenticationKeyEnsures">RecoveryAddress::RotateAuthenticationKeyEnsures</a>;
<b>aborts_with</b> [check]
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>


**Access Control:**
The delegatee at the recovery address has to hold the key rotation capability for
the address to recover. The address of the transaction signer has to be either
the delegatee's address or the address to recover [[H18]][PERMISSION][[J18]][PERMISSION].


<pre><code><b>let</b> account_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(account);
<b>aborts_if</b> !<a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_spec_holds_key_rotation_cap_for">RecoveryAddress::spec_holds_key_rotation_cap_for</a>(recovery_address, to_recover) <b>with</b> <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
<b>aborts_if</b> !(account_addr == recovery_address || account_addr == to_recover) <b>with</b> <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_dual_attestation_info"></a>

##### Function `rotate_dual_attestation_info`


<a name="@Summary_113"></a>

###### Summary

Updates the url used for off-chain communication, and the public key used to verify dual
attestation on-chain. Transaction can be sent by any account that has dual attestation
information published under it. In practice the only such accounts are Designated Dealers and
Parent VASPs.


<a name="@Technical_Description_114"></a>

###### Technical Description

Updates the <code>base_url</code> and <code>compliance_public_key</code> fields of the <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code>
resource published under <code>account</code>. The <code>new_key</code> must be a valid ed25519 public key.


<a name="@Events_115"></a>

###### Events

Successful execution of this transaction emits two events:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_ComplianceKeyRotationEvent">DualAttestation::ComplianceKeyRotationEvent</a></code> containing the new compliance public key, and
the blockchain time at which the key was updated emitted on the <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code>
<code>compliance_key_rotation_events</code> handle published under <code>account</code>; and
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_BaseUrlRotationEvent">DualAttestation::BaseUrlRotationEvent</a></code> containing the new base url to be used for
off-chain communication, and the blockchain time at which the url was updated emitted on the
<code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code> <code>base_url_rotation_events</code> handle published under <code>account</code>.


<a name="@Parameters_116"></a>

###### Parameters

| Name      | Type         | Description                                                               |
| ------    | ------       | -------------                                                             |
| <code>account</code> | <code>signer</code>     | Signer of the sending account of the transaction.                         |
| <code>new_url</code> | <code>vector&lt;u8&gt;</code> | ASCII-encoded url to be used for off-chain communication with <code>account</code>.  |
| <code>new_key</code> | <code>vector&lt;u8&gt;</code> | New ed25519 public key to be used for on-chain dual attestation checking. |


<a name="@Common_Abort_Conditions_117"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                           | Description                                                                |
| ----------------           | --------------                         | -------------                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_ECREDENTIAL">DualAttestation::ECREDENTIAL</a></code>         | A <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code> resource is not published under <code>account</code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_EINVALID_PUBLIC_KEY">DualAttestation::EINVALID_PUBLIC_KEY</a></code> | <code>new_key</code> is not a valid ed25519 public key.                               |


<a name="@Related_Scripts_118"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_designated_dealer">AccountCreationScripts::create_designated_dealer</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">rotate_dual_attestation_info</a>(account: signer, new_url: vector&lt;u8&gt;, new_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">rotate_dual_attestation_info</a>(account: signer, new_url: vector&lt;u8&gt;, new_key: vector&lt;u8&gt;) {
    <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_rotate_base_url">DualAttestation::rotate_base_url</a>(&account, new_url);
    <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_rotate_compliance_public_key">DualAttestation::rotate_compliance_public_key</a>(&account, new_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_RotateBaseUrlAbortsIf">DualAttestation::RotateBaseUrlAbortsIf</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_RotateBaseUrlEnsures">DualAttestation::RotateBaseUrlEnsures</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_RotateCompliancePublicKeyAbortsIf">DualAttestation::RotateCompliancePublicKeyAbortsIf</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_RotateCompliancePublicKeyEnsures">DualAttestation::RotateCompliancePublicKeyEnsures</a>;
<b>aborts_with</b> [check]
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_RotateBaseUrlEmits">DualAttestation::RotateBaseUrlEmits</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_RotateCompliancePublicKeyEmits">DualAttestation::RotateCompliancePublicKeyEmits</a>;
</code></pre>


**Access Control:**
Only the account having Credential can rotate the info.
Credential is granted to either a Parent VASP or a designated dealer [[H17]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_AbortsIfNoCredential">DualAttestation::AbortsIfNoCredential</a>{addr: <a href="_spec_address_of">Signer::spec_address_of</a>(account)};
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key"></a>

##### Function `rotate_shared_ed25519_public_key`


<a name="@Summary_119"></a>

###### Summary

Rotates the authentication key in a <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey">SharedEd25519PublicKey</a></code>. This transaction can be sent by
any account that has previously published a shared ed25519 public key using
<code><a href="script_documentation.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">AccountAdministrationScripts::publish_shared_ed25519_public_key</a></code>.


<a name="@Technical_Description_120"></a>

###### Technical Description

<code>public_key</code> must be a valid ed25519 public key.  This transaction first rotates the public key stored in <code>account</code>'s
<code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource to <code>public_key</code>, after which it
rotates the <code>account</code>'s authentication key to the new authentication key derived from <code>public_key</code> as defined
[here](https://developers.diem.com/docs/core/accounts/#addresses-authentication-keys-and-cryptographic-keys)
using the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> stored in <code>account</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code>.


<a name="@Parameters_121"></a>

###### Parameters

| Name         | Type         | Description                                           |
| ------       | ------       | -------------                                         |
| <code>account</code>    | <code>signer</code>     | The signer of the sending account of the transaction. |
| <code>public_key</code> | <code>vector&lt;u8&gt;</code> | 32-byte Ed25519 public key.                           |


<a name="@Common_Abort_Conditions_122"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                    | Description                                                                                   |
| ----------------           | --------------                                  | -------------                                                                                 |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_ESHARED_KEY">SharedEd25519PublicKey::ESHARED_KEY</a></code>           | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_SharedEd25519PublicKey">SharedEd25519PublicKey::SharedEd25519PublicKey</a></code> resource is not published under <code>account</code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_EMALFORMED_PUBLIC_KEY">SharedEd25519PublicKey::EMALFORMED_PUBLIC_KEY</a></code> | <code>public_key</code> is an invalid ed25519 public key.                                                |


<a name="@Related_Scripts_123"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_publish_shared_ed25519_public_key">AccountAdministrationScripts::publish_shared_ed25519_public_key</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key">rotate_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_shared_ed25519_public_key">rotate_shared_ed25519_public_key</a>(account: signer, public_key: vector&lt;u8&gt;) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_rotate_key">SharedEd25519PublicKey::rotate_key</a>(&account, public_key)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_RotateKeyAbortsIf">SharedEd25519PublicKey::RotateKeyAbortsIf</a>{new_public_key: public_key};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey_RotateKeyEnsures">SharedEd25519PublicKey::RotateKeyEnsures</a>{new_public_key: public_key};
<b>aborts_with</b> [check]
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_create_recovery_address"></a>

##### Function `create_recovery_address`


<a name="@Summary_124"></a>

###### Summary

Initializes the sending account as a recovery address that may be used by
other accounts belonging to the same VASP as <code>account</code>.
The sending account must be a VASP account, and can be either a child or parent VASP account.
Multiple recovery addresses can exist for a single VASP, but accounts in
each must be disjoint.


<a name="@Technical_Description_125"></a>

###### Technical Description

Publishes a <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource under <code>account</code>. It then
extracts the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code> for <code>account</code> and adds
it to the resource. After the successful execution of this transaction
other accounts may add their key rotation to this resource so that <code>account</code>
may be used as a recovery account for those accounts.


<a name="@Parameters_126"></a>

###### Parameters

| Name      | Type     | Description                                           |
| ------    | ------   | -------------                                         |
| <code>account</code> | <code>signer</code> | The signer of the sending account of the transaction. |


<a name="@Common_Abort_Conditions_127"></a>

###### Common Abort Conditions

| Error Category              | Error Reason                                               | Description                                                                                   |
| ----------------            | --------------                                             | -------------                                                                                 |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED">DiemAccount::EKEY_ROTATION_CAPABILITY_ALREADY_EXTRACTED</a></code> | <code>account</code> has already delegated/extracted its <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_KeyRotationCapability">DiemAccount::KeyRotationCapability</a></code>.          |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_ENOT_A_VASP">RecoveryAddress::ENOT_A_VASP</a></code>                             | <code>account</code> is not a VASP account.                                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_EKEY_ROTATION_DEPENDENCY_CYCLE">RecoveryAddress::EKEY_ROTATION_DEPENDENCY_CYCLE</a></code>          | A key rotation recovery cycle would be created by adding <code>account</code>'s key rotation capability. |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_ERECOVERY_ADDRESS">RecoveryAddress::ERECOVERY_ADDRESS</a></code>                       | A <code><a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_RecoveryAddress">RecoveryAddress::RecoveryAddress</a></code> resource has already been published under <code>account</code>.     |


<a name="@Related_Scripts_128"></a>

###### Related Scripts

* <code>Script::add_recovery_rotation_capability</code>
* <code>Script::rotate_authentication_key_with_recovery_address</code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_create_recovery_address">create_recovery_address</a>(account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_create_recovery_address">create_recovery_address</a>(account: signer) {
    <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_publish">RecoveryAddress::publish</a>(&account, <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_key_rotation_capability">DiemAccount::extract_key_rotation_capability</a>(&account))
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityAbortsIf">DiemAccount::ExtractKeyRotationCapabilityAbortsIf</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractKeyRotationCapabilityEnsures">DiemAccount::ExtractKeyRotationCapabilityEnsures</a>;
<b>let</b> account_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(account);
<b>let</b> rotation_cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_key_rotation_cap">DiemAccount::spec_get_key_rotation_cap</a>(account_addr);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_PublishAbortsIf">RecoveryAddress::PublishAbortsIf</a>{
    recovery_account: account,
    rotation_cap: rotation_cap
};
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_spec_is_recovery_address">RecoveryAddress::spec_is_recovery_address</a>(account_addr);
<b>ensures</b> len(<a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(account_addr)) == 1;
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress_spec_get_rotation_caps">RecoveryAddress::spec_get_rotation_caps</a>(account_addr)[0] == rotation_cap;
<b>aborts_with</b> [check]
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>;
</code></pre>



</details>

<a name="0x1_AccountAdministrationScripts_create_vasp_domains"></a>

##### Function `create_vasp_domains`


<a name="@Summary_129"></a>

###### Summary

Publishes a <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource under a parent VASP account.
The sending account must be a parent VASP account.


<a name="@Technical_Description_130"></a>

###### Technical Description

Publishes a <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource under <code>account</code>.
The The <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource's <code>domains</code> field is a vector
of VASPDomain, and will be empty on at the end of processing this transaction.


<a name="@Parameters_131"></a>

###### Parameters

| Name      | Type     | Description                                           |
| ------    | ------   | -------------                                         |
| <code>account</code> | <code>signer</code> | The signer of the sending account of the transaction. |


<a name="@Common_Abort_Conditions_132"></a>

###### Common Abort Conditions

| Error Category              | Error Reason              | Description                                                                    |
| ----------------            | --------------            | -------------                                                                  |
| <code><a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS">VASPDomain::EVASP_DOMAINS</a></code> | A <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource has already been published under <code>account</code>. |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>     | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EPARENT_VASP">Roles::EPARENT_VASP</a></code>     | The sending <code>account</code> was not a parent VASP account.                           |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_create_vasp_domains">create_vasp_domains</a>(account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_AccountAdministrationScripts_create_vasp_domains">create_vasp_domains</a>(account: signer) {
    <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_publish_vasp_domains">VASPDomain::publish_vasp_domains</a>(&account)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> vasp_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(account);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotParentVasp">Roles::AbortsIfNotParentVasp</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsAbortsIf">VASPDomain::PublishVASPDomainsAbortsIf</a> { vasp_addr };
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_PublishVASPDomainsEnsures">VASPDomain::PublishVASPDomainsEnsures</a> { vasp_addr };
<b>aborts_with</b> [check]
    <a href="_ALREADY_PUBLISHED">Errors::ALREADY_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
</code></pre>



</details>


---

<a name="@Payments_133"></a>

### Payments



<a name="0x1_PaymentScripts"></a>

#### Module `0x1::PaymentScripts`

This module holds all payment related script entrypoints in the Diem Framework.
Any account that can hold a balance can use the transaction scripts within this module.


<pre><code><b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
</code></pre>



<a name="0x1_PaymentScripts_peer_to_peer_with_metadata"></a>

##### Function `peer_to_peer_with_metadata`


<a name="@Summary_134"></a>

###### Summary

Transfers a given number of coins in a specified currency from one account to another.
Transfers over a specified amount defined on-chain that are between two different VASPs, or
other accounts that have opted-in will be subject to on-chain checks to ensure the receiver has
agreed to receive the coins.  This transaction can be sent by any account that can hold a
balance, and to any account that can hold a balance. Both accounts must hold balances in the
currency being transacted.


<a name="@Technical_Description_135"></a>

###### Technical Description


Transfers <code>amount</code> coins of type <code>Currency</code> from <code>payer</code> to <code>payee</code> with (optional) associated
<code>metadata</code> and an (optional) <code>metadata_signature</code> on the message of the form
<code>metadata</code> | <code><a href="_address_of">Signer::address_of</a>(payer)</code> | <code>amount</code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_DOMAIN_SEPARATOR">DualAttestation::DOMAIN_SEPARATOR</a></code>, that
has been signed by the <code>payee</code>'s private key associated with the <code>compliance_public_key</code> held in
the <code>payee</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code>. Both the <code><a href="_address_of">Signer::address_of</a>(payer)</code> and <code>amount</code> fields
in the <code>metadata_signature</code> must be BCS-encoded bytes, and <code>|</code> denotes concatenation.
The <code>metadata</code> and <code>metadata_signature</code> parameters are only required if <code>amount</code> >=
<code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_get_cur_microdiem_limit">DualAttestation::get_cur_microdiem_limit</a></code> XDX and <code>payer</code> and <code>payee</code> are distinct VASPs.
However, a transaction sender can opt in to dual attestation even when it is not required
(e.g., a DesignatedDealer -> VASP payment) by providing a non-empty <code>metadata_signature</code>.
Standardized <code>metadata</code> BCS format can be found in <code>diem_types::transaction::metadata::Metadata</code>.


<a name="@Events_136"></a>

###### Events

Successful execution of this script emits two events:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a></code> on <code>payer</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code> handle; and
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> on <code>payee</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> handle.


<a name="@Parameters_137"></a>

###### Parameters

| Name                 | Type         | Description                                                                                                                  |
| ------               | ------       | -------------                                                                                                                |
| <code>Currency</code>           | Type         | The Move type for the <code>Currency</code> being sent in this transaction. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>payer</code>              | <code>signer</code>     | The signer of the sending account that coins are being transferred from.                                                     |
| <code>payee</code>              | <code>address</code>    | The address of the account the coins are being transferred to.                                                               |
| <code>metadata</code>           | <code>vector&lt;u8&gt;</code> | Optional metadata about this payment.                                                                                        |
| <code>metadata_signature</code> | <code>vector&lt;u8&gt;</code> | Optional signature over <code>metadata</code> and payment information. See                                                              |


<a name="@Common_Abort_Conditions_138"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                     | Description                                                                                                                         |
| ----------------           | --------------                                   | -------------                                                                                                                       |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>       | <code>payer</code> doesn't hold a balance in <code>Currency</code>.                                                                                       |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>             | <code>amount</code> is greater than <code>payer</code>'s balance in <code>Currency</code>.                                                                           |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ECOIN_DEPOSIT_IS_ZERO">DiemAccount::ECOIN_DEPOSIT_IS_ZERO</a></code>             | <code>amount</code> is zero.                                                                                                                   |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYEE_DOES_NOT_EXIST">DiemAccount::EPAYEE_DOES_NOT_EXIST</a></code>             | No account exists at the <code>payee</code> address.                                                                                           |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYEE_CANT_ACCEPT_CURRENCY_TYPE">DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE</a></code>  | An account exists at <code>payee</code>, but it does not accept payments in <code>Currency</code>.                                                        |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_EACCOUNT_FROZEN">AccountFreezing::EACCOUNT_FROZEN</a></code>               | The <code>payee</code> account is frozen.                                                                                                      |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_EMALFORMED_METADATA_SIGNATURE">DualAttestation::EMALFORMED_METADATA_SIGNATURE</a></code> | <code>metadata_signature</code> is not 64 bytes.                                                                                               |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_EINVALID_METADATA_SIGNATURE">DualAttestation::EINVALID_METADATA_SIGNATURE</a></code>   | <code>metadata_signature</code> does not verify on the against the <code>payee'</code>s <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_Credential">DualAttestation::Credential</a></code> <code>compliance_public_key</code> public key. |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EWITHDRAWAL_EXCEEDS_LIMITS">DiemAccount::EWITHDRAWAL_EXCEEDS_LIMITS</a></code>        | <code>payer</code> has exceeded its daily withdrawal limits for the backing coins of XDX.                                                      |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>           | <code>payee</code> has exceeded its daily deposit limits for XDX.                                                                              |


<a name="@Related_Scripts_139"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_by_signers">PaymentScripts::peer_to_peer_by_signers</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_with_metadata">peer_to_peer_with_metadata</a>&lt;Currency&gt;(payer: signer, payee: address, amount: u64, metadata: vector&lt;u8&gt;, metadata_signature: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_with_metadata">peer_to_peer_with_metadata</a>&lt;Currency&gt;(
    payer: signer,
    payee: address,
    amount: u64,
    metadata: vector&lt;u8&gt;,
    metadata_signature: vector&lt;u8&gt;
) {
    <b>let</b> payer_withdrawal_cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&payer);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_pay_from">DiemAccount::pay_from</a>&lt;Currency&gt;(
        &payer_withdrawal_cap, payee, amount, metadata, metadata_signature
    );
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(payer_withdrawal_cap);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="script_documentation.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_AssertPaymentOkAbortsIf">DualAttestation::AssertPaymentOkAbortsIf</a>&lt;Currency&gt;{
    payer: <a href="_spec_address_of">Signer::spec_address_of</a>(payer),
    value: amount
};
</code></pre>



</details>

<a name="0x1_PaymentScripts_peer_to_peer_by_signers"></a>

##### Function `peer_to_peer_by_signers`


<a name="@Summary_140"></a>

###### Summary

Transfers a given number of coins in a specified currency from one account to another by multi-agent transaction.
Transfers over a specified amount defined on-chain that are between two different VASPs, or
other accounts that have opted-in will be subject to on-chain checks to ensure the receiver has
agreed to receive the coins.  This transaction can be sent by any account that can hold a
balance, and to any account that can hold a balance. Both accounts must hold balances in the
currency being transacted.


<a name="@Technical_Description_141"></a>

###### Technical Description


Transfers <code>amount</code> coins of type <code>Currency</code> from <code>payer</code> to <code>payee</code> with (optional) associated
<code>metadata</code>.
Dual attestation is not applied to this script as payee is also a signer of the transaction.
Standardized <code>metadata</code> BCS format can be found in <code>diem_types::transaction::metadata::Metadata</code>.


<a name="@Events_142"></a>

###### Events

Successful execution of this script emits two events:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a></code> on <code>payer</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code> handle; and
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> on <code>payee</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> handle.


<a name="@Parameters_143"></a>

###### Parameters

| Name                 | Type         | Description                                                                                                                  |
| ------               | ------       | -------------                                                                                                                |
| <code>Currency</code>           | Type         | The Move type for the <code>Currency</code> being sent in this transaction. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>payer</code>              | <code>signer</code>     | The signer of the sending account that coins are being transferred from.                                                     |
| <code>payee</code>              | <code>signer</code>     | The signer of the receiving account that the coins are being transferred to.                                                 |
| <code>metadata</code>           | <code>vector&lt;u8&gt;</code> | Optional metadata about this payment.                                                                                        |


<a name="@Common_Abort_Conditions_144"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                     | Description                                                                                                                         |
| ----------------           | --------------                                   | -------------                                                                                                                       |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>       | <code>payer</code> doesn't hold a balance in <code>Currency</code>.                                                                                       |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>             | <code>amount</code> is greater than <code>payer</code>'s balance in <code>Currency</code>.                                                                           |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ECOIN_DEPOSIT_IS_ZERO">DiemAccount::ECOIN_DEPOSIT_IS_ZERO</a></code>             | <code>amount</code> is zero.                                                                                                                   |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYEE_DOES_NOT_EXIST">DiemAccount::EPAYEE_DOES_NOT_EXIST</a></code>             | No account exists at the <code>payee</code> address.                                                                                           |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYEE_CANT_ACCEPT_CURRENCY_TYPE">DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE</a></code>  | An account exists at <code>payee</code>, but it does not accept payments in <code>Currency</code>.                                                        |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_EACCOUNT_FROZEN">AccountFreezing::EACCOUNT_FROZEN</a></code>               | The <code>payee</code> account is frozen.                                                                                                      |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EWITHDRAWAL_EXCEEDS_LIMITS">DiemAccount::EWITHDRAWAL_EXCEEDS_LIMITS</a></code>        | <code>payer</code> has exceeded its daily withdrawal limits for the backing coins of XDX.                                                      |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>           | <code>payee</code> has exceeded its daily deposit limits for XDX.                                                                              |


<a name="@Related_Scripts_145"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_child_vasp_account">AccountCreationScripts::create_child_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_parent_vasp_account">AccountCreationScripts::create_parent_vasp_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_add_currency_to_account">AccountAdministrationScripts::add_currency_to_account</a></code>
* <code><a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_by_signers">peer_to_peer_by_signers</a>&lt;Currency&gt;(payer: signer, payee: signer, amount: u64, metadata: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_by_signers">peer_to_peer_by_signers</a>&lt;Currency&gt;(
    payer: signer,
    payee: signer,
    amount: u64,
    metadata: vector&lt;u8&gt;,
) {
    <b>let</b> payer_withdrawal_cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&payer);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_pay_by_signers">DiemAccount::pay_by_signers</a>&lt;Currency&gt;(
        &payer_withdrawal_cap, &payee, amount, metadata
    );
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(payer_withdrawal_cap);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="script_documentation.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt;{payee: <a href="_spec_address_of">Signer::spec_address_of</a>(payee)};
</code></pre>




<a name="0x1_PaymentScripts_PeerToPeer"></a>


<pre><code><b>schema</b> <a href="script_documentation.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt; {
    payer: signer;
    payee: address;
    amount: u64;
    metadata: vector&lt;u8&gt;;
    <b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: payer};
    <b>let</b> payer_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(payer);
    <b>let</b> cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_withdraw_cap">DiemAccount::spec_get_withdraw_cap</a>(payer_addr);
    <b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractWithdrawCapAbortsIf">DiemAccount::ExtractWithdrawCapAbortsIf</a>{sender_addr: payer_addr};
    <b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_PayFromAbortsIf">DiemAccount::PayFromAbortsIf</a>&lt;Currency&gt;{cap: cap};
}
</code></pre>


The balances of payer and payee change by the correct amount.


<pre><code><b>schema</b> <a href="script_documentation.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt; {
    <b>ensures</b> payer_addr != payee
        ==&gt; <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payer_addr)
        == <b>old</b>(<a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payer_addr)) - amount;
    <b>ensures</b> payer_addr != payee
        ==&gt; <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee)
        == <b>old</b>(<a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee)) + amount;
    <b>ensures</b> payer_addr == payee
        ==&gt; <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee)
        == <b>old</b>(<a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Currency&gt;(payee));
    <b>aborts_with</b> [check]
        <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
        <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
        <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
        <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
    <b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_PayFromEmits">DiemAccount::PayFromEmits</a>&lt;Currency&gt;{cap: cap};
}
</code></pre>


**Access Control:**
Both the payer and the payee must hold the balances of the Currency. Only Designated Dealers,
Parent VASPs, and Child VASPs can hold balances [[D1]][ROLE][[D2]][ROLE][[D3]][ROLE][[D4]][ROLE][[D5]][ROLE][[D6]][ROLE][[D7]][ROLE].


<pre><code><b>schema</b> <a href="script_documentation.md#0x1_PaymentScripts_PeerToPeer">PeerToPeer</a>&lt;Currency&gt; {
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;&gt;(payer_addr) <b>with</b> <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
    <b>aborts_if</b> !<b>exists</b>&lt;<a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Currency&gt;&gt;(payee) <b>with</b> <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
}
</code></pre>



</details>


---

<a name="@Validator_and_Validator_Operator_Administration_146"></a>

### Validator and Validator Operator Administration



<a name="0x1_ValidatorAdministrationScripts"></a>

#### Module `0x1::ValidatorAdministrationScripts`



<pre><code><b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem">0x1::DiemSystem</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig">0x1::ValidatorConfig</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig">0x1::ValidatorOperatorConfig</a>;
</code></pre>



<a name="0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure"></a>

##### Function `add_validator_and_reconfigure`


<a name="@Summary_147"></a>

###### Summary

Adds a validator account to the validator set, and triggers a
reconfiguration of the system to admit the account to the validator set for the system. This
transaction can only be successfully called by the Diem Root account.


<a name="@Technical_Description_148"></a>

###### Technical Description

This script adds the account at <code>validator_address</code> to the validator set.
This transaction emits a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code> event and triggers a
reconfiguration. Once the reconfiguration triggered by this script's
execution has been performed, the account at the <code>validator_address</code> is
considered to be a validator in the network.

This transaction script will fail if the <code>validator_address</code> address is already in the validator set
or does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource already published under it.


<a name="@Parameters_149"></a>

###### Parameters

| Name                | Type         | Description                                                                                                                        |
| ------              | ------       | -------------                                                                                                                      |
| <code>dr_account</code>        | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Diem Root signer.                                               |
| <code>sliding_nonce</code>     | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                                         |
| <code>validator_name</code>    | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the validator. Must match the human name in the <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> for the validator. |
| <code>validator_address</code> | <code>address</code>    | The validator account address to be added to the validator set.                                                                    |


<a name="@Common_Abort_Conditions_150"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                 | Description                                                                                                                               |
| ----------------           | --------------                               | -------------                                                                                                                             |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>               | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                                                                            |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>               | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not.                                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>               | The <code>sliding_nonce</code> is too far in the future.                                                                                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>      | The <code>sliding_nonce</code> has been previously recorded.                                                                                         |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>                  | The sending account is not the Diem Root account.                                                                                         |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EDIEM_ROOT">Roles::EDIEM_ROOT</a></code>                          | The sending account is not the Diem Root account.                                                                                         |
| 0                          | 0                                            | The provided <code>validator_name</code> does not match the already-recorded human name for the validator.                                           |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_EINVALID_PROSPECTIVE_VALIDATOR">DiemSystem::EINVALID_PROSPECTIVE_VALIDATOR</a></code> | The validator to be added does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource published under it, or its <code>config</code> field is empty. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_EALREADY_A_VALIDATOR">DiemSystem::EALREADY_A_VALIDATOR</a></code>           | The <code>validator_address</code> account is already a registered validator.                                                                        |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_EINVALID_BLOCK_TIME">DiemConfig::EINVALID_BLOCK_TIME</a></code>            | An invalid time value was encountered in reconfiguration. Unlikely to occur.                                                              |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_EMAX_VALIDATORS">DiemSystem::EMAX_VALIDATORS</a></code>                | The validator set is already at its maximum size. The validator could not be added.                                                       |


<a name="@Related_Scripts_151"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">add_validator_and_reconfigure</a>(dr_account: signer, sliding_nonce: u64, validator_name: vector&lt;u8&gt;, validator_address: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">add_validator_and_reconfigure</a>(
    dr_account: signer,
    sliding_nonce: u64,
    validator_name: vector&lt;u8&gt;,
    validator_address: address
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <b>assert</b>(<a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_get_human_name">ValidatorConfig::get_human_name</a>(validator_address) == validator_name, 0);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_add_validator">DiemSystem::add_validator</a>(&dr_account, validator_address);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{seq_nonce: sliding_nonce, account: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_AbortsIfNoValidatorConfig">ValidatorConfig::AbortsIfNoValidatorConfig</a>{addr: validator_address};
<b>aborts_if</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_get_human_name">ValidatorConfig::get_human_name</a>(validator_address) != validator_name <b>with</b> 0;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_AddValidatorAbortsIf">DiemSystem::AddValidatorAbortsIf</a>{validator_addr: validator_address};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_AddValidatorEnsures">DiemSystem::AddValidatorEnsures</a>{validator_addr: validator_address};
</code></pre>


Reports INVALID_STATE because of is_operating() and !exists<DiemSystem::CapabilityHolder>.
is_operating() is always true during transactions, and CapabilityHolder is published
during initialization (Genesis).
Reports REQUIRES_ROLE if dr_account is not Diem root, but that can't happen
in practice because it aborts with NOT_PUBLISHED or REQUIRES_ADDRESS, first.


<pre><code><b>aborts_with</b> [check]
    0, // Odd error code in <b>assert</b> on second statement in add_validator_and_reconfigure
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_ReconfigureEmits">DiemConfig::ReconfigureEmits</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can add Validators [[H14]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
</code></pre>



</details>

<a name="0x1_ValidatorAdministrationScripts_register_validator_config"></a>

##### Function `register_validator_config`


<a name="@Summary_152"></a>

###### Summary

Updates a validator's configuration. This does not reconfigure the system and will not update
the configuration in the validator set that is seen by other validators in the network. Can
only be successfully sent by a Validator Operator account that is already registered with a
validator.


<a name="@Technical_Description_153"></a>

###### Technical Description

This updates the fields with corresponding names held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>
config resource held under <code>validator_account</code>. It does not emit a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code>
so the copy of this config held in the validator set will not be updated, and the changes are
only "locally" under the <code>validator_account</code> account address.


<a name="@Parameters_154"></a>

###### Parameters

| Name                          | Type         | Description                                                                                                        |
| ------                        | ------       | -------------                                                                                                      |
| <code>validator_operator_account</code>  | <code>signer</code>     | Signer of the sending account. Must be the registered validator operator for the validator at <code>validator_address</code>. |
| <code>validator_account</code>           | <code>address</code>    | The address of the validator's <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource being updated.                          |
| <code>consensus_pubkey</code>            | <code>vector&lt;u8&gt;</code> | New Ed25519 public key to be used in the updated <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>.                               |
| <code>validator_network_addresses</code> | <code>vector&lt;u8&gt;</code> | New set of <code>validator_network_addresses</code> to be used in the updated <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>.             |
| <code>fullnode_network_addresses</code>  | <code>vector&lt;u8&gt;</code> | New set of <code>fullnode_network_addresses</code> to be used in the updated <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>.              |


<a name="@Common_Abort_Conditions_155"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                   | Description                                                                                           |
| ----------------           | --------------                                 | -------------                                                                                         |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EVALIDATOR_CONFIG">ValidatorConfig::EVALIDATOR_CONFIG</a></code>           | <code>validator_address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource published under it.   |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EINVALID_TRANSACTION_SENDER">ValidatorConfig::EINVALID_TRANSACTION_SENDER</a></code> | <code>validator_operator_account</code> is not the registered operator for the validator at <code>validator_address</code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EINVALID_CONSENSUS_KEY">ValidatorConfig::EINVALID_CONSENSUS_KEY</a></code>      | <code>consensus_pubkey</code> is not a valid ed25519 public key.                                                 |


<a name="@Related_Scripts_156"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">register_validator_config</a>(validator_operator_account: signer, validator_account: address, consensus_pubkey: vector&lt;u8&gt;, validator_network_addresses: vector&lt;u8&gt;, fullnode_network_addresses: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">register_validator_config</a>(
    validator_operator_account: signer,
    // TODO Rename <b>to</b> validator_addr, since it is an address.
    validator_account: address,
    consensus_pubkey: vector&lt;u8&gt;,
    validator_network_addresses: vector&lt;u8&gt;,
    fullnode_network_addresses: vector&lt;u8&gt;,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_set_config">ValidatorConfig::set_config</a>(
        &validator_operator_account,
        validator_account,
        consensus_pubkey,
        validator_network_addresses,
        fullnode_network_addresses
    );
 }
</code></pre>



</details>

<details>
<summary>Specification</summary>

Access control rule is that only the validator operator for a validator may set
call this, but there is an aborts_if in SetConfigAbortsIf that tests that directly.


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: validator_operator_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_SetConfigAbortsIf">ValidatorConfig::SetConfigAbortsIf</a> {validator_addr: validator_account};
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_is_valid">ValidatorConfig::is_valid</a>(validator_account);
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
</code></pre>


**Access Control:**
Only the Validator Operator account which has been registered with the validator can
update the validator's configuration [[H15]][PERMISSION].


<pre><code><b>aborts_if</b> <a href="_address_of">Signer::address_of</a>(validator_operator_account) !=
            <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_get_operator">ValidatorConfig::get_operator</a>(validator_account)
                <b>with</b> <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure"></a>

##### Function `remove_validator_and_reconfigure`


<a name="@Summary_157"></a>

###### Summary

This script removes a validator account from the validator set, and triggers a reconfiguration
of the system to remove the validator from the system. This transaction can only be
successfully called by the Diem Root account.


<a name="@Technical_Description_158"></a>

###### Technical Description

This script removes the account at <code>validator_address</code> from the validator set. This transaction
emits a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code> event. Once the reconfiguration triggered by this event
has been performed, the account at <code>validator_address</code> is no longer considered to be a
validator in the network. This transaction will fail if the validator at <code>validator_address</code>
is not in the validator set.


<a name="@Parameters_159"></a>

###### Parameters

| Name                | Type         | Description                                                                                                                        |
| ------              | ------       | -------------                                                                                                                      |
| <code>dr_account</code>        | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Diem Root signer.                                               |
| <code>sliding_nonce</code>     | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                                         |
| <code>validator_name</code>    | <code>vector&lt;u8&gt;</code> | ASCII-encoded human name for the validator. Must match the human name in the <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> for the validator. |
| <code>validator_address</code> | <code>address</code>    | The validator account address to be removed from the validator set.                                                                |


<a name="@Common_Abort_Conditions_160"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                            | Description                                                                                     |
| ----------------           | --------------                          | -------------                                                                                   |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                                  |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not.      |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                                   |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                               |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | The sending account is not the Diem Root account or Treasury Compliance account                |
| 0                          | 0                                       | The provided <code>validator_name</code> does not match the already-recorded human name for the validator. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_ENOT_AN_ACTIVE_VALIDATOR">DiemSystem::ENOT_AN_ACTIVE_VALIDATOR</a></code> | The validator to be removed is not in the validator set.                                        |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>            | The sending account is not the Diem Root account.                                              |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EDIEM_ROOT">Roles::EDIEM_ROOT</a></code>                    | The sending account is not the Diem Root account.                                              |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_EINVALID_BLOCK_TIME">DiemConfig::EINVALID_BLOCK_TIME</a></code>      | An invalid time value was encountered in reconfiguration. Unlikely to occur.                    |


<a name="@Related_Scripts_161"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">remove_validator_and_reconfigure</a>(dr_account: signer, sliding_nonce: u64, validator_name: vector&lt;u8&gt;, validator_address: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">remove_validator_and_reconfigure</a>(
    dr_account: signer,
    sliding_nonce: u64,
    validator_name: vector&lt;u8&gt;,
    validator_address: address
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    // TODO: Use an error code from <a href="">Errors</a>.<b>move</b>
    <b>assert</b>(<a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_get_human_name">ValidatorConfig::get_human_name</a>(validator_address) == validator_name, 0);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_remove_validator">DiemSystem::remove_validator</a>(&dr_account, validator_address);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{seq_nonce: sliding_nonce, account: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_AbortsIfNoValidatorConfig">ValidatorConfig::AbortsIfNoValidatorConfig</a>{addr: validator_address};
<b>aborts_if</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_get_human_name">ValidatorConfig::get_human_name</a>(validator_address) != validator_name <b>with</b> 0;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_RemoveValidatorAbortsIf">DiemSystem::RemoveValidatorAbortsIf</a>{validator_addr: validator_address};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_RemoveValidatorEnsures">DiemSystem::RemoveValidatorEnsures</a>{validator_addr: validator_address};
</code></pre>


Reports INVALID_STATE because of is_operating() and !exists<DiemSystem::CapabilityHolder>.
is_operating() is always true during transactions, and CapabilityHolder is published
during initialization (Genesis).
Reports REQUIRES_ROLE if dr_account is not Diem root, but that can't happen
in practice because it aborts with NOT_PUBLISHED or REQUIRES_ADDRESS, first.


<pre><code><b>aborts_with</b> [check]
    0, // Odd error code in <b>assert</b> on second statement in add_validator_and_reconfigure
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_ReconfigureEmits">DiemConfig::ReconfigureEmits</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can remove Validators [[H14]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotDiemRoot">Roles::AbortsIfNotDiemRoot</a>{account: dr_account};
</code></pre>



</details>

<a name="0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure"></a>

##### Function `set_validator_config_and_reconfigure`


<a name="@Summary_162"></a>

###### Summary

Updates a validator's configuration, and triggers a reconfiguration of the system to update the
validator set with this new validator configuration.  Can only be successfully sent by a
Validator Operator account that is already registered with a validator.


<a name="@Technical_Description_163"></a>

###### Technical Description

This updates the fields with corresponding names held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>
config resource held under <code>validator_account</code>. It then emits a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code> to
trigger a reconfiguration of the system.  This reconfiguration will update the validator set
on-chain with the updated <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>.


<a name="@Parameters_164"></a>

###### Parameters

| Name                          | Type         | Description                                                                                                        |
| ------                        | ------       | -------------                                                                                                      |
| <code>validator_operator_account</code>  | <code>signer</code>     | Signer of the sending account. Must be the registered validator operator for the validator at <code>validator_address</code>. |
| <code>validator_account</code>           | <code>address</code>    | The address of the validator's <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource being updated.                          |
| <code>consensus_pubkey</code>            | <code>vector&lt;u8&gt;</code> | New Ed25519 public key to be used in the updated <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>.                               |
| <code>validator_network_addresses</code> | <code>vector&lt;u8&gt;</code> | New set of <code>validator_network_addresses</code> to be used in the updated <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>.             |
| <code>fullnode_network_addresses</code>  | <code>vector&lt;u8&gt;</code> | New set of <code>fullnode_network_addresses</code> to be used in the updated <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code>.              |


<a name="@Common_Abort_Conditions_165"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                   | Description                                                                                           |
| ----------------           | --------------                                 | -------------                                                                                         |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EVALIDATOR_CONFIG">ValidatorConfig::EVALIDATOR_CONFIG</a></code>           | <code>validator_address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource published under it.   |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EVALIDATOR_OPERATOR">Roles::EVALIDATOR_OPERATOR</a></code>                   | <code>validator_operator_account</code> does not have a Validator Operator role.                                 |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EINVALID_TRANSACTION_SENDER">ValidatorConfig::EINVALID_TRANSACTION_SENDER</a></code> | <code>validator_operator_account</code> is not the registered operator for the validator at <code>validator_address</code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EINVALID_CONSENSUS_KEY">ValidatorConfig::EINVALID_CONSENSUS_KEY</a></code>      | <code>consensus_pubkey</code> is not a valid ed25519 public key.                                                 |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_EINVALID_BLOCK_TIME">DiemConfig::EINVALID_BLOCK_TIME</a></code>             | An invalid time value was encountered in reconfiguration. Unlikely to occur.                          |


<a name="@Related_Scripts_166"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">set_validator_config_and_reconfigure</a>(validator_operator_account: signer, validator_account: address, consensus_pubkey: vector&lt;u8&gt;, validator_network_addresses: vector&lt;u8&gt;, fullnode_network_addresses: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">set_validator_config_and_reconfigure</a>(
    validator_operator_account: signer,
    validator_account: address,
    consensus_pubkey: vector&lt;u8&gt;,
    validator_network_addresses: vector&lt;u8&gt;,
    fullnode_network_addresses: vector&lt;u8&gt;,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_set_config">ValidatorConfig::set_config</a>(
        &validator_operator_account,
        validator_account,
        consensus_pubkey,
        validator_network_addresses,
        fullnode_network_addresses
    );
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_update_config_and_reconfigure">DiemSystem::update_config_and_reconfigure</a>(&validator_operator_account, validator_account);
 }
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: validator_operator_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_UpdateConfigAndReconfigureEnsures">DiemSystem::UpdateConfigAndReconfigureEnsures</a>{validator_addr: validator_account};
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_is_valid">ValidatorConfig::is_valid</a>(validator_account);
<b>ensures</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_spec_get_config">ValidatorConfig::spec_get_config</a>(validator_account)
    == <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_Config">ValidatorConfig::Config</a> {
                consensus_pubkey,
                validator_network_addresses,
                fullnode_network_addresses,
};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_SetConfigAbortsIf">ValidatorConfig::SetConfigAbortsIf</a>{validator_addr: validator_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_UpdateConfigAndReconfigureAbortsIf">DiemSystem::UpdateConfigAndReconfigureAbortsIf</a>{validator_addr: validator_account};
<b>let</b> is_validator_info_updated =
    (<b>exists</b> v_info in <a href="../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem_spec_get_validators">DiemSystem::spec_get_validators</a>():
        v_info.addr == validator_account
        && v_info.config != <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_Config">ValidatorConfig::Config</a> {
                consensus_pubkey,
                validator_network_addresses,
                fullnode_network_addresses,
           });
<b>include</b> is_validator_info_updated ==&gt; <a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_ReconfigureAbortsIf">DiemConfig::ReconfigureAbortsIf</a>;
</code></pre>


This reports a possible INVALID_STATE abort, which comes from an assert in DiemConfig::reconfigure_
that config.last_reconfiguration_time is not in the future. This is a system error that a user
for which there is no useful recovery except to resubmit the transaction.


<pre><code><b>aborts_with</b> [check]
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>;
<b>include</b> is_validator_info_updated ==&gt; <a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_ReconfigureEmits">DiemConfig::ReconfigureEmits</a>;
</code></pre>


**Access Control:**
Only the Validator Operator account which has been registered with the validator can
update the validator's configuration [[H15]][PERMISSION].


<pre><code><b>aborts_if</b> <a href="_address_of">Signer::address_of</a>(validator_operator_account) !=
            <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_get_operator">ValidatorConfig::get_operator</a>(validator_account)
                <b>with</b> <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_ValidatorAdministrationScripts_set_validator_operator"></a>

##### Function `set_validator_operator`


<a name="@Summary_167"></a>

###### Summary

Sets the validator operator for a validator in the validator's configuration resource "locally"
and does not reconfigure the system. Changes from this transaction will not picked up by the
system until a reconfiguration of the system is triggered. May only be sent by an account with
Validator role.


<a name="@Technical_Description_168"></a>

###### Technical Description

Sets the account at <code>operator_account</code> address and with the specified <code>human_name</code> as an
operator for the sending validator account. The account at <code>operator_account</code> address must have
a Validator Operator role and have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code>
resource published under it. The sending <code>account</code> must be a Validator and have a
<code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource published under it. This script does not emit a
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code> and no reconfiguration of the system is initiated by this script.


<a name="@Parameters_169"></a>

###### Parameters

| Name               | Type         | Description                                                                                  |
| ------             | ------       | -------------                                                                                |
| <code>account</code>          | <code>signer</code>     | The signer of the sending account of the transaction.                                        |
| <code>operator_name</code>    | <code>vector&lt;u8&gt;</code> | Validator operator's human name.                                                             |
| <code>operator_account</code> | <code>address</code>    | Address of the validator operator account to be added as the <code>account</code> validator's operator. |


<a name="@Common_Abort_Conditions_170"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                          | Description                                                                                                                                                  |
| ----------------           | --------------                                        | -------------                                                                                                                                                |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_EVALIDATOR_OPERATOR_CONFIG">ValidatorOperatorConfig::EVALIDATOR_OPERATOR_CONFIG</a></code> | The <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource is not published under <code>operator_account</code>.                                                   |
| 0                          | 0                                                     | The <code>human_name</code> field of the <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource under <code>operator_account</code> does not match the provided <code>human_name</code>. |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EVALIDATOR">Roles::EVALIDATOR</a></code>                                   | <code>account</code> does not have a Validator account role.                                                                                                            |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ENOT_A_VALIDATOR_OPERATOR">ValidatorConfig::ENOT_A_VALIDATOR_OPERATOR</a></code>          | The account at <code>operator_account</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource.                                               |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EVALIDATOR_CONFIG">ValidatorConfig::EVALIDATOR_CONFIG</a></code>                  | A <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> is not published under <code>account</code>.                                                                                       |


<a name="@Related_Scripts_171"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">ValidatorAdministrationScripts::set_validator_operator_with_nonce_admin</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">set_validator_operator</a>(account: signer, operator_name: vector&lt;u8&gt;, operator_account: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">set_validator_operator</a>(
    account: signer,
    operator_name: vector&lt;u8&gt;,
    operator_account: address
) {
    <b>assert</b>(<a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_get_human_name">ValidatorOperatorConfig::get_human_name</a>(operator_account) == operator_name, 0);
    <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_set_operator">ValidatorConfig::set_operator</a>(&account, operator_account);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> account_addr = <a href="_address_of">Signer::address_of</a>(account);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_AbortsIfNoValidatorConfig">ValidatorConfig::AbortsIfNoValidatorConfig</a>{addr: account_addr};
<b>aborts_if</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_get_human_name">ValidatorOperatorConfig::get_human_name</a>(operator_account) != operator_name <b>with</b> 0;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_SetOperatorAbortsIf">ValidatorConfig::SetOperatorAbortsIf</a>{validator_account: account, operator_addr: operator_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_SetOperatorEnsures">ValidatorConfig::SetOperatorEnsures</a>{validator_account: account, operator_addr: operator_account};
</code></pre>


Reports INVALID_STATE because of !exists<DiemSystem::CapabilityHolder>, but that can't happen
because CapabilityHolder is published during initialization (Genesis).


<pre><code><b>aborts_with</b> [check]
    0, // Odd error code in <b>assert</b> on second statement in add_validator_and_reconfigure
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
</code></pre>


**Access Control:**
Only a Validator account can set its Validator Operator [[H16]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotValidator">Roles::AbortsIfNotValidator</a>{validator_addr: account_addr};
</code></pre>



</details>

<a name="0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin"></a>

##### Function `set_validator_operator_with_nonce_admin`


<a name="@Summary_172"></a>

###### Summary

Sets the validator operator for a validator in the validator's configuration resource "locally"
and does not reconfigure the system. Changes from this transaction will not picked up by the
system until a reconfiguration of the system is triggered. May only be sent by the Diem Root
account as a write set transaction.


<a name="@Technical_Description_173"></a>

###### Technical Description

Sets the account at <code>operator_account</code> address and with the specified <code>human_name</code> as an
operator for the validator <code>account</code>. The account at <code>operator_account</code> address must have a
Validator Operator role and have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource
published under it. The account represented by the <code>account</code> signer must be a Validator and
have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> resource published under it. No reconfiguration of
the system is initiated by this script.


<a name="@Parameters_174"></a>

###### Parameters

| Name               | Type         | Description                                                                                   |
| ------             | ------       | -------------                                                                                 |
| <code>dr_account</code>       | <code>signer</code>     | Signer of the sending account of the write set transaction. May only be the Diem Root signer. |
| <code>account</code>          | <code>signer</code>     | Signer of account specified in the <code>execute_as</code> field of the write set transaction.           |
| <code>sliding_nonce</code>    | <code>u64</code>        | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction for Diem Root.      |
| <code>operator_name</code>    | <code>vector&lt;u8&gt;</code> | Validator operator's human name.                                                              |
| <code>operator_account</code> | <code>address</code>    | Address of the validator operator account to be added as the <code>account</code> validator's operator.  |


<a name="@Common_Abort_Conditions_175"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                          | Description                                                                                                                                                  |
| ----------------           | --------------                                        | -------------                                                                                                                                                |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                        | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>dr_account</code>.                                                                                               |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                        | The <code>sliding_nonce</code> in <code>dr_account</code> is too old and it's impossible to determine if it's duplicated or not.                                                   |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                        | The <code>sliding_nonce</code> in <code>dr_account</code> is too far in the future.                                                                                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>               | The <code>sliding_nonce</code> in<code> dr_account</code> has been previously recorded.                                                                                            |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                        | The sending account is not the Diem Root account or Treasury Compliance account                                                                             |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_EVALIDATOR_OPERATOR_CONFIG">ValidatorOperatorConfig::EVALIDATOR_OPERATOR_CONFIG</a></code> | The <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource is not published under <code>operator_account</code>.                                                   |
| 0                          | 0                                                     | The <code>human_name</code> field of the <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource under <code>operator_account</code> does not match the provided <code>human_name</code>. |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EVALIDATOR">Roles::EVALIDATOR</a></code>                                   | <code>account</code> does not have a Validator account role.                                                                                                            |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ENOT_A_VALIDATOR_OPERATOR">ValidatorConfig::ENOT_A_VALIDATOR_OPERATOR</a></code>          | The account at <code>operator_account</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_ValidatorOperatorConfig">ValidatorOperatorConfig::ValidatorOperatorConfig</a></code> resource.                                               |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_EVALIDATOR_CONFIG">ValidatorConfig::EVALIDATOR_CONFIG</a></code>                  | A <code><a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_ValidatorConfig">ValidatorConfig::ValidatorConfig</a></code> is not published under <code>account</code>.                                                                                       |


<a name="@Related_Scripts_176"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_account">AccountCreationScripts::create_validator_account</a></code>
* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_validator_operator_account">AccountCreationScripts::create_validator_operator_account</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_register_validator_config">ValidatorAdministrationScripts::register_validator_config</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_remove_validator_and_reconfigure">ValidatorAdministrationScripts::remove_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_add_validator_and_reconfigure">ValidatorAdministrationScripts::add_validator_and_reconfigure</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator">ValidatorAdministrationScripts::set_validator_operator</a></code>
* <code><a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_config_and_reconfigure">ValidatorAdministrationScripts::set_validator_config_and_reconfigure</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">set_validator_operator_with_nonce_admin</a>(dr_account: signer, account: signer, sliding_nonce: u64, operator_name: vector&lt;u8&gt;, operator_account: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_ValidatorAdministrationScripts_set_validator_operator_with_nonce_admin">set_validator_operator_with_nonce_admin</a>(
    dr_account: signer,
    account: signer,
    sliding_nonce: u64,
    operator_name: vector&lt;u8&gt;,
    operator_account: address
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <b>assert</b>(<a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_get_human_name">ValidatorOperatorConfig::get_human_name</a>(operator_account) == operator_name, 0);
    <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_set_operator">ValidatorConfig::set_operator</a>(&account, operator_account);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>let</b> account_addr = <a href="_address_of">Signer::address_of</a>(account);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{seq_nonce: sliding_nonce, account: dr_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_AbortsIfNoValidatorConfig">ValidatorConfig::AbortsIfNoValidatorConfig</a>{addr: account_addr};
<b>aborts_if</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig_get_human_name">ValidatorOperatorConfig::get_human_name</a>(operator_account) != operator_name <b>with</b> 0;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_SetOperatorAbortsIf">ValidatorConfig::SetOperatorAbortsIf</a>{validator_account: account, operator_addr: operator_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig_SetOperatorEnsures">ValidatorConfig::SetOperatorEnsures</a>{validator_account: account, operator_addr: operator_account};
<b>aborts_with</b> [check]
    0, // Odd error code in <b>assert</b> on second statement in add_validator_and_reconfigure
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
</code></pre>


**Access Control:**
Only the Diem Root account can process the admin scripts [[H9]][PERMISSION].


<pre><code><b>requires</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_has_diem_root_role">Roles::has_diem_root_role</a>(dr_account);
</code></pre>


This is ensured by DiemAccount::writeset_prologue.
Only a Validator account can set its Validator Operator [[H16]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotValidator">Roles::AbortsIfNotValidator</a>{validator_addr: account_addr};
</code></pre>



</details>


---

<a name="@Treasury_and_Compliance_Operations_177"></a>

### Treasury and Compliance Operations



<a name="0x1_TreasuryComplianceScripts"></a>

#### Module `0x1::TreasuryComplianceScripts`

This module holds scripts relating to treasury and compliance-related
activities in the Diem Framework.

Only accounts with a role of <code>Roles::TREASURY_COMPLIANCE</code> and
<code>Roles::DESIGNATED_DEALER</code> can (successfully) use the scripts in this
module. The exact role required for a transaction is determined on a
per-transaction basis.


<pre><code><b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing">0x1::AccountFreezing</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem">0x1::Diem</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount">0x1::DiemAccount</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation">0x1::DualAttestation</a>;
<b>use</b> <a href="">0x1::FixedPoint32</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/TransactionFee.md#0x1_TransactionFee">0x1::TransactionFee</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain">0x1::VASPDomain</a>;
</code></pre>



<a name="0x1_TreasuryComplianceScripts_cancel_burn_with_amount"></a>

##### Function `cancel_burn_with_amount`


<a name="@Summary_178"></a>

###### Summary

Cancels and returns the coins held in the preburn area under
<code>preburn_address</code>, which are equal to the <code>amount</code> specified in the transaction. Finds the first preburn
resource with the matching amount and returns the funds to the <code>preburn_address</code>'s balance.
Can only be successfully sent by an account with Treasury Compliance role.


<a name="@Technical_Description_179"></a>

###### Technical Description

Cancels and returns all coins held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource under the <code>preburn_address</code> and
return the funds to the <code>preburn_address</code> account's <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Token&gt;</code>.
The transaction must be sent by an <code>account</code> with a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code>
resource published under it. The account at <code>preburn_address</code> must have a
<code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource published under it, and its value must be nonzero. The transaction removes
the entire balance held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource, and returns it back to the account's
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Token&gt;</code> under <code>preburn_address</code>. Due to this, the account at
<code>preburn_address</code> must already have a balance in the <code>Token</code> currency published
before this script is called otherwise the transaction will fail.


<a name="@Events_180"></a>

###### Events

The successful execution of this transaction will emit:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CancelBurnEvent">Diem::CancelBurnEvent</a></code> on the event handle held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;</code>
resource's <code>burn_events</code> published under <code>0xA550C18</code>.
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ReceivedPaymentEvent">DiemAccount::ReceivedPaymentEvent</a></code> on the <code>preburn_address</code>'s
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>received_events</code> event handle with both the <code>payer</code> and <code>payee</code>
being <code>preburn_address</code>.


<a name="@Parameters_181"></a>

###### Parameters

| Name              | Type      | Description                                                                                                                          |
| ------            | ------    | -------------                                                                                                                        |
| <code>Token</code>           | Type      | The Move type for the <code>Token</code> currenty that burning is being cancelled for. <code>Token</code> must be an already-registered currency on-chain. |
| <code>account</code>         | <code>signer</code>  | The signer of the sending account of this transaction, must have a burn capability for <code>Token</code> published under it.                   |
| <code>preburn_address</code> | <code>address</code> | The address where the coins to-be-burned are currently held.                                                                         |
| <code>amount</code>          | <code>u64</code>     | The amount to be cancelled.                                                                                                          |


<a name="@Common_Abort_Conditions_182"></a>

###### Common Abort Conditions

| Error Category                | Error Reason                                     | Description                                                                                                                         |
| ----------------              | --------------                                   | -------------                                                                                                                       |
| <code><a href="_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EBURN_CAPABILITY">Diem::EBURN_CAPABILITY</a></code>                         | The sending <code>account</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code> published under it.                                             |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EPREBURN_NOT_FOUND">Diem::EPREBURN_NOT_FOUND</a></code>                       | The <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource under <code>preburn_address</code> does not contain a preburn request with a value matching <code>amount</code>. |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EPREBURN_QUEUE">Diem::EPREBURN_QUEUE</a></code>                           | The account at <code>preburn_address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource published under it.                           |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                           | The specified <code>Token</code> is not a registered currency on-chain.                                                                        |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYEE_CANT_ACCEPT_CURRENCY_TYPE">DiemAccount::EPAYEE_CANT_ACCEPT_CURRENCY_TYPE</a></code>  | The account at <code>preburn_address</code> doesn't have a balance resource for <code>Token</code>.                                                       |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>      | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>           | The depositing of the funds held in the prebun area would exceed the <code>account</code>'s account limits.                                    |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_EPAYEE_COMPLIANCE_KEY_NOT_SET">DualAttestation::EPAYEE_COMPLIANCE_KEY_NOT_SET</a></code> | The <code>account</code> does not have a compliance key set on it but dual attestion checking was performed.                                   |


<a name="@Related_Scripts_183"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_txn_fees">TreasuryComplianceScripts::burn_txn_fees</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_with_amount">TreasuryComplianceScripts::burn_with_amount</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_preburn">TreasuryComplianceScripts::preburn</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">cancel_burn_with_amount</a>&lt;Token&gt;(account: signer, preburn_address: address, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">cancel_burn_with_amount</a>&lt;Token&gt;(account: signer, preburn_address: address, amount: u64) {
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_cancel_burn">DiemAccount::cancel_burn</a>&lt;Token&gt;(&account, preburn_address, amount)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_CancelBurnAbortsIf">DiemAccount::CancelBurnAbortsIf</a>&lt;Token&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CancelBurnWithCapEnsures">Diem::CancelBurnWithCapEnsures</a>&lt;Token&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DepositEnsures">DiemAccount::DepositEnsures</a>&lt;Token&gt;{payee: preburn_address};
<b>let</b> total_preburn_value = <b>global</b>&lt;<a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;&gt;(
    @CurrencyInfo
).preburn_value;
<b>let</b> post post_total_preburn_value = <b>global</b>&lt;<a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;&gt;(
    @CurrencyInfo
).preburn_value;
<b>let</b> balance_at_addr = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Token&gt;(preburn_address);
<b>let</b> post post_balance_at_addr = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_balance">DiemAccount::balance</a>&lt;Token&gt;(preburn_address);
</code></pre>


The total value of preburn for <code>Token</code> should decrease by the preburned amount.


<pre><code><b>ensures</b> post_total_preburn_value == total_preburn_value - amount;
</code></pre>


The balance of <code>Token</code> at <code>preburn_address</code> should increase by the preburned amount.


<pre><code><b>ensures</b> post_balance_at_addr == balance_at_addr + amount;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CancelBurnWithCapEmits">Diem::CancelBurnWithCapEmits</a>&lt;Token&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DepositEmits">DiemAccount::DepositEmits</a>&lt;Token&gt;{
    payer: preburn_address,
    payee: preburn_address,
    amount: amount,
    metadata: x""
};
<b>aborts_with</b> [check]
    <a href="_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>;
</code></pre>


**Access Control:**
Only the account with the burn capability can cancel burning [[H3]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_AbortsIfNoBurnCapability">Diem::AbortsIfNoBurnCapability</a>&lt;Token&gt;{account: account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_burn_with_amount"></a>

##### Function `burn_with_amount`


<a name="@Summary_184"></a>

###### Summary

Burns the coins held in a preburn resource in the preburn queue at the
specified preburn address, which are equal to the <code>amount</code> specified in the
transaction. Finds the first relevant outstanding preburn request with
matching amount and removes the contained coins from the system. The sending
account must be the Treasury Compliance account.
The account that holds the preburn queue resource will normally be a Designated
Dealer, but there are no enforced requirements that it be one.


<a name="@Technical_Description_185"></a>

###### Technical Description

This transaction permanently destroys all the coins of <code>Token</code> type
stored in the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource published under the
<code>preburn_address</code> account address.

This transaction will only succeed if the sending <code>account</code> has a
<code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code>, and a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource
exists under <code>preburn_address</code>, with a non-zero <code>to_burn</code> field. After the successful execution
of this transaction the <code>total_value</code> field in the
<code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;</code> resource published under <code>0xA550C18</code> will be
decremented by the value of the <code>to_burn</code> field of the preburn resource
under <code>preburn_address</code> immediately before this transaction, and the
<code>to_burn</code> field of the preburn resource will have a zero value.


<a name="@Events_186"></a>

###### Events

The successful execution of this transaction will emit a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnEvent">Diem::BurnEvent</a></code> on the event handle
held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token&gt;</code> resource's <code>burn_events</code> published under
<code>0xA550C18</code>.


<a name="@Parameters_187"></a>

###### Parameters

| Name              | Type      | Description                                                                                                        |
| ------            | ------    | -------------                                                                                                      |
| <code>Token</code>           | Type      | The Move type for the <code>Token</code> currency being burned. <code>Token</code> must be an already-registered currency on-chain.      |
| <code>tc_account</code>      | <code>signer</code>  | The signer of the sending account of this transaction, must have a burn capability for <code>Token</code> published under it. |
| <code>sliding_nonce</code>   | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                         |
| <code>preburn_address</code> | <code>address</code> | The address where the coins to-be-burned are currently held.                                                       |
| <code>amount</code>          | <code>u64</code>     | The amount to be burned.                                                                                           |


<a name="@Common_Abort_Conditions_188"></a>

###### Common Abort Conditions

| Error Category                | Error Reason                            | Description                                                                                                                         |
| ----------------              | --------------                          | -------------                                                                                                                       |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                                                         |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not.                                          |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                                                                       |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                                                                   |
| <code><a href="_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EBURN_CAPABILITY">Diem::EBURN_CAPABILITY</a></code>                | The sending <code>account</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnCapability">Diem::BurnCapability</a>&lt;Token&gt;</code> published under it.                                             |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EPREBURN_NOT_FOUND">Diem::EPREBURN_NOT_FOUND</a></code>              | The <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource under <code>preburn_address</code> does not contain a preburn request with a value matching <code>amount</code>. |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EPREBURN_QUEUE">Diem::EPREBURN_QUEUE</a></code>                  | The account at <code>preburn_address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;</code> resource published under it.                           |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                  | The specified <code>Token</code> is not a registered currency on-chain.                                                                        |


<a name="@Related_Scripts_189"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_txn_fees">TreasuryComplianceScripts::burn_txn_fees</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">TreasuryComplianceScripts::cancel_burn_with_amount</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_preburn">TreasuryComplianceScripts::preburn</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_with_amount">burn_with_amount</a>&lt;Token&gt;(account: signer, sliding_nonce: u64, preburn_address: address, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_with_amount">burn_with_amount</a>&lt;Token&gt;(account: signer, sliding_nonce: u64, preburn_address: address, amount: u64) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_burn">Diem::burn</a>&lt;Token&gt;(&account, preburn_address, amount)
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ seq_nonce: sliding_nonce };
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnAbortsIf">Diem::BurnAbortsIf</a>&lt;Token&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnEnsures">Diem::BurnEnsures</a>&lt;Token&gt;;
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnWithResourceCapEmits">Diem::BurnWithResourceCapEmits</a>&lt;Token&gt;{preburn: <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_spec_make_preburn">Diem::spec_make_preburn</a>(amount)};
</code></pre>


**Access Control:**
Only the account with the burn capability can burn coins [[H3]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_AbortsIfNoBurnCapability">Diem::AbortsIfNoBurnCapability</a>&lt;Token&gt;{account: account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_preburn"></a>

##### Function `preburn`


<a name="@Summary_190"></a>

###### Summary

Moves a specified number of coins in a given currency from the account's
balance to its preburn area after which the coins may be burned. This
transaction may be sent by any account that holds a balance and preburn area
in the specified currency.


<a name="@Technical_Description_191"></a>

###### Technical Description

Moves the specified <code>amount</code> of coins in <code>Token</code> currency from the sending <code>account</code>'s
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_Balance">DiemAccount::Balance</a>&lt;Token&gt;</code> to the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> published under the same
<code>account</code>. <code>account</code> must have both of these resources published under it at the start of this
transaction in order for it to execute successfully.


<a name="@Events_192"></a>

###### Events

Successful execution of this script emits two events:
* <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_SentPaymentEvent">DiemAccount::SentPaymentEvent</a> </code> on <code>account</code>'s <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_DiemAccount">DiemAccount::DiemAccount</a></code> <code>sent_events</code>
handle with the <code>payee</code> and <code>payer</code> fields being <code>account</code>'s address; and
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_PreburnEvent">Diem::PreburnEvent</a></code> with <code>Token</code>'s currency code on the
<code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Token</code>'s <code>preburn_events</code> handle for <code>Token</code> and with
<code>preburn_address</code> set to <code>account</code>'s address.


<a name="@Parameters_193"></a>

###### Parameters

| Name      | Type     | Description                                                                                                                      |
| ------    | ------   | -------------                                                                                                                    |
| <code>Token</code>   | Type     | The Move type for the <code>Token</code> currency being moved to the preburn area. <code>Token</code> must be an already-registered currency on-chain. |
| <code>account</code> | <code>signer</code> | The signer of the sending account.                                                                                               |
| <code>amount</code>  | <code>u64</code>    | The amount in <code>Token</code> to be moved to the preburn area.                                                                           |


<a name="@Common_Abort_Conditions_194"></a>

###### Common Abort Conditions

| Error Category           | Error Reason                                             | Description                                                                             |
| ----------------         | --------------                                           | -------------                                                                           |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>                                  | The <code>Token</code> is not a registered currency on-chain.                                      |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>  | <code>DiemAccount::EWITHDRAWAL_CAPABILITY_ALREADY_EXTRACTED</code> | The withdrawal capability for <code>account</code> has already been extracted.                     |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EINSUFFICIENT_BALANCE">DiemAccount::EINSUFFICIENT_BALANCE</a></code>                    | <code>amount</code> is greater than <code>payer</code>'s balance in <code>Token</code>.                                  |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EPAYER_DOESNT_HOLD_CURRENCY">DiemAccount::EPAYER_DOESNT_HOLD_CURRENCY</a></code>              | <code>account</code> doesn't hold a balance in <code>Token</code>.                                            |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EPREBURN">Diem::EPREBURN</a></code>                                        | <code>account</code> doesn't have a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource published under it.           |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EPREBURN_OCCUPIED">Diem::EPREBURN_OCCUPIED</a></code>                               | The <code>value</code> field in the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;</code> resource under the sender is non-zero. |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EROLE_ID">Roles::EROLE_ID</a></code>                                        | The <code>account</code> did not have a role assigned to it.                                       |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>  | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_EDESIGNATED_DEALER">Roles::EDESIGNATED_DEALER</a></code>                              | The <code>account</code> did not have the role of DesignatedDealer.                                |


<a name="@Related_Scripts_195"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">TreasuryComplianceScripts::cancel_burn_with_amount</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_with_amount">TreasuryComplianceScripts::burn_with_amount</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_txn_fees">TreasuryComplianceScripts::burn_txn_fees</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_preburn">preburn</a>&lt;Token&gt;(account: signer, amount: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_preburn">preburn</a>&lt;Token&gt;(account: signer, amount: u64) {
    <b>let</b> withdraw_cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_extract_withdraw_capability">DiemAccount::extract_withdraw_capability</a>(&account);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_preburn">DiemAccount::preburn</a>&lt;Token&gt;(&account, &withdraw_cap, amount);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_restore_withdraw_capability">DiemAccount::restore_withdraw_capability</a>(withdraw_cap);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: account};
<b>let</b> account_addr = <a href="_spec_address_of">Signer::spec_address_of</a>(account);
<b>let</b> cap = <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_spec_get_withdraw_cap">DiemAccount::spec_get_withdraw_cap</a>(account_addr);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_ExtractWithdrawCapAbortsIf">DiemAccount::ExtractWithdrawCapAbortsIf</a>{sender_addr: account_addr};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_PreburnAbortsIf">DiemAccount::PreburnAbortsIf</a>&lt;Token&gt;{dd: account, cap: cap};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_PreburnEnsures">DiemAccount::PreburnEnsures</a>&lt;Token&gt;{dd: account, payer: account_addr};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_PreburnEmits">DiemAccount::PreburnEmits</a>&lt;Token&gt;{dd: account, cap: cap};
<b>aborts_with</b> [check]
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>;
</code></pre>


**Access Control:**
Only the account with a Preburn resource or PreburnQueue resource can preburn [[H4]][PERMISSION].


<pre><code><b>aborts_if</b> !(<b>exists</b>&lt;<a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_Preburn">Diem::Preburn</a>&lt;Token&gt;&gt;(account_addr) || <b>exists</b>&lt;<a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_PreburnQueue">Diem::PreburnQueue</a>&lt;Token&gt;&gt;(account_addr));
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_burn_txn_fees"></a>

##### Function `burn_txn_fees`


<a name="@Summary_196"></a>

###### Summary

Burns the transaction fees collected in the <code>CoinType</code> currency so that the
Diem association may reclaim the backing coins off-chain. May only be sent
by the Treasury Compliance account.


<a name="@Technical_Description_197"></a>

###### Technical Description

Burns the transaction fees collected in <code>CoinType</code> so that the
association may reclaim the backing coins. Once this transaction has executed
successfully all transaction fees that will have been collected in
<code>CoinType</code> since the last time this script was called with that specific
currency. Both <code>balance</code> and <code>preburn</code> fields in the
<code><a href="../../../../../releases/artifacts/current/docs/modules/TransactionFee.md#0x1_TransactionFee_TransactionFee">TransactionFee::TransactionFee</a>&lt;CoinType&gt;</code> resource published under the <code>0xB1E55ED</code>
account address will have a value of 0 after the successful execution of this script.


<a name="@Events_198"></a>

###### Events

The successful execution of this transaction will emit a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_BurnEvent">Diem::BurnEvent</a></code> on the event handle
held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;CoinType&gt;</code> resource's <code>burn_events</code> published under
<code>0xA550C18</code>.


<a name="@Parameters_199"></a>

###### Parameters

| Name         | Type     | Description                                                                                                                                         |
| ------       | ------   | -------------                                                                                                                                       |
| <code>CoinType</code>   | Type     | The Move type for the <code>CoinType</code> being added to the sending account of the transaction. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>tc_account</code> | <code>signer</code> | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                                     |


<a name="@Common_Abort_Conditions_200"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                          | Description                                                 |
| ----------------           | --------------                        | -------------                                               |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code> | The sending account is not the Treasury Compliance account. |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/TransactionFee.md#0x1_TransactionFee_ETRANSACTION_FEE">TransactionFee::ETRANSACTION_FEE</a></code>    | <code>CoinType</code> is not an accepted transaction fee currency.     |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECOIN">Diem::ECOIN</a></code>                        | The collected fees in <code>CoinType</code> are zero.                  |


<a name="@Related_Scripts_201"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_with_amount">TreasuryComplianceScripts::burn_with_amount</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_cancel_burn_with_amount">TreasuryComplianceScripts::cancel_burn_with_amount</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_txn_fees">burn_txn_fees</a>&lt;CoinType&gt;(tc_account: signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_burn_txn_fees">burn_txn_fees</a>&lt;CoinType&gt;(tc_account: signer) {
    <a href="../../../../../releases/artifacts/current/docs/modules/TransactionFee.md#0x1_TransactionFee_burn_fees">TransactionFee::burn_fees</a>&lt;CoinType&gt;(&tc_account);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_tiered_mint"></a>

##### Function `tiered_mint`


<a name="@Summary_202"></a>

###### Summary

Mints a specified number of coins in a currency to a Designated Dealer. The sending account
must be the Treasury Compliance account, and coins can only be minted to a Designated Dealer
account.


<a name="@Technical_Description_203"></a>

###### Technical Description

Mints <code>mint_amount</code> of coins in the <code>CoinType</code> currency to Designated Dealer account at
<code>designated_dealer_address</code>. The <code>tier_index</code> parameter specifies which tier should be used to
check verify the off-chain approval policy, and is based in part on the on-chain tier values
for the specific Designated Dealer, and the number of <code>CoinType</code> coins that have been minted to
the dealer over the past 24 hours. Every Designated Dealer has 4 tiers for each currency that
they support. The sending <code>tc_account</code> must be the Treasury Compliance account, and the
receiver an authorized Designated Dealer account.


<a name="@Events_204"></a>

###### Events

Successful execution of the transaction will emit two events:
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_MintEvent">Diem::MintEvent</a></code> with the amount and currency code minted is emitted on the
<code>mint_event_handle</code> in the stored <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;CoinType&gt;</code> resource stored under
<code>0xA550C18</code>; and
* A <code><a href="../../../../../releases/artifacts/current/docs/modules/DesignatedDealer.md#0x1_DesignatedDealer_ReceivedMintEvent">DesignatedDealer::ReceivedMintEvent</a></code> with the amount, currency code, and Designated
Dealer's address is emitted on the <code>mint_event_handle</code> in the stored <code><a href="../../../../../releases/artifacts/current/docs/modules/DesignatedDealer.md#0x1_DesignatedDealer_Dealer">DesignatedDealer::Dealer</a></code>
resource published under the <code>designated_dealer_address</code>.


<a name="@Parameters_205"></a>

###### Parameters

| Name                        | Type      | Description                                                                                                |
| ------                      | ------    | -------------                                                                                              |
| <code>CoinType</code>                  | Type      | The Move type for the <code>CoinType</code> being minted. <code>CoinType</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>                | <code>signer</code>  | The signer of the sending account of this transaction. Must be the Treasury Compliance account.            |
| <code>sliding_nonce</code>             | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                                 |
| <code>designated_dealer_address</code> | <code>address</code> | The address of the Designated Dealer account being minted to.                                              |
| <code>mint_amount</code>               | <code>u64</code>     | The number of coins to be minted.                                                                          |
| <code>tier_index</code>                | <code>u64</code>     | [Deprecated] The mint tier index to use for the Designated Dealer account. Will be ignored                 |


<a name="@Common_Abort_Conditions_206"></a>

###### Common Abort Conditions

| Error Category                | Error Reason                                 | Description                                                                                                                  |
| ----------------              | --------------                               | -------------                                                                                                                |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>               | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                                                               |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>               | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not.                                   |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>               | The <code>sliding_nonce</code> is too far in the future.                                                                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>      | The <code>sliding_nonce</code> has been previously recorded.                                                                            |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>        | <code>tc_account</code> is not the Treasury Compliance account.                                                                         |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>                | <code>tc_account</code> is not the Treasury Compliance account.                                                                         |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/DesignatedDealer.md#0x1_DesignatedDealer_EINVALID_MINT_AMOUNT">DesignatedDealer::EINVALID_MINT_AMOUNT</a></code>     | <code>mint_amount</code> is zero.                                                                                                       |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/DesignatedDealer.md#0x1_DesignatedDealer_EDEALER">DesignatedDealer::EDEALER</a></code>                  | <code><a href="../../../../../releases/artifacts/current/docs/modules/DesignatedDealer.md#0x1_DesignatedDealer_Dealer">DesignatedDealer::Dealer</a></code> or <code><a href="../../../../../releases/artifacts/current/docs/modules/DesignatedDealer.md#0x1_DesignatedDealer_TierInfo">DesignatedDealer::TierInfo</a>&lt;CoinType&gt;</code> resource does not exist at <code>designated_dealer_address</code>. |
| <code><a href="_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EMINT_CAPABILITY">Diem::EMINT_CAPABILITY</a></code>                    | <code>tc_account</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_MintCapability">Diem::MintCapability</a>&lt;CoinType&gt;</code> resource published under it.                                  |
| <code><a href="_INVALID_STATE">Errors::INVALID_STATE</a></code>       | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_EMINTING_NOT_ALLOWED">Diem::EMINTING_NOT_ALLOWED</a></code>                | Minting is not currently allowed for <code>CoinType</code> coins.                                                                       |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>      | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_EDEPOSIT_EXCEEDS_LIMITS">DiemAccount::EDEPOSIT_EXCEEDS_LIMITS</a></code>      | The depositing of the funds would exceed the <code>account</code>'s account limits.                                                     |


<a name="@Related_Scripts_207"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_AccountCreationScripts_create_designated_dealer">AccountCreationScripts::create_designated_dealer</a></code>
* <code><a href="script_documentation.md#0x1_PaymentScripts_peer_to_peer_with_metadata">PaymentScripts::peer_to_peer_with_metadata</a></code>
* <code><a href="script_documentation.md#0x1_AccountAdministrationScripts_rotate_dual_attestation_info">AccountAdministrationScripts::rotate_dual_attestation_info</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_tiered_mint">tiered_mint</a>&lt;CoinType&gt;(tc_account: signer, sliding_nonce: u64, designated_dealer_address: address, mint_amount: u64, tier_index: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_tiered_mint">tiered_mint</a>&lt;CoinType&gt;(
    tc_account: signer,
    sliding_nonce: u64,
    designated_dealer_address: address,
    mint_amount: u64,
    tier_index: u64
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_tiered_mint">DiemAccount::tiered_mint</a>&lt;CoinType&gt;(
        &tc_account, designated_dealer_address, mint_amount, tier_index
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{account: tc_account, seq_nonce: sliding_nonce};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TieredMintAbortsIf">DiemAccount::TieredMintAbortsIf</a>&lt;CoinType&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TieredMintEnsures">DiemAccount::TieredMintEnsures</a>&lt;CoinType&gt;;
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_REQUIRES_CAPABILITY">Errors::REQUIRES_CAPABILITY</a>,
    <a href="_INVALID_STATE">Errors::INVALID_STATE</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TieredMintEmits">DiemAccount::TieredMintEmits</a>&lt;CoinType&gt;;
</code></pre>


**Access Control:**
Only the Treasury Compliance account can mint [[H1]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_freeze_account"></a>

##### Function `freeze_account`


<a name="@Summary_208"></a>

###### Summary

Freezes the account at <code>address</code>. The sending account of this transaction
must be the Treasury Compliance account. The account being frozen cannot be
the Diem Root or Treasury Compliance account. After the successful
execution of this transaction no transactions may be sent from the frozen
account, and the frozen account may not send or receive coins.


<a name="@Technical_Description_209"></a>

###### Technical Description

Sets the <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_FreezingBit">AccountFreezing::FreezingBit</a></code> to <code><b>true</b></code> and emits a
<code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_FreezeAccountEvent">AccountFreezing::FreezeAccountEvent</a></code>. The transaction sender must be the
Treasury Compliance account, but the account at <code>to_freeze_account</code> must
not be either <code>0xA550C18</code> (the Diem Root address), or <code>0xB1E55ED</code> (the
Treasury Compliance address). Note that this is a per-account property
e.g., freezing a Parent VASP will not effect the status any of its child
accounts and vice versa.



<a name="@Events_210"></a>

###### Events

Successful execution of this transaction will emit a <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_FreezeAccountEvent">AccountFreezing::FreezeAccountEvent</a></code> on
the <code>freeze_event_handle</code> held in the <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_FreezeEventsHolder">AccountFreezing::FreezeEventsHolder</a></code> resource published
under <code>0xA550C18</code> with the <code>frozen_address</code> being the <code>to_freeze_account</code>.


<a name="@Parameters_211"></a>

###### Parameters

| Name                | Type      | Description                                                                                     |
| ------              | ------    | -------------                                                                                   |
| <code>tc_account</code>        | <code>signer</code>  | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>sliding_nonce</code>     | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                      |
| <code>to_freeze_account</code> | <code>address</code> | The account address to be frozen.                                                               |


<a name="@Common_Abort_Conditions_212"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                 | Description                                                                                |
| ----------------           | --------------                               | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>               | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>               | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>               | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>      | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>        | The sending account is not the Treasury Compliance account.                                |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>                | The sending account is not the Treasury Compliance account.                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_ECANNOT_FREEZE_TC">AccountFreezing::ECANNOT_FREEZE_TC</a></code>         | <code>to_freeze_account</code> was the Treasury Compliance account (<code>0xB1E55ED</code>).                     |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_ECANNOT_FREEZE_DIEM_ROOT">AccountFreezing::ECANNOT_FREEZE_DIEM_ROOT</a></code> | <code>to_freeze_account</code> was the Diem Root account (<code>0xA550C18</code>).                              |


<a name="@Related_Scripts_213"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_unfreeze_account">TreasuryComplianceScripts::unfreeze_account</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_freeze_account">freeze_account</a>(tc_account: signer, sliding_nonce: u64, to_freeze_account: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_freeze_account">freeze_account</a>(tc_account: signer, sliding_nonce: u64, to_freeze_account: address) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_freeze_account">AccountFreezing::freeze_account</a>(&tc_account, to_freeze_account);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_unfreeze_account"></a>

##### Function `unfreeze_account`


<a name="@Summary_214"></a>

###### Summary

Unfreezes the account at <code>address</code>. The sending account of this transaction must be the
Treasury Compliance account. After the successful execution of this transaction transactions
may be sent from the previously frozen account, and coins may be sent and received.


<a name="@Technical_Description_215"></a>

###### Technical Description

Sets the <code><a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_FreezingBit">AccountFreezing::FreezingBit</a></code> to <code><b>false</b></code> and emits a
<code>AccountFreezing::UnFreezeAccountEvent</code>. The transaction sender must be the Treasury Compliance
account. Note that this is a per-account property so unfreezing a Parent VASP will not effect
the status any of its child accounts and vice versa.


<a name="@Events_216"></a>

###### Events

Successful execution of this script will emit a <code>AccountFreezing::UnFreezeAccountEvent</code> with
the <code>unfrozen_address</code> set the <code>to_unfreeze_account</code>'s address.


<a name="@Parameters_217"></a>

###### Parameters

| Name                  | Type      | Description                                                                                     |
| ------                | ------    | -------------                                                                                   |
| <code>tc_account</code>          | <code>signer</code>  | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>sliding_nonce</code>       | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                      |
| <code>to_unfreeze_account</code> | <code>address</code> | The account address to be frozen.                                                               |


<a name="@Common_Abort_Conditions_218"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                            | Description                                                                                |
| ----------------           | --------------                          | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | The sending account is not the Treasury Compliance account.                                |


<a name="@Related_Scripts_219"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_freeze_account">TreasuryComplianceScripts::freeze_account</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_unfreeze_account">unfreeze_account</a>(account: signer, sliding_nonce: u64, to_unfreeze_account: address)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_unfreeze_account">unfreeze_account</a>(account: signer, sliding_nonce: u64, to_unfreeze_account: address) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing_unfreeze_account">AccountFreezing::unfreeze_account</a>(&account, to_unfreeze_account);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_update_dual_attestation_limit"></a>

##### Function `update_dual_attestation_limit`


<a name="@Summary_220"></a>

###### Summary

Update the dual attestation limit on-chain. Defined in terms of micro-XDX.  The transaction can
only be sent by the Treasury Compliance account.  After this transaction all inter-VASP
payments over this limit must be checked for dual attestation.


<a name="@Technical_Description_221"></a>

###### Technical Description

Updates the <code>micro_xdx_limit</code> field of the <code><a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_Limit">DualAttestation::Limit</a></code> resource published under
<code>0xA550C18</code>. The amount is set in micro-XDX.


<a name="@Parameters_222"></a>

###### Parameters

| Name                  | Type     | Description                                                                                     |
| ------                | ------   | -------------                                                                                   |
| <code>tc_account</code>          | <code>signer</code> | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>sliding_nonce</code>       | <code>u64</code>    | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                      |
| <code>new_micro_xdx_limit</code> | <code>u64</code>    | The new dual attestation limit to be used on-chain.                                             |


<a name="@Common_Abort_Conditions_223"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                            | Description                                                                                |
| ----------------           | --------------                          | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | <code>tc_account</code> is not the Treasury Compliance account.                                       |


<a name="@Related_Scripts_224"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_exchange_rate">TreasuryComplianceScripts::update_exchange_rate</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_minting_ability">TreasuryComplianceScripts::update_minting_ability</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">update_dual_attestation_limit</a>(tc_account: signer, sliding_nonce: u64, new_micro_xdx_limit: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">update_dual_attestation_limit</a>(
        tc_account: signer,
        sliding_nonce: u64,
        new_micro_xdx_limit: u64
    ) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation_set_microdiem_limit">DualAttestation::set_microdiem_limit</a>(&tc_account, new_micro_xdx_limit);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_update_exchange_rate"></a>

##### Function `update_exchange_rate`


<a name="@Summary_225"></a>

###### Summary

Update the rough on-chain exchange rate between a specified currency and XDX (as a conversion
to micro-XDX). The transaction can only be sent by the Treasury Compliance account. After this
transaction the updated exchange rate will be used for normalization of gas prices, and for
dual attestation checking.


<a name="@Technical_Description_226"></a>

###### Technical Description

Updates the on-chain exchange rate from the given <code>Currency</code> to micro-XDX.  The exchange rate
is given by <code>new_exchange_rate_numerator/new_exchange_rate_denominator</code>.


<a name="@Parameters_227"></a>

###### Parameters

| Name                            | Type     | Description                                                                                                                        |
| ------                          | ------   | -------------                                                                                                                      |
| <code>Currency</code>                      | Type     | The Move type for the <code>Currency</code> whose exchange rate is being updated. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>tc_account</code>                    | <code>signer</code> | The signer of the sending account of this transaction. Must be the Treasury Compliance account.                                    |
| <code>sliding_nonce</code>                 | <code>u64</code>    | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for the transaction.                                                          |
| <code>new_exchange_rate_numerator</code>   | <code>u64</code>    | The numerator for the new to micro-XDX exchange rate for <code>Currency</code>.                                                               |
| <code>new_exchange_rate_denominator</code> | <code>u64</code>    | The denominator for the new to micro-XDX exchange rate for <code>Currency</code>.                                                             |


<a name="@Common_Abort_Conditions_228"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                            | Description                                                                                |
| ----------------           | --------------                          | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>          | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>tc_account</code>.                             |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>          | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>          | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code> | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>   | <code>tc_account</code> is not the Treasury Compliance account.                                       |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>           | <code>tc_account</code> is not the Treasury Compliance account.                                       |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="_EDENOMINATOR">FixedPoint32::EDENOMINATOR</a></code>            | <code>new_exchange_rate_denominator</code> is zero.                                                   |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="_ERATIO_OUT_OF_RANGE">FixedPoint32::ERATIO_OUT_OF_RANGE</a></code>     | The quotient is unrepresentable as a <code><a href="">FixedPoint32</a></code>.                                       |
| <code><a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a></code>   | <code><a href="_ERATIO_OUT_OF_RANGE">FixedPoint32::ERATIO_OUT_OF_RANGE</a></code>     | The quotient is unrepresentable as a <code><a href="">FixedPoint32</a></code>.                                       |


<a name="@Related_Scripts_229"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">TreasuryComplianceScripts::update_dual_attestation_limit</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_minting_ability">TreasuryComplianceScripts::update_minting_ability</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_exchange_rate">update_exchange_rate</a>&lt;Currency&gt;(tc_account: signer, sliding_nonce: u64, new_exchange_rate_numerator: u64, new_exchange_rate_denominator: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_exchange_rate">update_exchange_rate</a>&lt;Currency&gt;(
        tc_account: signer,
        sliding_nonce: u64,
        new_exchange_rate_numerator: u64,
        new_exchange_rate_denominator: u64,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&tc_account, sliding_nonce);
    <b>let</b> rate = <a href="_create_from_rational">FixedPoint32::create_from_rational</a>(
            new_exchange_rate_numerator,
            new_exchange_rate_denominator,
    );
    <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_update_xdx_exchange_rate">Diem::update_xdx_exchange_rate</a>&lt;Currency&gt;(&tc_account, rate);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_RecordNonceAbortsIf">SlidingNonce::RecordNonceAbortsIf</a>{ account: tc_account, seq_nonce: sliding_nonce };
<b>include</b> <a href="_CreateFromRationalAbortsIf">FixedPoint32::CreateFromRationalAbortsIf</a>{
       numerator: new_exchange_rate_numerator,
       denominator: new_exchange_rate_denominator
};
<b>let</b> rate = <a href="_spec_create_from_rational">FixedPoint32::spec_create_from_rational</a>(
        new_exchange_rate_numerator,
        new_exchange_rate_denominator
);
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_UpdateXDXExchangeRateAbortsIf">Diem::UpdateXDXExchangeRateAbortsIf</a>&lt;Currency&gt;;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_UpdateXDXExchangeRateEnsures">Diem::UpdateXDXExchangeRateEnsures</a>&lt;Currency&gt;{xdx_exchange_rate: rate};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_UpdateXDXExchangeRateEmits">Diem::UpdateXDXExchangeRateEmits</a>&lt;Currency&gt;{xdx_exchange_rate: rate};
<b>aborts_with</b> [check]
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_LIMIT_EXCEEDED">Errors::LIMIT_EXCEEDED</a>,
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>;
</code></pre>


**Access Control:**
Only the Treasury Compliance account can update the exchange rate [[H5]][PERMISSION].


<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_AbortsIfNotTreasuryCompliance">Roles::AbortsIfNotTreasuryCompliance</a>{account: tc_account};
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_update_minting_ability"></a>

##### Function `update_minting_ability`


<a name="@Summary_230"></a>

###### Summary

Script to allow or disallow minting of new coins in a specified currency.  This transaction can
only be sent by the Treasury Compliance account.  Turning minting off for a currency will have
no effect on coins already in circulation, and coins may still be removed from the system.


<a name="@Technical_Description_231"></a>

###### Technical Description

This transaction sets the <code>can_mint</code> field of the <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_CurrencyInfo">Diem::CurrencyInfo</a>&lt;Currency&gt;</code> resource
published under <code>0xA550C18</code> to the value of <code>allow_minting</code>. Minting of coins if allowed if
this field is set to <code><b>true</b></code> and minting of new coins in <code>Currency</code> is disallowed otherwise.
This transaction needs to be sent by the Treasury Compliance account.


<a name="@Parameters_232"></a>

###### Parameters

| Name            | Type     | Description                                                                                                                          |
| ------          | ------   | -------------                                                                                                                        |
| <code>Currency</code>      | Type     | The Move type for the <code>Currency</code> whose minting ability is being updated. <code>Currency</code> must be an already-registered currency on-chain. |
| <code>account</code>       | <code>signer</code> | Signer of the sending account. Must be the Diem Root account.                                                                        |
| <code>allow_minting</code> | <code>bool</code>   | Whether to allow minting of new coins in <code>Currency</code>.                                                                                 |


<a name="@Common_Abort_Conditions_233"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                          | Description                                          |
| ----------------           | --------------                        | -------------                                        |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code> | <code>tc_account</code> is not the Treasury Compliance account. |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_ECURRENCY_INFO">Diem::ECURRENCY_INFO</a></code>               | <code>Currency</code> is not a registered currency on-chain.    |


<a name="@Related_Scripts_234"></a>

###### Related Scripts

* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_dual_attestation_limit">TreasuryComplianceScripts::update_dual_attestation_limit</a></code>
* <code><a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_exchange_rate">TreasuryComplianceScripts::update_exchange_rate</a></code>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_minting_ability">update_minting_ability</a>&lt;Currency&gt;(tc_account: signer, allow_minting: bool)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_update_minting_ability">update_minting_ability</a>&lt;Currency&gt;(
    tc_account: signer,
    allow_minting: bool
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem_update_minting_ability">Diem::update_minting_ability</a>&lt;Currency&gt;(&tc_account, allow_minting);
}
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_add_vasp_domain"></a>

##### Function `add_vasp_domain`


<a name="@Summary_235"></a>

###### Summary

Add a VASP domain to parent VASP account. The transaction can only be sent by
the Treasury Compliance account.


<a name="@Technical_Description_236"></a>

###### Technical Description

Adds a <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code> to the <code>domains</code> field of the <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under
the account at <code>address</code>.


<a name="@Parameters_237"></a>

###### Parameters

| Name         | Type         | Description                                                                                     |
| ------       | ------       | -------------                                                                                   |
| <code>tc_account</code> | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>address</code>    | <code>address</code>    | The <code>address</code> of the parent VASP account that will have have <code>domain</code> added to its domains.     |
| <code>domain</code>     | <code>vector&lt;u8&gt;</code> | The domain to be added.                                                                         |


<a name="@Common_Abort_Conditions_238"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                             | Description                                                                                                                            |
| ----------------           | --------------                           | -------------                                                                                                                          |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>            | The sending account is not the Treasury Compliance account.                                                                            |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>    | <code>tc_account</code> is not the Treasury Compliance account.                                                                                   |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">VASPDomain::EVASP_DOMAIN_MANAGER</a></code>        | The <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomain::VASPDomainManager</a></code> resource is not yet published under the Treasury Compliance account.                                 |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">VASPDomain::EVASP_DOMAINS_NOT_PUBLISHED</a></code> | <code>address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under it.                                                         |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code>VASPDomain::EDOMAIN_ALREADY_EXISTS</code>         | The <code>domain</code> already exists in the list of <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code>s  in the <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under <code>address</code>. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EINVALID_VASP_DOMAIN">VASPDomain::EINVALID_VASP_DOMAIN</a></code>        | The <code>domain</code> is greater in length than <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">VASPDomain::DOMAIN_LENGTH</a></code>.                                                                        |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_add_vasp_domain">add_vasp_domain</a>(tc_account: signer, address: address, domain: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_add_vasp_domain">add_vasp_domain</a> (
    tc_account: signer,
    address: address,
    domain: vector&lt;u8&gt;,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_add_vasp_domain">VASPDomain::add_vasp_domain</a>(&tc_account, address, domain);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount_TransactionChecks">DiemAccount::TransactionChecks</a>{sender: tc_account};
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_AddVASPDomainAbortsIf">VASPDomain::AddVASPDomainAbortsIf</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_AddVASPDomainEnsures">VASPDomain::AddVASPDomainEnsures</a>;
<b>include</b> <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_AddVASPDomainEmits">VASPDomain::AddVASPDomainEmits</a>;
<b>aborts_with</b> [check]
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>

<a name="0x1_TreasuryComplianceScripts_remove_vasp_domain"></a>

##### Function `remove_vasp_domain`


<a name="@Summary_239"></a>

###### Summary

Remove a VASP domain from parent VASP account. The transaction can only be sent by
the Treasury Compliance account.


<a name="@Technical_Description_240"></a>

###### Technical Description

Removes a <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code> from the <code>domains</code> field of the <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under
account with <code>address</code>.


<a name="@Parameters_241"></a>

###### Parameters

| Name         | Type         | Description                                                                                     |
| ------       | ------       | -------------                                                                                   |
| <code>tc_account</code> | <code>signer</code>     | The signer of the sending account of this transaction. Must be the Treasury Compliance account. |
| <code>address</code>    | <code>address</code>    | The <code>address</code> of parent VASP account that will update its domains.                              |
| <code>domain</code>     | <code>vector&lt;u8&gt;</code> | The domain name.                                                                                |


<a name="@Common_Abort_Conditions_242"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                             | Description                                                                                                                            |
| ----------------           | --------------                           | -------------                                                                                                                          |
| <code><a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles_ETREASURY_COMPLIANCE">Roles::ETREASURY_COMPLIANCE</a></code>            | The sending account is not the Treasury Compliance account.                                                                            |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_ETREASURY_COMPLIANCE">CoreAddresses::ETREASURY_COMPLIANCE</a></code>    | <code>tc_account</code> is not the Treasury Compliance account.                                                                                   |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_MANAGER">VASPDomain::EVASP_DOMAIN_MANAGER</a></code>        | The <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomainManager">VASPDomain::VASPDomainManager</a></code> resource is not yet published under the Treasury Compliance account.                                 |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EVASP_DOMAINS_NOT_PUBLISHED">VASPDomain::EVASP_DOMAINS_NOT_PUBLISHED</a></code> | <code>address</code> does not have a <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under it.                                                         |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EINVALID_VASP_DOMAIN">VASPDomain::EINVALID_VASP_DOMAIN</a></code>        | The <code>domain</code> is greater in length than <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_DOMAIN_LENGTH">VASPDomain::DOMAIN_LENGTH</a></code>.                                                                        |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_EVASP_DOMAIN_NOT_FOUND">VASPDomain::EVASP_DOMAIN_NOT_FOUND</a></code>              | The <code>domain</code> does not exist in the list of <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomain">VASPDomain::VASPDomain</a></code>s  in the <code><a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_VASPDomains">VASPDomain::VASPDomains</a></code> resource published under <code>address</code>. |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_remove_vasp_domain">remove_vasp_domain</a>(tc_account: signer, address: address, domain: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_TreasuryComplianceScripts_remove_vasp_domain">remove_vasp_domain</a> (
    tc_account: signer,
    address: address,
    domain: vector&lt;u8&gt;,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain_remove_vasp_domain">VASPDomain::remove_vasp_domain</a>(&tc_account, address, domain);
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>aborts_with</b> [check]
    <a href="_REQUIRES_ROLE">Errors::REQUIRES_ROLE</a>,
    <a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a>,
    <a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a>,
    <a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a>;
</code></pre>



</details>


---

<a name="@System_Administration_243"></a>

### System Administration



<a name="0x1_SystemAdministrationScripts"></a>

#### Module `0x1::SystemAdministrationScripts`

This module contains Diem Framework script functions to administer the
network outside of validators and validator operators.


<pre><code><b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemConsensusConfig.md#0x1_DiemConsensusConfig">0x1::DiemConsensusConfig</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemVMConfig.md#0x1_DiemVMConfig">0x1::DiemVMConfig</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/DiemVersion.md#0x1_DiemVersion">0x1::DiemVersion</a>;
<b>use</b> <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">0x1::SlidingNonce</a>;
</code></pre>



<a name="0x1_SystemAdministrationScripts_update_diem_version"></a>

##### Function `update_diem_version`


<a name="@Summary_244"></a>

###### Summary

Updates the Diem major version that is stored on-chain and is used by the VM.  This
transaction can only be sent from the Diem Root account.


<a name="@Technical_Description_245"></a>

###### Technical Description

Updates the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemVersion.md#0x1_DiemVersion">DiemVersion</a></code> on-chain config and emits a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code> to trigger
a reconfiguration of the system. The <code>major</code> version that is passed in must be strictly greater
than the current major version held on-chain. The VM reads this information and can use it to
preserve backwards compatibility with previous major versions of the VM.


<a name="@Parameters_246"></a>

###### Parameters

| Name            | Type     | Description                                                                |
| ------          | ------   | -------------                                                              |
| <code>account</code>       | <code>signer</code> | Signer of the sending account. Must be the Diem Root account.              |
| <code>sliding_nonce</code> | <code>u64</code>    | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction. |
| <code>major</code>         | <code>u64</code>    | The <code>major</code> version of the VM to be used from this transaction on.         |


<a name="@Common_Abort_Conditions_247"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                  | Description                                                                                |
| ----------------           | --------------                                | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>       | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>                   | <code>account</code> is not the Diem Root account.                                                    |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemVersion.md#0x1_DiemVersion_EINVALID_MAJOR_VERSION_NUMBER">DiemVersion::EINVALID_MAJOR_VERSION_NUMBER</a></code>  | <code>major</code> is less-than or equal to the current major version stored on-chain.                |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_update_diem_version">update_diem_version</a>(account: signer, sliding_nonce: u64, major: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_update_diem_version">update_diem_version</a>(account: signer, sliding_nonce: u64, major: u64) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemVersion.md#0x1_DiemVersion_set">DiemVersion::set</a>(&account, major)
}
</code></pre>



</details>

<a name="0x1_SystemAdministrationScripts_set_gas_constants"></a>

##### Function `set_gas_constants`


<a name="@Summary_248"></a>

###### Summary

Updates the gas constants stored on chain and used by the VM for gas
metering. This transaction can only be sent from the Diem Root account.


<a name="@Technical_Description_249"></a>

###### Technical Description

Updates the on-chain config holding the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemVMConfig.md#0x1_DiemVMConfig">DiemVMConfig</a></code> and emits a
<code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code> to trigger a reconfiguration of the system.


<a name="@Parameters_250"></a>

###### Parameters

| Name                                | Type     | Description                                                                                            |
| ------                              | ------   | -------------                                                                                          |
| <code>account</code>                           | <code>signer</code> | Signer of the sending account. Must be the Diem Root account.                                          |
| <code>sliding_nonce</code>                     | <code>u64</code>    | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction.                             |
| <code>global_memory_per_byte_cost</code>       | <code>u64</code>    | The new cost to read global memory per-byte to be used for gas metering.                               |
| <code>global_memory_per_byte_write_cost</code> | <code>u64</code>    | The new cost to write global memory per-byte to be used for gas metering.                              |
| <code>min_transaction_gas_units</code>         | <code>u64</code>    | The new flat minimum amount of gas required for any transaction.                                       |
| <code>large_transaction_cutoff</code>          | <code>u64</code>    | The new size over which an additional charge will be assessed for each additional byte.                |
| <code>intrinsic_gas_per_byte</code>            | <code>u64</code>    | The new number of units of gas that to be charged per-byte over the new <code>large_transaction_cutoff</code>.    |
| <code>maximum_number_of_gas_units</code>       | <code>u64</code>    | The new maximum number of gas units that can be set in a transaction.                                  |
| <code>min_price_per_gas_unit</code>            | <code>u64</code>    | The new minimum gas price that can be set for a transaction.                                           |
| <code>max_price_per_gas_unit</code>            | <code>u64</code>    | The new maximum gas price that can be set for a transaction.                                           |
| <code>max_transaction_size_in_bytes</code>     | <code>u64</code>    | The new maximum size of a transaction that can be processed.                                           |
| <code>gas_unit_scaling_factor</code>           | <code>u64</code>    | The new scaling factor to use when scaling between external and internal gas units.                    |
| <code>default_account_size</code>              | <code>u64</code>    | The new default account size to use when assessing final costs for reads and writes to global storage. |


<a name="@Common_Abort_Conditions_251"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                | Description                                                                                |
| ----------------           | --------------                              | -------------                                                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemVMConfig.md#0x1_DiemVMConfig_EGAS_CONSTANT_INCONSISTENCY">DiemVMConfig::EGAS_CONSTANT_INCONSISTENCY</a></code> | The provided gas constants are inconsistent.                                               |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>              | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>              | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>              | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>     | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>                 | <code>account</code> is not the Diem Root account.                                                    |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_set_gas_constants">set_gas_constants</a>(dr_account: signer, sliding_nonce: u64, global_memory_per_byte_cost: u64, global_memory_per_byte_write_cost: u64, min_transaction_gas_units: u64, large_transaction_cutoff: u64, intrinsic_gas_per_byte: u64, maximum_number_of_gas_units: u64, min_price_per_gas_unit: u64, max_price_per_gas_unit: u64, max_transaction_size_in_bytes: u64, gas_unit_scaling_factor: u64, default_account_size: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_set_gas_constants">set_gas_constants</a>(
    dr_account: signer,
    sliding_nonce: u64,
    global_memory_per_byte_cost: u64,
    global_memory_per_byte_write_cost: u64,
    min_transaction_gas_units: u64,
    large_transaction_cutoff: u64,
    intrinsic_gas_per_byte: u64,
    maximum_number_of_gas_units: u64,
    min_price_per_gas_unit: u64,
    max_price_per_gas_unit: u64,
    max_transaction_size_in_bytes: u64,
    gas_unit_scaling_factor: u64,
    default_account_size: u64,
) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&dr_account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemVMConfig.md#0x1_DiemVMConfig_set_gas_constants">DiemVMConfig::set_gas_constants</a>(
            &dr_account,
            global_memory_per_byte_cost,
            global_memory_per_byte_write_cost,
            min_transaction_gas_units,
            large_transaction_cutoff,
            intrinsic_gas_per_byte,
            maximum_number_of_gas_units,
            min_price_per_gas_unit,
            max_price_per_gas_unit,
            max_transaction_size_in_bytes,
            gas_unit_scaling_factor,
            default_account_size,
    )
}
</code></pre>



</details>

<a name="0x1_SystemAdministrationScripts_initialize_diem_consensus_config"></a>

##### Function `initialize_diem_consensus_config`


<a name="@Summary_252"></a>

###### Summary

Initializes the Diem consensus config that is stored on-chain.  This
transaction can only be sent from the Diem Root account.


<a name="@Technical_Description_253"></a>

###### Technical Description

Initializes the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConsensusConfig.md#0x1_DiemConsensusConfig">DiemConsensusConfig</a></code> on-chain config to empty and allows future updates from DiemRoot via
<code>update_diem_consensus_config</code>. This doesn't emit a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code>.


<a name="@Parameters_254"></a>

###### Parameters

| Name            | Type      | Description                                                                |
| ------          | ------    | -------------                                                              |
| <code>account</code>       | <code>signer</code> | Signer of the sending account. Must be the Diem Root account.               |
| <code>sliding_nonce</code> | <code>u64</code>     | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction. |


<a name="@Common_Abort_Conditions_255"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                  | Description                                                                                |
| ----------------           | --------------                                | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>       | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>                   | <code>account</code> is not the Diem Root account.                                                    |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_initialize_diem_consensus_config">initialize_diem_consensus_config</a>(account: signer, sliding_nonce: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_initialize_diem_consensus_config">initialize_diem_consensus_config</a>(account: signer, sliding_nonce: u64) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemConsensusConfig.md#0x1_DiemConsensusConfig_initialize">DiemConsensusConfig::initialize</a>(&account);
}
</code></pre>



</details>

<a name="0x1_SystemAdministrationScripts_update_diem_consensus_config"></a>

##### Function `update_diem_consensus_config`


<a name="@Summary_256"></a>

###### Summary

Updates the Diem consensus config that is stored on-chain and is used by the Consensus.  This
transaction can only be sent from the Diem Root account.


<a name="@Technical_Description_257"></a>

###### Technical Description

Updates the <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConsensusConfig.md#0x1_DiemConsensusConfig">DiemConsensusConfig</a></code> on-chain config and emits a <code><a href="../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig_NewEpochEvent">DiemConfig::NewEpochEvent</a></code> to trigger
a reconfiguration of the system.


<a name="@Parameters_258"></a>

###### Parameters

| Name            | Type          | Description                                                                |
| ------          | ------        | -------------                                                              |
| <code>account</code>       | <code>signer</code>      | Signer of the sending account. Must be the Diem Root account.              |
| <code>sliding_nonce</code> | <code>u64</code>         | The <code>sliding_nonce</code> (see: <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code>) to be used for this transaction. |
| <code>config</code>        | <code>vector&lt;u8&gt;</code>  | The serialized bytes of consensus config.                                  |


<a name="@Common_Abort_Conditions_259"></a>

###### Common Abort Conditions

| Error Category             | Error Reason                                  | Description                                                                                |
| ----------------           | --------------                                | -------------                                                                              |
| <code><a href="_NOT_PUBLISHED">Errors::NOT_PUBLISHED</a></code>    | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ESLIDING_NONCE">SlidingNonce::ESLIDING_NONCE</a></code>                | A <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce">SlidingNonce</a></code> resource is not published under <code>account</code>.                                |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_OLD">SlidingNonce::ENONCE_TOO_OLD</a></code>                | The <code>sliding_nonce</code> is too old and it's impossible to determine if it's duplicated or not. |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_TOO_NEW">SlidingNonce::ENONCE_TOO_NEW</a></code>                | The <code>sliding_nonce</code> is too far in the future.                                              |
| <code><a href="_INVALID_ARGUMENT">Errors::INVALID_ARGUMENT</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_ENONCE_ALREADY_RECORDED">SlidingNonce::ENONCE_ALREADY_RECORDED</a></code>       | The <code>sliding_nonce</code> has been previously recorded.                                          |
| <code><a href="_REQUIRES_ADDRESS">Errors::REQUIRES_ADDRESS</a></code> | <code><a href="../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses_EDIEM_ROOT">CoreAddresses::EDIEM_ROOT</a></code>                   | <code>account</code> is not the Diem Root account.                                                    |


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_update_diem_consensus_config">update_diem_consensus_config</a>(account: signer, sliding_nonce: u64, config: vector&lt;u8&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>script</b>) <b>fun</b> <a href="script_documentation.md#0x1_SystemAdministrationScripts_update_diem_consensus_config">update_diem_consensus_config</a>(account: signer, sliding_nonce: u64, config: vector&lt;u8&gt;) {
    <a href="../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce_record_nonce_or_abort">SlidingNonce::record_nonce_or_abort</a>(&account, sliding_nonce);
    <a href="../../../../../releases/artifacts/current/docs/modules/DiemConsensusConfig.md#0x1_DiemConsensusConfig_set">DiemConsensusConfig::set</a>(&account, config)
}
</code></pre>



</details>



<a name="@Index_260"></a>

### Index


-  [`0x1::AccountAdministrationScripts`](script_documentation.md#0x1_AccountAdministrationScripts)
-  [`0x1::AccountCreationScripts`](script_documentation.md#0x1_AccountCreationScripts)
-  [`0x1::AccountFreezing`](../../../../../releases/artifacts/current/docs/modules/AccountFreezing.md#0x1_AccountFreezing)
-  [`0x1::AccountLimits`](../../../../../releases/artifacts/current/docs/modules/AccountLimits.md#0x1_AccountLimits)
-  [`0x1::Authenticator`](../../../../../releases/artifacts/current/docs/modules/Authenticator.md#0x1_Authenticator)
-  [`0x1::ChainId`](../../../../../releases/artifacts/current/docs/modules/ChainId.md#0x1_ChainId)
-  [`0x1::CoreAddresses`](../../../../../releases/artifacts/current/docs/modules/CoreAddresses.md#0x1_CoreAddresses)
-  [`0x1::DesignatedDealer`](../../../../../releases/artifacts/current/docs/modules/DesignatedDealer.md#0x1_DesignatedDealer)
-  [`0x1::Diem`](../../../../../releases/artifacts/current/docs/modules/Diem.md#0x1_Diem)
-  [`0x1::DiemAccount`](../../../../../releases/artifacts/current/docs/modules/DiemAccount.md#0x1_DiemAccount)
-  [`0x1::DiemBlock`](../../../../../releases/artifacts/current/docs/modules/DiemBlock.md#0x1_DiemBlock)
-  [`0x1::DiemConfig`](../../../../../releases/artifacts/current/docs/modules/DiemConfig.md#0x1_DiemConfig)
-  [`0x1::DiemConsensusConfig`](../../../../../releases/artifacts/current/docs/modules/DiemConsensusConfig.md#0x1_DiemConsensusConfig)
-  [`0x1::DiemSystem`](../../../../../releases/artifacts/current/docs/modules/DiemSystem.md#0x1_DiemSystem)
-  [`0x1::DiemTimestamp`](../../../../../releases/artifacts/current/docs/modules/DiemTimestamp.md#0x1_DiemTimestamp)
-  [`0x1::DiemTransactionPublishingOption`](../../../../../releases/artifacts/current/docs/modules/DiemTransactionPublishingOption.md#0x1_DiemTransactionPublishingOption)
-  [`0x1::DiemVMConfig`](../../../../../releases/artifacts/current/docs/modules/DiemVMConfig.md#0x1_DiemVMConfig)
-  [`0x1::DiemVersion`](../../../../../releases/artifacts/current/docs/modules/DiemVersion.md#0x1_DiemVersion)
-  [`0x1::DualAttestation`](../../../../../releases/artifacts/current/docs/modules/DualAttestation.md#0x1_DualAttestation)
-  [`0x1::Genesis`](../../../../../releases/artifacts/current/docs/modules/Genesis.md#0x1_Genesis)
-  [`0x1::PaymentScripts`](script_documentation.md#0x1_PaymentScripts)
-  [`0x1::RecoveryAddress`](../../../../../releases/artifacts/current/docs/modules/RecoveryAddress.md#0x1_RecoveryAddress)
-  [`0x1::RegisteredCurrencies`](../../../../../releases/artifacts/current/docs/modules/RegisteredCurrencies.md#0x1_RegisteredCurrencies)
-  [`0x1::Roles`](../../../../../releases/artifacts/current/docs/modules/Roles.md#0x1_Roles)
-  [`0x1::SharedEd25519PublicKey`](../../../../../releases/artifacts/current/docs/modules/SharedEd25519PublicKey.md#0x1_SharedEd25519PublicKey)
-  [`0x1::Signature`](../../../../../releases/artifacts/current/docs/modules/Signature.md#0x1_Signature)
-  [`0x1::SlidingNonce`](../../../../../releases/artifacts/current/docs/modules/SlidingNonce.md#0x1_SlidingNonce)
-  [`0x1::SystemAdministrationScripts`](script_documentation.md#0x1_SystemAdministrationScripts)
-  [`0x1::TransactionFee`](../../../../../releases/artifacts/current/docs/modules/TransactionFee.md#0x1_TransactionFee)
-  [`0x1::TreasuryComplianceScripts`](script_documentation.md#0x1_TreasuryComplianceScripts)
-  [`0x1::VASP`](../../../../../releases/artifacts/current/docs/modules/VASP.md#0x1_VASP)
-  [`0x1::VASPDomain`](../../../../../releases/artifacts/current/docs/modules/VASPDomain.md#0x1_VASPDomain)
-  [`0x1::ValidatorAdministrationScripts`](script_documentation.md#0x1_ValidatorAdministrationScripts)
-  [`0x1::ValidatorConfig`](../../../../../releases/artifacts/current/docs/modules/ValidatorConfig.md#0x1_ValidatorConfig)
-  [`0x1::ValidatorOperatorConfig`](../../../../../releases/artifacts/current/docs/modules/ValidatorOperatorConfig.md#0x1_ValidatorOperatorConfig)
-  [`0x1::XDX`](../../../../../releases/artifacts/current/docs/modules/XDX.md#0x1_XDX)
-  [`0x1::XUS`](../../../../../releases/artifacts/current/docs/modules/XUS.md#0x1_XUS)


[//]: # ("File containing references which can be used from documentation")
[ACCESS_CONTROL]: https://github.com/diem/dip/blob/main/dips/dip-2.md
[ROLE]: https://github.com/diem/dip/blob/main/dips/dip-2.md#roles
[PERMISSION]: https://github.com/diem/dip/blob/main/dips/dip-2.md#permissions
