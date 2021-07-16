---
id: accounts
title: Accounts
sidebar_label: Accounts
---




An [account](/reference/glossary.md#accounts) represents a resource on the Diem Blockchain that can send transactions. An account is a collection of Move resources stored at a particular 16-byte account address. Every account on the Diem Payment Network (DPN) is created with at least two resources:

* [RoleId](https://github.com/diem/diem/blob/main/language/diem-framework/modules/doc/Roles.md#resource-roleid), which grants the account a single, immutable [*role*](#account-roles) for [access control](https://github.com/diem/lip/blob/master/lips/lip-2.md).
* [DiemAccount](https://github.com/diem/diem/blob/main/language/diem-framework/modules/doc/DiemAccount.md#resource-diemaccount), which holds the account’s sequence number, authentication key, and event handles.

The Diem Payment Network (DPN) supports Regulated Virtual Asset Service Provider (Regulated VASP) accounts and Designated Dealer accounts.

## Account roles

There are seven types of account roles in the DPN. All Regulated VASPs can have two kinds of accounts, each with a different role -- ParentVASP and ChildVASP accounts.

#### ParentVASP
ParentVASP is the unique root account for a particular Regulated VASP. This means that there will be one account of this type for each Regulated VASP. A ParentVASP carries three key pieces of data—its name, the URL of an endpoint to hit for off-chain APIs, and a compliance public key for authenticating signatures on off-chain data payloads.

#### ChildVASP
ChildVASP is a child account of a particular ParentVASP. A Regulated VASP need not have any child accounts, but child accounts allow a Regulated VASP to maintain a structured on-chain presence if it wishes (e.g., separate cold/warm/hot accounts). A ChildVASP knows the address of its ParentVASP. When transacting with a ChildVASP, clients should use this address to look up the ParentVASP information if off-chain communication is required.


## Creating accounts

On Diem mainnet (at launch), ParentVASP accounts can only be created by the [TreasuryCompliance account](https://github.com/diem/dip/blob/main/dips/dip-2.md#roles). Once a ParentVASP account is created, the Regulated VASP can then create ChildVASP accounts.

In order to create a new account, the creator must specify the address of the new account, its authentication key prefix, and the currencies that the account will initially accept. Learn more about how accounts are created [here](transaction-types.md#account-creation-and-minting).

>
>**Note**: Funds can only be sent to an address that already contains an account; importantly, sending funds to an empty address A will not create an account at A. Instead, a transaction that sends funds to an empty address will abort.
>


## Addresses, authentication keys, and cryptographic keys
A Diem Blockchain account is uniquely identified by its 16-byte account address. Each account stores an authentication key used to authenticate the signer of a transaction. An account’s address is derived from its initial authentication key, but the Diem Payment Network supports rotating the authentication key of an account without changing its address.


To generate an authentication key and account address:

* Generate a fresh key-pair (pubkey_A, privkey_A). The Diem Payment Network uses the PureEdDSA scheme over the Ed25519 curve, as defined in RFC 8032.
* Derive a 32-byte authentication key `auth_key = sha3-256(K_pub | 0x00)`, where | denotes concatenation. The 0x00 is a 1-byte signature scheme identifier where 0x00 means single-signature.
* The account address is the last 16 bytes of `auth_key`.
* The first 16 bytes of `auth_key` is the “auth key prefix”. Any transaction that creates an account needs both an account address and an auth key prefix, but a transaction that is interacting with an existing account only needs the address.
* The authentication key for an account may require either a single signature or multiple signatures ("multisig"). With K-of-N multisig authentication, there are a total of N signers for the account, and at least K of those N signatures must be used to authenticate a transaction. Creating a K-of-N multisig authentication key is similar: generate N ed25519 public keys p_1, …, p_n, then compute `auth_key = sha3-256(p_1 | … | p_n | K | 0x01)`. Derive an address and an auth key prefix as described above. The 0x01 is a 1-byte signature scheme identifier where 0x01 means multisignature.


## Currencies and balances

The Diem Payment Network supports an account transacting in different currencies.  [`Diem<CoinType>`](https://github.com/diem/diem/blob/main/language/diem-framework/modules/doc/Diem.md#resource-diem) is the Diem Blockchain equivalent of [ERC20](https://eips.ethereum.org/EIPS/eip-20) from a standards perspective. At the Move level, these are different generic instantiations of the same Diem resource type (e.g., `Diem<Coin1>`, `Diem<XUS>`).

>
>**Note**: `Diem<XUS>` will be available at launch.
>

Each non-administrative account stores one or more [Balance`<CoinType>`](https://github.com/diem/diem/blob/main/language/diem-framework/modules/doc/DiemAccount.md#resource-balance) resources. There is a separate Balance resource for each currency type that the account holds (e.g., Balance`<Diem<Coin1>>`, Balance`<Diem<XUS>>`, …).

In order to send and receive `Diem<CoinType>`, an account must have a balance in `Diem<CoinType>`. This can be a zero balance of `Diem<CoinType>` that is added whenever `Diem<CoinType>` currency is authorized for an account. A transaction that sends `Diem<CoinType>` to an account without a balance in `Diem<CoinType>` will abort. Thus, before sending funds of type CoinType to an address, clients should first ensure that (a) the address exists, and (b) the address has a balance in CoinType (even if that balance is zero).

Balances can be added either at account creation time or subsequently via the [add_currency script](transaction-types.md#adding-a-currency-to-an-account). Only the account owner can add new balances after account creation. Once a balance has been added to an account, it cannot be removed. For example, an account that accepts `Diem<XUS>` will always accept `Diem<XUS>`.


###### tags: `core`
