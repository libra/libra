---
id: my-first-transaction
title: My First Transaction
---

This document will guide you through executing your first transaction on the Diem Blockchain. Before you proceed, we recommend that you read the following to familiarize yourself with the key concepts:


* [Diem Protocol](diem-protocol.md)
* [Life of a Transaction](life-of-a-transaction.md)

We provide a command line interface (CLI) client to interact with the Diem Blockchain.

#### Assumptions

All commands in this document assume that:

* You are running on a Linux (Red Hat or Debian-based) or macOS system.
* You have a stable connection to the internet.
* `git` is installed on your system.
* Homebrew is installed on a macOS system.
* `yum`or `apt-get` is installed on a Linux system.


## Steps to submit a transaction

In this example, we will download the necessary Diem components and execute a transaction between two users: Alice and Bob.

To submit a transaction to a validator node on the Diem testnet:

1. [Clone and build Diem Core](#clone-and-build-diem-core).
2. [Build the Diem CLI client and connect to the testnet](#build-diem-cli-client-and-connect-to-the-testnet).
3. [Create accounts for Alice and Bob](#create-accounts-for-alice-and-bob).
4. [Add Fake Diem Coins to Alice’s and Bob’s accounts](#add-fake-diem-coins-to-alices-and-bobs-accounts).
5. [Submit a transaction](#submit-a-transaction).


### Clone and build Diem Core

1. Clone the Diem Core repository

    ```bash
    git clone https://github.com/diem/diem.git && cd diem
    ```

2. Checkout the `testnet` branch

    ```bash
    git checkout testnet
    ```

3. Install dependencies
    To setup Diem Core, change to the `diem` directory and run the setup script to install the dependencies, as shown below:

    ```
    ./scripts/dev_setup.sh
    ```

    The setup script performs these actions:

    * Installs rustup, an installer for the Rust programming language, in which Diem Core is implemented.
    * Installs the required versions of the rust-toolchain.
    * Installs CMake to manage the build process.


If your setup fails, see [Troubleshooting](#setup)


### Build Diem CLI client and connect to the testnet

To connect to a validator node running on the Diem testnet, run the client as shown below.


```bash
./scripts/cli/start_cli_testnet.sh
```

This command builds and runs the client utilizing cargo (Rust’s package manager) and connects the client to a validator node on the testnet.

Once the client connects to a node on the testnet, you will see the following output. To quit the client at any time, use the quit command.


```
usage: <command> <args>

Use the following commands:

account | a 
	Account operations
query | q 
	Query operations
transfer | transferb | t | tb 
	<sender_account_address>|<sender_account_ref_id> <receiver_account_address>|<receiver_account_ref_id> <number_of_coins> <currency_code> [gas_unit_price_in_micro_diems (default=0)] [max_gas_amount_in_micro_diems (default 400_000)] Suffix 'b' is for blocking. 
	Transfer coins from one account to another.
info | i 
	Print cli config and client internal information
help | h 
	Prints this help
quit | q! 
	Exit this client


Please, input commands: 

diem%

```

If you have problems building the client and connecting to the testnet, refer to [Troubleshooting](#client-build-and-run).


>
>**Note**: If you would like to run a test validator network locally on your system, follow the instructions [here](run-local-network.md). The instructions for creating accounts, minting coins, and performing a transaction are the same as that for a node on testnet.
>


### Create accounts for Alice and Bob

Once your client is connected to the testnet, you can run CLI commands to create new accounts.  We will walk you through creating accounts for two users (let's call them Alice and Bob).

#### Step 1: Check if the CLI client Is running on your system

A `diem%` command line prompt indicates that your Diem CLI client is running. To see the help information for the `account` command enter “account” as shown below:

```
diem% account
usage: account <arg>

Use the following args for this command:

Use the following args for this command:

create | c 
	Create a local account--no on-chain effect. Returns reference ID to use in other operations
list | la 
	Print all accounts that were created or loaded
recover | r <file_path>
	Recover Diem wallet from the file path
write | w <file_path>
	Save Diem wallet mnemonic recovery seed to disk
mint | mintb | m | mb <receiver_account_ref_id>|<receiver_account_address> <number_of_coins> <currency_code> [use_base_units (default=false)]
	Send currency of the given type from the faucet address to the given recipient address. Creates an account at the recipient address if one does not already exist.
addc | addcb | ac | acb <account_address> <currency_code>
	Add specified currency to the account. Suffix 'b' is for blocking

```

#### Step 2: Create Alice’s account

>
>**Note**: Creating an account using the CLI does not update the Diem Blockchain, it just creates a local key-pair.
>

To create Alice’s account, enter this command:

`diem% account create`

Sample output on success:

```
>> Creating/retrieving next local account from wallet
Created/retrieved local account #0 address 9d02da2312d2687ca665ccf77f2435fc
```

* 0 is the index of Alice’s account.
* The hex string is the address of Alice’s account.

The index is just a way to refer to Alice’s account. Users can use the account index, a local CLI index, in other CLI commands to refer to the accounts they have created. The index is meaningless to the blockchain. Alice’s account will be created on the blockchain only when fake Diem Coins are added to Alice’s account or transferred to Alice’s account via a transfer from another user. Note that you may also use the hex address in CLI commands. The account index is just a convenience wrapper around the account address.


#### Step 3: Create Bob’s account

To create Bob’s account, repeat the account creation command:

`diem% account create`

Sample output on success:

```
>> Creating/retrieving next local account from wallet
Created/retrieved local account #1 address 3099d7230aa336f5dcfe13c1231454ce

```
* 1 is the index for Bob’s account.
* The hex string is the address of Bob’s account.


#### Step 4 (Optional): List accounts

To list the accounts you have created, enter this command:

`diem% account list`

Sample output on success:
```
User account index: 0, address: 9d02da2312d2687ca665ccf77f2435fc, private_key: "1762350c5f5b56fc61d913fe9d25325eff69766d735d05e76ca780328b52a68d", sequence number: 0, status: Local
User account index: 1, address: 3099d7230aa336f5dcfe13c1231454ce, private_key: "6a6704b403ebe52603baf16798b0c8f1ce54048321858d3d61bb4e6bafffda30", sequence number: 0, status: Local

```

The sequence number for an account indicates the number of transactions that have been sent from that account. It is incremented by one every time a transaction sent from that account is executed and stored in the Diem Blockchain. To learn more, refer to  [sequence number](reference/glossary.md#sequence-number).

### Add Fake Diem Coins to Alice’s and Bob’s accounts

Adding fake Diem Coins with no real-world value to accounts on testnet is done via Faucet. Faucet is a service that runs along with the testnet. This service only exists to facilitate minting coins for testnet and will not exist for mainnet. Faucet creates Diem Coins with no real-world value. Assuming you’ve [created Alice’s and Bob’s account](#create-alices-and-bobs-account), with index 0 and index 1 respectively, you can follow the steps below to add fake Diem Coins to both accounts.


#### Step 1: Add 110 Diem Coins to Alice’s account

To mint fake Diem Coins and add them to Alice’s account, enter this command:


`diem% account mint 0 110 XUS`

* 0 is the index of Alice’s account.
* 110 is the amount of fake Diem Coins to be added to Alice’s account.
* XUS is the currency code for the fake Diem Coins

A successful account “mint” command will also create Alice’s account on the blockchain.  Note that “minting” on Testnet means adding new fake Diem Coins to an account.

Sample output on success:


```
>> Sending coins from faucet
..........................................................................................
.....................
Finished sending coins from faucet!
```

When the request is submitted, it means that it has been added to the mempool (of a validator node on testnet) successfully. It does not necessarily imply that it will be successfully completed. Later, we will query the account balance to confirm whether the minting was successful.

If your account “mint” command did not submit your request successfully, refer to [Troubleshooting](#minting-and-adding-money-to-account)

#### Step 2: Add 52 Diem Coins to Bob’s account

To mint fake Diem Coins and add them to Bob’s account, enter this command:


`diem% account mint 1 52 XUS`

* 1 is the index of Bob’s account.
* 52 is the amount of Diem to be added to Bob’s account.
* XUS is the currency code for the fake Diem Coins

A successful account “mint” command can also create Bob’s account on the blockchain. Another way to create Bob’s account on the blockchain is to transfer money from Alice’s account to Bob’s account.

Sample output on success:

```
>> Sending coins from faucet
....................................................................................................................
......................
Finished sending coins from faucet!
```

If your account mint command did not submit your request successfully, refer to [Troubleshooting](#minting-and-adding-money-to-account)


#### Step 3: Check the balance

To check the balance in Alice’s account, enter this command:

`diem% query balance 0`

Sample output on success:

`Balance is: 110.000000XUS`

To check the balance in Bob’s account, enter this command:

`diem% query balance 1`

Sample output on success:

`Balance is: 52.000000XUS`

### Submit a transaction

Before we submit a transaction to transfer Diem Coins from Alice’s account to Bob’s account, we will query the sequence number of each account. This will help us understand how executing a transaction changes the sequence number of each account.

#### Query the accounts’ sequence numbers

```plaintext
diem% query sequence 0
>> Getting current sequence number
Sequence number is: 0
diem% query sequence 1
>> Getting current sequence number
Sequence number is: 0
```

In `query sequence 0`, 0 is the index of Alice’s account. A sequence number of 0 for both Alice’s and Bob’s accounts indicates that no transactions from either Alice’s or Bob’s account has been executed so far.

#### Transfer money

To submit a transaction to transfer 10 Diem Coins from Alice’s account to Bob’s account, enter this command:

`diem% transfer 0 1 10 XUS`

* 0 is the index of Alice’s account.
* 1 is the index of Bob’s account.
* 10 is the number of fake Diem Coins to transfer from Alice’s account to Bob’s account.
* XUS is the currency code for the fake Diem Coins


Sample output on success:

```
>> Transferring
Transaction submitted to validator
To query for transaction status, run: query txn_acc_seq 0 0 <fetch_events=true|false>
```

You can use the command `query txn_acc_seq 0 0 true` (transaction by account and sequence number) to retrieve the information about the transaction you just submitted. The first parameter is the local index of the sender account, and the second parameter is the sequence number of the account. To see a sample output of this command refer to [Sample Outputs](#query-transaction-by-account-and-sequence-number).

You just submitted your transaction to a validator node on testnet, and it was included in the [mempool](reference/glossary.md#mempool) of the validator. This doesn't necessarily mean your transaction has been executed. In theory, if the system were slow or overloaded, it would take some time to see the results, and you may have to check multiple times by querying the accounts. To query an account with index 0, you can use the command  `query account_state 0.` The expected output is shown in the [Sample Outputs](#query-events) section

To troubleshoot the transfer command, refer to [Troubleshooting](#the-transfer-command).

**The Blocking Transfer Command**: You can use the `transferb` command (as shown below), instead of the `transfer` command. `transferb` will submit the transaction and return to the client prompt only after the transaction has been committed to the blockchain. An example is shown below:

`diem% transferb 0 1 10 XUS`

Refer to [Life of a Transaction](life-of-a-transaction.md) for an understanding of the lifecycle of a transaction from submission to execution and storage.

#### Query sequence number after transfer

```
diem% query sequence 0
>> Getting current sequence number
Sequence number is: 1
diem% query sequence 1
>> Getting current sequence number
Sequence number is: 0
```

The sequence number of 1 for Alice’s account (index 0) indicates that one transaction has been sent from Alice’s account so far. The sequence number of 0 for Bob’s account (index 1) indicates that no transaction has been sent from Bob’s account so far. Every time a transaction is sent from an account, the sequence number is incremented by 1.

#### Check the balance in both accounts after transfer

To check the final balance in both accounts, query the balance again for each account as you did in [this step](#step-3-check-the-balance). If your transaction (transfer) executed successfully, you should see 100 fake Diem Coins in Alice’s account and 62 fake Diem Coins in Bob’s account.

```
diem% query balance 0
Balance is: 100.000000XUS
diem% query balance 1
Balance is: 62.000000XUS
```

### Congratulations!

You have successfully executed your transaction on the Diem testnet and transferred 10 Diem Coins from Alice’s account to Bob’s account!


## Troubleshooting

### Setup

* Update Rust:
    * Run `rustup update` from your diem directory.
* Update protoc:
    * Update `protoc` to version 3.6.0 or above.
* Re-run setup script from your diem directory:
    * `./scripts/dev_setup.sh`


### Client build and run

If you are experiencing build failures, try to remove the cargo lock file from the diem directory:

* `rm Cargo.lock`

If your client did not connect to the testnet:

* Check your internet connection.
* Ensure that you are using the latest version of the client. Pull the latest Diem Core and rerun the client: `./scripts/cli/start_cli_testnet.sh`


### Minting and adding money to account

* If the validator node you connected to on testnet is unavailable, you will get a “Server unavailable” message as shown below:

```
diem% account mint 0 110 XUS
>> Minting coins
[ERROR] Error minting coins: Server unavailable, please retry and/or check **if** host passed to the client is running
```

* If your balance was not updated after submitting a transaction, wait a moment and query the balance again. There may be a delay if the blockchain is experiencing a very high volume of transactions.  If your balance still is not updated, please try minting again.

* To check if an account exists, query the account state. For an account with index 0 enter this:

  `diem% query account_state 0`

### The transfer command

If the testnet validator node (your client was connected to) is unavailable or your connection to the testnet has timed-out, you will see this error:

```
diem% transfer 0 1 10 XUS
>> Transferring
[ERROR] Failed to perform transaction: Server unavailable, please retry and/or check if host passed to the client is running
```
To troubleshoot transfer errors:

* Check the connection to testnet.
* Query the sender account to make sure it exists. Use the following command for an account with index 0:`query account_state 0`
* You can try quitting the client using `quit` or `q!`, and rerun the following command to connect to the testnet: `./scripts/cli/start_cli_testnet.sh` from the diem directory

## Sample outputs of additional query commands

### Query transaction by account and sequence number

This example will query for a single transaction's details using the account and sequence number.

```
diem% query txn_acc_seq 0 0 true
>>> Getting committed transaction by account and sequence number
Committed transaction: Transaction {
    version: 51985530,
    transaction: Some(
        TransactionData {
            r#type: "user",
            timestamp_usecs: 0,
            sender: "9d02da2312d2687ca665ccf77f2435fc",
            signature_scheme: "Scheme::Ed25519",
            signature: "d542c1b81d500e31da30809abf27b3c77ca8ef7a14cf686e8aec904eb05a49ed70a7ab8344cafc89530720ae57bb2ab8f32d05bf05ef3214e172195e827a0801",
            public_key: "eb25078db5c85fa8467083c16b7c3c2c35a81b9e68fd0a4f6297479f3bcfd349",
            sequence_number: 0,
            chain_id: 2,
            max_gas_amount: 1000000,
            gas_unit_price: 0,
            gas_currency: "XUS",
            expiration_timestamp_secs: 1611792876,
            script_hash: "04ea43107fafc12adcd09f6c68d63e194675d0ce843a7faf7cceb6c813db9d9a",
            script_bytes: "e001a11ceb0b010000000701000202020403061004160205181d0735600895011000000001010000020001000003020301010004010300010501060c0108000506080005030a020a020005060c05030a020a020109000b4469656d4163636f756e741257697468647261774361706162696c6974791b657874726163745f77697468647261775f6361706162696c697479087061795f66726f6d1b726573746f72655f77697468647261775f6361706162696c69747900000000000000000000000000000001010104010c0b0011000c050e050a010a020b030b0438000b0511020201070000000000000000000000000000000103585553035855530004033099d7230aa336f5dcfe13c1231454ce01809698000000000004000400",
            script: Some(
                Script {
                    r#type: "peer_to_peer_with_metadata",
                    code: "a11ceb0b010000000701000202020403061004160205181d0735600895011000000001010000020001000003020301010004010300010501060c0108000506080005030a020a020005060c05030a020a020109000b4469656d4163636f756e741257697468647261774361706162696c6974791b657874726163745f77697468647261775f6361706162696c697479087061795f66726f6d1b726573746f72655f77697468647261775f6361706162696c69747900000000000000000000000000000001010104010c0b0011000c050e050a010a020b030b0438000b05110202",
                    arguments: [
                        "{ADDRESS: 3099D7230AA336F5DCFE13C1231454CE}",
                        "{U64: 10000000}",
                        "{U8Vector: 0x}",
                        "{U8Vector: 0x}",
                    ],
                    type_arguments: [
                        "XUS",
                    ],
                    receiver: "3099d7230aa336f5dcfe13c1231454ce",
                    amount: 10000000,
                    currency: "XUS",
                    metadata: "",
                    metadata_signature: "",
                },
            ),
        },
    ),
    hash: "90d44b788d4edeb4b9289c09f56ac8599cc3d9f60dd93d84eedd54bcd8210b43",
    bytes: "009d02da2312d2687ca665ccf77f2435fc000000000000000001e001a11ceb0b010000000701000202020403061004160205181d0735600895011000000001010000020001000003020301010004010300010501060c0108000506080005030a020a020005060c05030a020a020109000b4469656d4163636f756e741257697468647261774361706162696c6974791b657874726163745f77697468647261775f6361706162696c697479087061795f66726f6d1b726573746f72655f77697468647261775f6361706162696c69747900000000000000000000000000000001010104010c0b0011000c050e050a010a020b030b0438000b0511020201070000000000000000000000000000000103585553035855530004033099d7230aa336f5dcfe13c1231454ce0180969800000000000400040040420f0000000000000000000000000003585553ec01126000000000020020eb25078db5c85fa8467083c16b7c3c2c35a81b9e68fd0a4f6297479f3bcfd34940d542c1b81d500e31da30809abf27b3c77ca8ef7a14cf686e8aec904eb05a49ed70a7ab8344cafc89530720ae57bb2ab8f32d05bf05ef3214e172195e827a0801",
    events: [
        Event {
            key: "03000000000000009d02da2312d2687ca665ccf77f2435fc",
            sequence_number: 0,
            transaction_version: 51985530,
            data: Some(
                EventData {
                    r#type: "sentpayment",
                    amount: Some(
                        Amount {
                            amount: 10000000,
                            currency: "XUS",
                        },
                    ),
                    preburn_address: "",
                    currency_code: "",
                    new_to_xdx_exchange_rate: 0.0,
                    sender: "9d02da2312d2687ca665ccf77f2435fc",
                    receiver: "3099d7230aa336f5dcfe13c1231454ce",
                    metadata: "",
                    epoch: 0,
                    round: 0,
                    proposer: "",
                    proposed_time: 0,
                    destination_address: "",
                    new_compliance_public_key: "",
                    new_base_url: "",
                    time_rotated_seconds: 0,
                    created_address: "",
                    role_id: 0,
                    committed_timestamp_secs: 0,
                },
            ),
        },
        Event {
            key: "02000000000000003099d7230aa336f5dcfe13c1231454ce",
            sequence_number: 1,
            transaction_version: 51985530,
            data: Some(
                EventData {
                    r#type: "receivedpayment",
                    amount: Some(
                        Amount {
                            amount: 10000000,
                            currency: "XUS",
                        },
                    ),
                    preburn_address: "",
                    currency_code: "",
                    new_to_xdx_exchange_rate: 0.0,
                    sender: "9d02da2312d2687ca665ccf77f2435fc",
                    receiver: "3099d7230aa336f5dcfe13c1231454ce",
                    metadata: "",
                    epoch: 0,
                    round: 0,
                    proposer: "",
                    proposed_time: 0,
                    destination_address: "",
                    new_compliance_public_key: "",
                    new_base_url: "",
                    time_rotated_seconds: 0,
                    created_address: "",
                    role_id: 0,
                    committed_timestamp_secs: 0,
                },
            ),
        },
    ],
    vm_status: Some(
        VmStatus {
            r#type: "executed",
            location: "",
            abort_code: 0,
            function_index: 0,
            code_offset: 0,
            explanation: None,
        },
    ),
    gas_used: 481,
}

```



### Query events

In the following example, we will query for “sent” events from the account at reference index 0.  You will notice there is a single event since we sent one transaction from this account.  The proof of the current state is also returned so that verification can be performed that no events are missing - this is done when the query does not return “limit” events.

```
diem% query event 0 sent 0 10
>> Getting events by account and event type.
Event { key: "03000000000000009d02da2312d2687ca665ccf77f2435fc", sequence_number: 0, transaction_version: 51985530, data: Some(EventData { r#type: "sentpayment", amount: Some(Amount { amount: 10000000, currency: "XUS" }), preburn_address: "", currency_code: "", new_to_xdx_exchange_rate: 0.0, sender: "9d02da2312d2687ca665ccf77f2435fc", receiver: "3099d7230aa336f5dcfe13c1231454ce", metadata: "", epoch: 0, round: 0, proposer: "", proposed_time: 0, destination_address: "", new_compliance_public_key: "", new_base_url: "", time_rotated_seconds: 0, created_address: "", role_id: 0, committed_timestamp_secs: 0 }) }
Last event state: Account {
    address: "9d02da2312d2687ca665ccf77f2435fc",
    balances: [
        Amount {
            amount: 100000000,
            currency: "XUS",
        },
    ],
    sequence_number: 1,
    authentication_key: "961c7447e62a97eee93c2340742da2119d02da2312d2687ca665ccf77f2435fc",
    sent_events_key: "03000000000000009d02da2312d2687ca665ccf77f2435fc",
    received_events_key: "02000000000000009d02da2312d2687ca665ccf77f2435fc",
    delegated_key_rotation_capability: false,
    delegated_withdrawal_capability: false,
    is_frozen: false,
    role: Some(
        AccountRole {
            r#type: "parent_vasp",
            parent_vasp_address: "",
            human_name: "No. 30712 VASP",
            base_url: "",
            expiration_time: 18446744073709551615,
            compliance_key: "",
            compliance_key_rotation_events_key: "00000000000000009d02da2312d2687ca665ccf77f2435fc",
            base_url_rotation_events_key: "01000000000000009d02da2312d2687ca665ccf77f2435fc",
            num_children: 0,
            received_mint_events_key: "",
            preburn_balances: [],
        },
    ),
}

```

### Query account state

In this example, we will query for the state of a single account.

```plaintext
diem% query account_state 0
>> Getting latest account state
Latest account state is: 
 Account: (
    9D02DA2312D2687CA665CCF77F2435FC,
    Some(
        AuthenticationKey(
            [
                150,
                28,
                116,
                71,
                230,
                42,
                151,
                238,
                233,
                60,
                35,
                64,
                116,
                45,
                162,
                17,
                157,
                2,
                218,
                35,
                18,
                210,
                104,
                124,
                166,
                101,
                204,
                247,
                127,
                36,
                53,
                252,
            ],
        ),
    ),
)
 State: Some(
    Account {
        address: "9d02da2312d2687ca665ccf77f2435fc",
        balances: [
            Amount {
                amount: 100000000,
                currency: "XUS",
            },
        ],
        sequence_number: 1,
        authentication_key: "961c7447e62a97eee93c2340742da2119d02da2312d2687ca665ccf77f2435fc",
        sent_events_key: "03000000000000009d02da2312d2687ca665ccf77f2435fc",
        received_events_key: "02000000000000009d02da2312d2687ca665ccf77f2435fc",
        delegated_key_rotation_capability: false,
        delegated_withdrawal_capability: false,
        is_frozen: false,
        role: Some(
            AccountRole {
                r#type: "parent_vasp",
                parent_vasp_address: "",
                human_name: "No. 30712 VASP",
                base_url: "",
                expiration_time: 18446744073709551615,
                compliance_key: "",
                compliance_key_rotation_events_key: "00000000000000009d02da2312d2687ca665ccf77f2435fc",
                base_url_rotation_events_key: "01000000000000009d02da2312d2687ca665ccf77f2435fc",
                num_children: 0,
                received_mint_events_key: "",
                preburn_balances: [],
            },
        ),
    },
)
 Blockchain Version: 51986212
```



## Life of a transaction

Once you have executed your first transaction, you may refer to the document [Life of a Transaction](life-of-a-transaction.md) for:

* A look "under the hood" at the lifecycle of a transaction from submission to execution.
* An understanding of the interactions between each logical component of a Diem validator as transactions get submitted and executed in the Diem ecosystem.


###### tags: `core`
