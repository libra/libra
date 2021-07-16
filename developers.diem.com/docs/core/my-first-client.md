---
id: my-first-client
title: My First Client
sidebar_label: My First Client
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
const syntax = [
  {label: 'Python', value: 'python'},
  {label: 'Java', value: 'java'},
];

_An introduction to client development on testnet using the official SDKs._


## Getting Started

In this tutorial, we demonstrate the key elements of a basic client using the official SDKs to interact with the Blockchain. The code for the tutorial is available here: [my-first-client](https://github.com/diem/my-first-client). The code in this project can be run from the root of the project directory by issuing the `make` command.

The example code uses the official Client SDKs. Currently, Go, Java, and Python are available. These libraries are developed to simplify aspects of the development process. If your language is not currently supported, or on the upcoming roadmap (Rust), then you will want to  refer to the low-level JSON-RPC API. To request additional functionality or to track when it is implemented, you can submit a GitHub issue on the corresponding project repository.

To see advanced usage, refer to the Reference Wallet project.


## Setup

All code examples are shared in the [my-first-client](https://github.com/diem/my-first-client) repo on GitHub.

### Clone the repo:

_git clone [https://github.com/diem/my-first-client.git](https://github.com/diem/my-first-client.git)_

Each SDK has the following system requirements:

*   Java: Java 8+
*   Python: Python v3.7+, pipenv

### Run the examples:

`make`

or

`make python` for Python

`make java` for Java

## Connecting to the network

The first thing your client code will need to do is connect to the network.

<Tabs groupId="syntax" defaultValue="python" values={syntax}>
<TabItem value="python">

```py
client = testnet.create_client();
```

</TabItem>
<TabItem value="java">

```java
client = Testnet.createClient();
```
</TabItem>
</Tabs>

## Creating wallets

Wallets are addresses on the Blockchain that may issue transactions that send or receive funds. Private and Public key are needed.

<Tabs groupId="syntax" defaultValue="python" values={syntax}>
<TabItem value="python">

```python
# generate private key for sender account
sender_private_key = Ed25519PrivateKey.generate()

# generate auth key for sender account
sender_auth_key = AuthKey.from_public_key(sender_private_key.public_key())
print(f"Generated sender address: {utils.account_address_hex(sender_auth_key.account_address())}")
```

</TabItem>
<TabItem value="java">

```java
PrivateKey senderPrivateKey = new Ed25519PrivateKey(new Ed25519PrivateKeyParameters(new SecureRandom()));
AuthKey senderAuthKey = AuthKey.ed24419(senderPrivateKey.publicKey());
```

</TabItem>
</Tabs>

## Requesting XUS from the faucet

A faucet is a blockchain tool for testing blockchain transactions by providing coins for testing. When instructed, the testnet faucet will send the requested amount of XUS to the address provided.

Here, we request 100 XUS from the faucet and deposit it in Wallet A.

<Tabs groupId="syntax" defaultValue="python" values={syntax}>
<TabItem value="python">

```python
faucet = testnet.Faucet(client)
faucet.mint(sender_auth_key.hex(), 10000000, "XUS")
```

</TabItem>
<TabItem value="java">

```java
Testnet.mintCoins(client, 10000000, senderAuthKey.hex(), "XUS");
```

</TabItem>
</Tabs>


## Getting a balance

In the previous step we requested 100 XUS from the faucet. We can verify that our test wallet now has the expected balance.

<Tabs groupId="syntax" defaultValue="python" values={syntax}>
<TabItem value="python">

```python
# connect to testnet
client = testnet.create_client()

# generate private key
private_key = Ed25519PrivateKey.generate()

# generate auth key
auth_key = AuthKey.from_public_key(private_key.public_key())
print(f"Generated address: {utils.account_address_hex(auth_key.account_address())}")

# create account
faucet = testnet.Faucet(client)
faucet.mint(auth_key.hex(), 1340000000, "XUS")

# get account information
account = client.get_account(auth_key.account_address())
print("Account info:")
print(account)
```

</TabItem>
<TabItem value="java">

```java
//connect to testnet
DiemClient client = Testnet.createClient();

//generate private key for new account
PrivateKey privateKey = new Ed25519PrivateKey(new Ed25519PrivateKeyParameters(new SecureRandom()));

//generate auth key for new account
AuthKey authKey = AuthKey.ed24419(privateKey.publicKey());

//create account
Testnet.mintCoins(client, 10000000, authKey.hex(), CURRENCY_CODE);

//get account information
Account account = client.getAccount(authKey.accountAddress());
System.out.println("Account info:");
System.out.println(account);
```

</TabItem>
</Tabs>


## Sending Coins

_Note: There are several types of peer to peer transactions. These transactions shall have regulatory and compliance requirements that must be followed. To learn more about requirements, please visit the Prospective VASPs document here._

Next we demonstrate sending 10 units of XUS from a Sender wallet to a Receiver wallet.

<Tabs groupId="syntax" defaultValue="python" values={syntax}>
<TabItem value="python">

```python
# connect to testnet
client = testnet.create_client()

# generate private key for sender account
sender_private_key = Ed25519PrivateKey.generate()

# generate auth key for sender account
sender_auth_key = AuthKey.from_public_key(sender_private_key.public_key())
print(f"Generated sender address: {utils.account_address_hex(sender_auth_key.account_address())}")

# create sender account
faucet = testnet.Faucet(client)
testnet.Faucet.mint(faucet, sender_auth_key.hex(), 100000000, "XUS")

# get sender account
sender_account = client.get_account(sender_auth_key.account_address())

# generate private key for receiver account
receiver_private_key = Ed25519PrivateKey.generate()

# generate auth key for receiver account
receiver_auth_key = AuthKey.from_public_key(receiver_private_key.public_key())
print(f"Generated receiver address: {utils.account_address_hex(receiver_auth_key.account_address())}")

# create receiver account
faucet = testnet.Faucet(client)
faucet.mint(receiver_auth_key.hex(), 10000000, CURRENCY)

# create script
script = stdlib.encode_peer_to_peer_with_metadata_script(
    currency=utils.currency_code(CURRENCY),
    payee=receiver_auth_key.account_address(),
    amount=10000000,
    metadata=b'',  # no requirement for metadata and metadata signature
    metadata_signature=b'',
    )

# create transaction
raw_transaction = diem_types.RawTransaction(
    sender=sender_auth_key.account_address(),
    sequence_number=sender_account.sequence_number,
    payload=diem_types.TransactionPayload__Script(script),
    max_gas_amount=1_000_000,
    gas_unit_price=0,
    gas_currency_code=CURRENCY,
    expiration_timestamp_secs=int(time.time()) + 30,
    chain_id=CHAIN_ID,
    )

# sign transaction
signature = sender_private_key.sign(utils.raw_transaction_signing_msg(raw_transaction))
public_key_bytes = utils.public_key_bytes(sender_private_key.public_key())
signed_txn = utils.create_signed_transaction(raw_transaction, public_key_bytes, signature)

# submit transaction
client.submit(signed_txn)

# wait for transaction
client.wait_for_transaction(signed_txn)
```

</TabItem>
<TabItem value="java">

```java
//connect to testnet
DiemClient client = Testnet.createClient();

//generate private key for sender account
PrivateKey senderPrivateKey = new Ed25519PrivateKey(new Ed25519PrivateKeyParameters(new SecureRandom()));

//generate auth key for sender account
AuthKey senderAuthKey = AuthKey.ed24419(senderPrivateKey.publicKey());

//create sender account with 100 XUS balance
Testnet.mintCoins(client, 100000000, senderAuthKey.hex(), CURRENCY_CODE);

//get sender account for sequence number
Account account = client.getAccount(senderAuthKey.accountAddress());

//generate private key for receiver account
PrivateKey receiverPrivateKey = new Ed25519PrivateKey(new Ed25519PrivateKeyParameters(new SecureRandom()));

//generate auth key for receiver account
AuthKey receiverAuthKey = AuthKey.ed24419(receiverPrivateKey.publicKey());

//create receiver account with 1 XUS balance
Testnet.mintCoins(client, 10000000, receiverAuthKey.hex(), CURRENCY_CODE);

//create script
TransactionPayload script = new TransactionPayload.Script(
        Helpers.encode_peer_to_peer_with_metadata_script(
                CurrencyCode.typeTag(CURRENCY_CODE),
                receiverAuthKey.accountAddress(),
                10000000L,
                new Bytes(new byte[0]),
                new Bytes(new byte[0])));

//create transaction to send 1 XUS
RawTransaction rawTransaction = new RawTransaction(
        senderAuthKey.accountAddress(),
        account.getSequenceNumber(),
        script,
        1000000L,
        0L,
        CURRENCY_CODE,
        (System.currentTimeMillis() / 1000) + 300,
        CHAIN_ID);

//sign transaction
SignedTransaction st = Signer.sign(senderPrivateKey, rawTransaction);

//submit transaction
try {
    client.submit(st);
} catch (StaleResponseException e) {
    //ignore
}

//wait for the transaction to complete
Transaction transaction = client.waitForTransaction(st, 100000);
System.out.println(transaction);
```

</TabItem>
</Tabs>


We can verify that 10 XUS was sent by verifying the sender’s wallet balance is 90 and receiver’s balance is 10.


## Transaction Intent (DIP-5)

_DIP-5 introduces a standard way for communicating information about a specific transaction. DIP-5 encodes a destination address, currency, and amount. You can use this information to handle the user’s intent._

Each SDK provides the following helper function for processing this information.

<Tabs groupId="syntax" defaultValue="python" values={syntax}>
<TabItem value="python">

```python
//generate private key for new account
PrivateKey privateKey = new Ed25519PrivateKey(new Ed25519PrivateKeyParameters(new SecureRandom()));

//generate auth key for new account
AuthKey authKey = AuthKey.ed24419(privateKey.publicKey());

//create IntentIdentifier
AccountIdentifier accountIdentifier = new AccountIdentifier(TestnetPrefix, authKey.accountAddress());
IntentIdentifier intentIdentifier = new IntentIdentifier(accountIdentifier, CURRENCY, 10000000L);
String intentIdentifierString = intentIdentifier.encode();
System.out.println("Encoded IntentIdentifier: " + intentIdentifierString);

//deserialize IntentIdentifier
IntentIdentifier decodedIntentIdentifier = decode(TestnetPrefix, intentIdentifierString);

System.out.println("Account (HEX) from intent: " + Hex.encode(decodedIntentIdentifier.getAccountIdentifier().getAccountAddress().value));
System.out.println("Amount from intent: " + decodedIntentIdentifier.getAmount());
System.out.println("Currency from intent: " + decodedIntentIdentifier.getCurrency());
```

</TabItem>
<TabItem value="java">

```java
# generate private key
private_key = Ed25519PrivateKey.generate()

# generate auth key
auth_key = AuthKey.from_public_key(private_key.public_key())

# create intent identifier
account_identifier = identifier.encode_account(utils.account_address_hex(auth_key.account_address()), None, identifier.TLB)
encoded_intent_identifier = identifier.encode_intent(account_identifier, "XUS", 10000000)
print(f"Encoded IntentIdentifier: {encoded_intent_identifier}")

# deserialize IntentIdentifier
intent_identifier = diem.identifier.decode_intent(encoded_intent_identifier, identifier.TLB)
print(f"Account (HEX) from intent: {utils.account_address_hex(intent_identifier.account_address)}")
print(f"Amount from intent: {intent_identifier.amount}")
print(f"Currency from intent: {intent_identifier.currency_code}")
```

</TabItem>
</Tabs>

## Subscribing to events

To monitor and react to transactions, you may subscribe to events.

In the example below, we will setup a wallet with 100 XUS and then call the mint to add 1 XUS ten times.

<Tabs groupId="syntax" defaultValue="python" values={syntax}>
<TabItem value="python">

```python title="https://github.com/diem/my-first-client/blob/master/python/src/get_events_example.py"
import time
from random import randrange
from threading import Thread
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from diem import testnet, AuthKey, utils

CURRENCY = "XUS"

"""get_events_example demonstrates how to subscribe to a specific events stream base on events key"""

def main():

    # connect to testnet
    client = testnet.create_client()

    # generate private key
    private_key = Ed25519PrivateKey.generate()

    # generate auth key
    auth_key = AuthKey.from_public_key(private_key.public_key())
    print(f"Generated address: {utils.account_address_hex(auth_key.account_address())}")

    # create new account
    faucet = testnet.Faucet(client)
    faucet.mint(auth_key.hex(), 100000000, CURRENCY)

    # get account events key
    account = client.get_account(auth_key.account_address())
    events_key = account.received_events_key

    # start minter to demonstrates events creation
    start_minter(client, auth_key)

    # demonstrates events subscription
    subscribe(client, events_key)

def subscribe_(client, events_key):
    start = 0
    for x in range(0, 15):
        events = client.get_events(events_key, start, 10)
        start += len(events)
        print(f"{len(events)} new events found")
        time.sleep(3)
        for i in range(0, len(events)):
            print(f"Event # {i + 1}:")
            print(events[i])

def minter(client, auth_key):
    for x in range(0, 10):
        amount = 1000000
        faucet = testnet.Faucet(client)
        testnet.Faucet.mint(faucet, auth_key.hex(), amount, CURRENCY)
        time.sleep(1)

def subscribe(client, events_key):
    Thread(target=subscribe_, args=(client, events_key,)).start()

def start_minter(client, auth_key):
    Thread(target=minter, args=(client, auth_key)).start()

if __name__ == "__main__":
    main()
```

</TabItem>
<TabItem value="java">

```java title="https://github.com/diem/my-first-client/blob/master/java/src/main/java/example/GetEventsExample.java"

package example;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.diem.*;
import org.diem.jsonrpctypes.JsonRpc.Account;
import org.diem.jsonrpctypes.JsonRpc.Event;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * GetEventsExample demonstrates how to subscribe to a specific events stream base on events key
 */

public class GetEventsExample {
   public static final String CURRENCY_CODE = "XUS";
   public static void main(String[] args) throws DiemException {
       //connect to testnet
       DiemClient client = Testnet.createClient();
       //create new account
       SecureRandom random = new SecureRandom();
       Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(random);
       Ed25519PrivateKey privateKey = new Ed25519PrivateKey(privateKeyParams);
       AuthKey authKey = AuthKey.ed24419(privateKey.publicKey());
       Testnet.mintCoins(client, 100000000, authKey.hex(), CURRENCY_CODE);
       //get account events key
       Account account = client.getAccount(authKey.accountAddress());
       String eventsKey = account.getReceivedEventsKey();
       //start minter to demonstrates events creation
       startMinter(client, authKey);
       //demonstrates events subscription
       subscribe(client, eventsKey);
   }
   public static void subscribe(DiemClient client, String eventsKey) {
       Runnable listener = () -> {
           long start = 0;
           for (int i = 0; i &lt; 15; i++) {
               List&lt;Event> events;
               try {
                   events = client.getEvents(eventsKey, start, 10);
               } catch (DiemException e) {
                   throw new RuntimeException(e);
               }
               start += events.size();
               System.out.println(events.size() + " new events found");
               for (int j = 0; j &lt; events.size(); j++) {
                   System.out.println("Event #" + (j + 1) + ":");
                   System.out.println(events.get(j));
               }
               try {
                   Thread.sleep(3_000);
               } catch (InterruptedException e) {
                   throw new RuntimeException(e);
               }
           }
       };
       Thread listenerThread = new Thread(listener);
       listenerThread.start();
   }
   private static void startMinter(DiemClient client, AuthKey authKey) {
       Runnable minter = () -> {
           for (int i = 0; i &lt; 10; i++) {
               int amount =  1000000;
               Testnet.mintCoins(client, amount, authKey.hex(), CURRENCY_CODE);
               try {
                   Thread.sleep(1_000);
               } catch (InterruptedException e) {
                   throw new RuntimeException(e);
               }
           }
       };
       Thread minterThread = new Thread(minter);
       minterThread.start();
   }
}
```
</TabItem>
</Tabs>

###### tags: `core` `tutorials` `sdks`
