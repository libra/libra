---
id: query-the-blockchain
title: Query the Blockchain
---

The JSON-RPC service provides APIs for clients to query the Diem Blockchain. This tutorial will guide you through the different methods you can use. You can test these on testnet.

#### Assumptions

All commands in this document assume that:

* You are running on a Linux (Red Hat or Debian-based) or macOS system.
* You have a stable connection to the internet.

#### Prerequisites
* Complete the [My First Transaction](my-first-transaction.md) tutorial to understand how to create accounts and interact with testnet.

If you have already completed the My First Transaction tutorial, you can use the following account information for Alice and Bob to get started:
* [Account address: Hex-coded account address](my-first-transaction.md#step-4-optional-list-accounts)

## Get account information
To get information about Alice’s account, use [get_account](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_account.md). To run this method, you will need the hex-coded account address (see step 4 of My First Transaction).

In the example below, we have a request sent using [get_account](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_account.md) to learn information about Alice’s account and the response received.

```
// Request: fetches account for account address "5261f913eab22cfc448a815a0e672143"curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"get_account","params":["5261f913eab22cfc448a815a0e672143"],"id":1}' https://testnet.libra.org/v1
  // Response{  "libra_chain_id":2,  "libra_ledger_version":3052934,  "libra_ledger_timestampusec":1603827580322991,  "jsonrpc":"2.0",  "id":1,  "result":  {    "address":"5261f913eab22cfc448a815a0e672143",    "authentication_key":"8013a28f82e5ab390ff0b75762bf3d8c5261f913eab22cfc448a815a0e672143",    "balances":[      {        "amount":100000000,        "currency":"Coin1"      }    ],    "delegated_key_rotation_capability":false,    "delegated_withdrawal_capability":false,    "is_frozen":false,    "received_events_key":"02000000000000005261f913eab22cfc448a815a0e672143",    "role":      {        "base_url":"",        "base_url_rotation_events_key":"01000000000000005261f913eab22cfc448a815a0e672143",        "compliance_key":"",        "compliance_key_rotation_events_key":"00000000000000005261f913eab22cfc448a815a0e672143",        "expiration_time":18446744073709551615,        "human_name":"No. 3597",        "num_children":0,        "type":"parent_vasp"      },    "sent_events_key":"03000000000000005261f913eab22cfc448a815a0e672143",    "sequence_number":1  }}%
```


## Get transactions for an account
To see all the transactions sent by Alice’s account, you can use [get_account_transactions](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_account_transactions.md). You will need:
* Alice’s hex-code account address
* the starting sequence number
* the maximum number of transactions you want returned for this method

In the example below, we have a request sent using [get_account_transactions](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_account_transactions.md) to learn transaction information about Alice’s account and the response received.

```
// Request: fetches account for account address "5261f913eab22cfc448a815a0e672143"curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"get_account_transactions","params":["5261f913eab22cfc448a815a0e672143", 0, 100, false],"id":1}' https://testnet.libra.org/v1
//Response{  libra_chain_id":2,  "libra_ledger_version":3058809,  "libra_ledger_timestampusec":1603828579094476,  "jsonrpc":"2.0",  "id":1,  "result":[    {      "bytes":"005261f913eab22cfc448a815a0e672143000000000000000001e101a11ceb0b010000000701000202020403061004160205181d0735610896011000000001010000020001000003020301010004010300010501060c0108000506080005030a020a020005060c05030a020a020109000c4c696272614163636f756e741257697468647261774361706162696c6974791b657874726163745f77697468647261775f6361706162696c697479087061795f66726f6d1b726573746f72655f77697468647261775f6361706162696c69747900000000000000000000000000000001010104010c0b0011000c050e050a010a020b030b0438000b0511020201070000000000000000000000000000000105436f696e3105436f696e31000403701901dad4e06079cc701452ac48a99d0180969800000000000400040040420f0000000000000000000000000005436f696e319a75985f0000000002002043e9cc017c028e3a4537d7a434e10f4efe969e40b6874a9fded9a87fe8460cf8404b357285fcf6919188ada95517dfab76717faadc54aaef37e22c4bd0fbe4a450b7ba20e41e2629bb5754dd0a51af0a4360af8ac07d8f32419d197ff0401e830f","events":[],"gas_used":489,"hash":"40de7d62d0a7583e8670a2b2b872c63c51060cc2d86acdd191a739af77f239e6",      "transaction":      {        "chain_id":2,        "expiration_timestamp_secs":1603827098,        "gas_currency":"Coin1",        "gas_unit_price":0,        "max_gas_amount":1000000,        "public_key":"43e9cc017c028e3a4537d7a434e10f4efe969e40b6874a9fded9a87fe8460cf8",        "script":          {            "amount":10000000,            "arguments":[              "{ADDRESS: 701901DAD4E06079CC701452AC48A99D}",              "{U64: 10000000}",              "{U8Vector: 0x}",              "{U8Vector: 0x}"            ],            "code":"a11ceb0b010000000701000202020403061004160205181d0735610896011000000001010000020001000003020301010004010300010501060c0108000506080005030a020a020005060c05030a020a020109000c4c696272614163636f756e741257697468647261774361706162696c6974791b657874726163745f77697468647261775f6361706162696c697479087061795f66726f6d1b726573746f72655f77697468647261775f6361706162696c69747900000000000000000000000000000001010104010c0b0011000c050e050a010a020b030b0438000b05110202",            "currency":"Coin1",            "metadata":"",            "metadata_signature":"",            "receiver":"701901DAD4E06079CC701452AC48A99D",            "type":"peer_to_peer_with_metadata",            "type_arguments":["Coin1"]          },        "script_bytes":"e101a11ceb0b010000000701000202020403061004160205181d0735610896011000000001010000020001000003020301010004010300010501060c0108000506080005030a020a020005060c05030a020a020109000c4c696272614163636f756e741257697468647261774361706162696c6974791b657874726163745f77697468647261775f6361706162696c697479087061795f66726f6d1b726573746f72655f77697468647261775f6361706162696c69747900000000000000000000000000000001010104010c0b0011000c050e050a010a020b030b0438000b0511020201070000000000000000000000000000000105436f696e3105436f696e31000403701901dad4e06079cc701452ac48a99d01809698000000000004000400",        "script_hash":"61749d43d8f10940be6944df85ddf13f0f8fb830269c601f481cc5ee3de731c8",        "sender":"5261F913EAB22CFC448A815A0E672143",        "sequence_number":0,        "signature":"4b357285fcf6919188ada95517dfab76717faadc54aaef37e22c4bd0fbe4a450b7ba20e41e2629bb5754dd0a51af0a4360af8ac07d8f32419d197ff0401e830f",        "signature_scheme":"Scheme::Ed25519",        "type":"user"      },      "version":3049426,      "vm_status":{"type":"executed"}    }  ]}%
```


## Get the latest ledger state
You can check the current state of the testnet using [get_metadata](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_metadata.md).

The example below has the request and response received.

```
// Request: fetches current block metadatacurl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"get_metadata","params":[],"id":1}' https://testnet.libra.org/v1
//Response{  "libra_chain_id":2,  "libra_ledger_version":3063324,  "libra_ledger_timestampusec":1603829337973264,  "jsonrpc":"2.0",  "id":1,  "result":    {      "accumulator_root_hash":"a01b07539e4e6a303eeeefab2fe88be3671d4db80d6e4bd2cf19cef63e88b740",      "chain_id":2,      "libra_version":1,      "module_publishing_allowed":false,      "script_hash_allow_list":[        "6d9d309c5cc6df4c7082817eb657904781b06b2071552ae762806fce3b623463",        "570b8627a80ded5704775fc18060d58af396bb72565952fb0920221cc21ea9d1",        "19ea57b5051d34306353cc335baedbc022d28055cd6d76238a107ba433295930",        "a801d467df10ac00de027bc427637db66e8afc84a4bb94761b526016cb20a5ef",        "8f019b20740269011c05d8348cc7501bed64c7d56b8726eb8f4e21a01bd2eb4c",        "18da4e8c53fed321d58770e6c3f455848935cdc26153c3b41c166995787cff1d",        "5de6edd4b881622c4f7bc3bb9f2a1f98eeb8ca8483ad4e8dda3691c6bc5cbf32",        "bef38e6ed5ad51f0d060a4e194e4c8379cc6dfb60492c671a885f6752733866b",        "04ec5aec7f5cf5ea55e29cd65542134a7f4bb3c18421fecf00e5102dfe2d7efb",        "afabc7c4a2fd7b54734881f7e760e7d798cd93411839c20860a57e02eebd3893",        "ae693591b0d7169f4a68da27859fc055053b317c81836d6ef66a1418b1e9db5b",        "1a2c5cd660de7217f513bdfaa9c36bef8f384d018f128e7ddbb37dbb21f9b38f",        "387dce4a1f3421a369de8a48c070e7aa8e1e587ecadcf35fe254d3d8df0382b8",        "ff9e545db9c3546d892de6c6716d0a45929a721a14d478da3d689900eb16a394",        "61749d43d8f10940be6944df85ddf13f0f8fb830269c601f481cc5ee3de731c8",        "d01cd5656905ab073fefc899eb4af0c158ad3775d17f5d9731e5b5b040d52cfd",        "dfcfe1d8eb8e7a9dc1038b5d9d015c09c9e38ec6af310de7d5592de359092486",        "2b124c549e828df9bc38c6d45779d155f973116f077d8f0faa92c4d25389a4c1",        "c46e0e6d7579033024c73242b9a031d0d602f46222a79d1c86afcc07a1bbe59d",        "6aa259be3a3f160a5d0d089fdf14d70a3579d23b34bad2ae1dee50f52275ed9c",        "4820a09dae6cbfc9a77a060a919ad5913f91e6d52a75430c0672b44f241b70cc",        "8a1a527d4bf4b4993d525f1c1458235b47c26582762c6ac59cbc3162a0555499",        "157f747315d3cbf7695f6892b1aee3fb493d7fa231dd545fe5f173920b30e657",        "b4e23670c081e09e5da9f3c26aa31f84da8beab55ab299cfdddf64769551ed76",        "6adcf90ce474223545e2c204c1b48fab4ce28693a1d9bf51fb0f06d687d22a3f",        "ccf81752586ce59142e3625dd4aa7463f1e7167812f7de0ac82a924a0638284b",        "b33b71a6e98a50d8f41f00af92feec4fd77ede12d3ceb5052e53c6291920620d",        "7b7d7e02addc3dc14210d1db2baf17779b443b6dc9b70daf88cf4673d458f429",        "27d5e5756fd287f2c3e90bba57cfc82674b7d9890d9e65e4619b81fe6aa1d6c8",        "0e9dceaf3a66b076acb0ddd29041ddea4316716da26c88fdd55dad5fd862a3e3",        "b3a8003b1ebeafab289e75f8adec0f4fe80f7f220c01143173b0caf3b467fa6a",        "8e756eee24336712dcd5d03e20f2b97db7b1f74e26f077d41ba02175874dfd84",        "431c979535f701b76bfb0c4b51f35d4893dd30d4dd52bdf2f31c7002c0067369",        "ffbf8a2b64b711e61376c525a96b4206c791fc050e09a56c12d1ec187ad598ad"      ],      "timestamp":1603829337973264,      "version":3063324    }}%
```


## Get currencies available
Use [get_currencies](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_currencies.md) to query the types of currencies supported by the Diem Blockchain.

```
// Request: fetches currencies supported by the systemcurl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"get_currencies","params":[],"id":1}' https://testnet.libra.org/v1
// Response{  "libra_chain_id":2,  "libra_ledger_version":3068158,  "libra_ledger_timestampusec":1603830172248671,  "jsonrpc":"2.0",  "id":1,  "result":[    {      "burn_events_key":"06000000000000000000000000000000000000000a550c18",      "cancel_burn_events_key":"08000000000000000000000000000000000000000a550c18",      "code":"Coin1",      "exchange_rate_update_events_key":"09000000000000000000000000000000000000000a550c18",      "fractional_part":100,      "mint_events_key":"05000000000000000000000000000000000000000a550c18",      "preburn_events_key":"07000000000000000000000000000000000000000a550c18",      "scaling_factor":1000000,      "to_lbr_exchange_rate":1.0    },    {      "burn_events_key":"0b000000000000000000000000000000000000000a550c18",      "cancel_burn_events_key":"0d000000000000000000000000000000000000000a550c18",      "code":"LBR",      "exchange_rate_update_events_key":"0e000000000000000000000000000000000000000a550c18",      "fractional_part":1000,      "mint_events_key":"0a000000000000000000000000000000000000000a550c18",      "preburn_events_key":"0c000000000000000000000000000000000000000a550c18",      "scaling_factor":1000000,      "to_lbr_exchange_rate":1.0    }  ]}%

```

## All methods
You can use different methods to query the blockchain and get the information you’re looking for. We’ve included the complete list and their descriptions below.

| Method                                                       | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [get_transactions](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_transactions.md) | Get transactions on the Diem Blockchain.                    |
| [get_account](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_account.md) | Get the latest account information for a given account address. |
| [get_account_transactions](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_account_transactions.md) | Get transactions sent by a particular account.               |
| [get_metadata](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_metadata.md) | Get the blockchain metadata (for example, state as known to the current full node). |
| [get_events](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_events.md) | Get the events for a given event stream key.                 |
| [get_currencies](https://github.com/diem/diem/blob/main/json-rpc/docs/method_get_currencies.md) | Get information about all currencies supported by the Diem Blockchain. |


###### tags: `core`
