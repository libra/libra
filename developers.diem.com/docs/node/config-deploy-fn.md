---
id: config-deploy-fn
title: Configure and Run Public Full Node
sidebar_label: Configure Public Full Node
---

You can run [FullNodes](/core/nodes.md#fullnodes) to verify the state and synchronize to the Diem Blockchain. FullNodes can be run by anyone. FullNodes replicate the full state of the blockchain by querying each other, or by querying the validators directly.

This tutorial details how to configure a public FullNode to connect to *testnet*, the Diem Payment Network’s public test network.

>
> **Note:** Your public FullNode will be connected to testnet with a JSON-RPC endpoint accessible on your computer at localhost:8080.
>

#### Prerequisites
Before you get started with this tutorial, we recommend you familiarize yourself with the following:
* [Diem node concepts](/core/nodes.md)
* [JSON-RPC specifications](https://github.com/diem/diem/blob/main/json-rpc/json-rpc-spec.md)
* [CLI reference](/core/diem-cli.md)


## Getting started
You can configure a public FullNode in two ways: using the Diem Core source code or Docker.

### Using Diem Core source code
1. Download and clone the Diem Core repository from GitHub and prepare your developer environment by running the following commands:
     ```
     git clone https://github.com/diem/diem.git
     cd diem
     ./scripts/dev_setup.sh
     source ~/.cargo/env
     ```

2. Checkout the branch for testnet using `git checkout origin/testnet`.

3. To prepare your configuration file:

     * Copy `config/src/config/test_data/public_full_node.yaml` to your current working directory.

     * Download [genesis](https://testnet.diem.com/genesis.blob) and [waypoint](https://testnet.diem.com/waypoint.txt) files for testnet.

     * Update the public_full_node.yaml file in your current working directory by:

       * Specifying the directory where you want testnet to store its database next to `base:data_dir`; for example, `./data`.

       * Copying and pasting the contents of the waypoint file to the `waypoint` field.

       * Adding the path where your Genesis file is located to `genesis_file_location`.

       * Adding the following under `full_node_networks`.

          ```
          	seed_addrs:
                D4C4FB4956D899E55289083F45AC5D84:
                    - "/dns4/fn.testnet.diem.com/tcp/6182/ln-noise-ik/d29d01bed8ab6c30921b327823f7e92c63f8371456fb110256e8c0e8911f4938/ln-handshake/0"
          ```

       * Disable on-chain discovery for the `discovery_method: "none"` (this is not required but it will limit log spew)

       * Reading through the config and making any other desired changes. You can see what configurations the `public_full_node.yaml` file should have by checking the following file as an example: `docker/compose/public_full_node/public_full_node.yaml`
4. Run the libra-node using `cargo run -p diem-node -- -f ./public_full_node.yaml`



You have now successfully configured and started running a public FullNode in testnet.

## Using Docker

You can also use Docker to configure and run your PublicFullNode.

1. Install Docker and Docker-Compose.
2. Create a directory for your public FullNode composition.
3. Download the public FullNode [docker compose](https://github.com/diem/diem/tree/main/docker/compose/public_full_node/docker-compose.yaml) and [diem](https://github.com/diem/diem/tree/main/docker/compose/public_full_node/public_full_node.yaml) configuration files into this directory.
4. Download [genesis](https://testnet.diem.com/genesis.blob) and [waypoint](https://testnet.diem.com/waypoint.txt) files for testnet into that directory.
5. Run docker-compose: `docker-compose up`.


### Understand and verify the correctness of your FullNode

#### Initial synchronization
During the initial synchronization of your FullNode, there may be a lot of data to transfer.

* The Executor component will update the output log by showing that 250 blocks are committed at a time:

  ```
  fullnode_1  | INFO 2020-09-28T23:16:04.425083Z execution/executor/src/lib.rs:534 sync_request_received {"local_synced_version":633750,"name":"chunk_executor","first_version_in_request":633751,"num_txns_in_request":250}
  fullnode_1  | INFO 2020-09-28T23:16:04.508902Z execution/executor/src/lib.rs:580 sync_finished {"committed_with_ledger_info":false,"name":"chunk_executor","synced_to_version":634000}
  ```

* At the same time, the StateSync component will output similar information but show the destination.

* The blockchain (testnet) ledger’s volume can be monitored by entering the container:

  ```
  # Obtain the container id:
  id=$(docker container ls | grep public_full_node_fullnode_1 | grep -oE "^[0-9a-zA-Z]+")
  # Enter the container:
  docker exec -it $id /bin/bash
  # Observe the volume (ledger) size:
  du -cs -BM /opt/diem/data
  ```


  ###### tags: `node`
