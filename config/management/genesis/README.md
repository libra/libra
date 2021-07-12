# Diem Config Manager

The `diem-genesis-tool` provides a tool for the genesis ceremony of the Diem blockchain. The functionality of the tool is dictated by the organization of nodes within the system:

* A diem root account that maintains the set of validator owners, validator operators, and the active validator set.
* A treasury compliance account that maintains VASPs, DDs, and other related topics.
* The initial set of Move modules published at genesis.
* Validator owners (OW) that have accounts on the blockchain. These accounts contain a validator configuration and specify a validator operator.
* Validator operators (OP) that have accounts on the blockchain. These accounts have the ability to manipulate validator configuration.
## Generating Genesis

The process for starting organization of the planned and current functionality includes:

* Initialization ceremony
  * The association sets up a secure-backend for data uploads, `shared storage`, e.g., GitHub.  The association then distributes credentials for each OW and OP.
  * The association generates its `diem root key` and shares the public key to the `shared storage`.
  * The association uploads the initial set of Move modules to `shared storage`.
  * Each OW will generate a private `owner key` and share the public key to the `shared storage`.
  * Each OP will generate a private `operator key` and share the public key to the `shared storage`.
* Validator initialization
  * Each OW will select a OP and submit this as a transaction signed by their `owner key` and uploads it to the `shared storage`.
  * For each validator supported by a OP, the OP will generate network, execution and consensus keys as well as network addresses for full node and validator endpoints. The OP will generate a transaction containing this data signed by their `operator key` and uploads it to the `shared storage`.
* Genesis
  * Each OP will download the accumulated data to produce a genesis.blob
  * The association will download the accumulated data to produce both a genesis.blob and genesis waypoint.
* Starting
  * The association publishes the data associated with genesis, the genesis.blob, and the genesis waypoint.
  * Each OP downloads the genesis waypoint provided by the association and inserts it into their Diem instance(s).
  * Each OP verifies that the genesis.blob, waypoint, and local configuration are correct and broadcast their results to other OPs and the association.
  * Upon a quorum of validators having correct status, the association instructs the OPs to begin their validators.
  * Upon a quorum of validators coming online, the blockchain will begin processing transactions.

Notes:
* This describes a process for instantiating organization that has yet to be specified but extends from the current state of the Diem Testnet.
* The implementation as described has yet to be fully implemented in Move, hence, this tool maps to the current state.
* A new OP / OW onboarding to an existing blockchain follow the same process and delegate the initial creation of accounts and setting of configuration to the association.

## Requirements

Each individual instance, OW or OP, should have access to a secure storage solution. Those leveraging Diem Secure Storage can directly use this tool, those that do not will need to provide their own tooling.

## The Tools

`diem-genesis-tool` offers several facilities:

* Simplified configuration management via a config file that can store frequently reused paramters including validator and shared storage.
* Retrieving and submitting OW, OP, and validator configuration -- this is from a local secure storage to a remote secure storage -- leveraging the identity tool.
* Converting a genesis configuration and a secure storage into a genesis.blob / genesis waypoint.

## The Process

The end-to-end process assumes that each participant has their own secure storage solution, e.g., Vault, and a token stored locally on their disk in a file accessible to the management tool.

In addition, the association will provide an entry point into a `shared storage`, e.g., GitHub repository (and repository owner) along with a distinct namespace for each participant. GitHub namespaces equate to directories within the repository.

Each participant must retrieve an appropriate GitHub [token](https://github.com/settings/tokens) for their account that allows access to the `repo` scope. This token must be stored locally on their disk in a file accessible to the management tool.

Finally, each participant should initialize their respective key: `diem_root`, `treasury_compliance`, `owner`, or `operator` in a secure storage solution. How this is done is outside the scope of this document.

The remainder of this section specifies distinct behaviors for each role.

### Build a Configuration File

While `diem-genesis-tool` supports setting the backends on each command, doing so is cumbersome and fraught with error. Instead, all participants, should first construct a configuration file for use in genesis and later use via the operational tool. Below is an example configuration file in yaml format:

```
# config.yaml

chain_id: "MAINNET"
json_server: "http://127.0.0.1:8080"
shared_backend:
    type: "github"
    repository_owner: "REPOSITORY_OWNER"
    repository: "REPOSITORY"
    namespace: "REPOSITOR_FOLDER"
    token:
        from_config: "test"
validator_backend:
    type: "vault"
    server: "127.0.0.1:8200"
    namespace: "VIRTUAL_NAMESPACE"
    token:
        from_config: "test"
```

Overview of fields:

* `chain_id` specifies a distinct chain and is written into genesis, checked during network connections, and part of each transaction. It is provided by the association.
* `json_server` specifies a Diem JSON Server. This can be any that connect to your network including your own of one run by the association. It is not used in genesis, so a dummy value is acceptable during initial configuration.
* `shared_backend` is a pointer to the associaton's `shared storage`.
* `validator_backend` is a pointer to the local validator node's secure storage.

### The Association

* The association will publish a layout containing the distinct names and roles of the participants to `shared storage`:
```
cargo run -p diem-genesis-tool -- \
    set-layout \
    --config config_file.yaml \
    --path $PATH_TO_LAYOUT
```
* The association will publish the initial set of Move modules to `shared storage`:
```
cargo run -p diem-genesis-tool -- \
    set-move-modules \
    --config config_file.yaml \
    --dir $MOVE_MODULES_DIR
```
This should be a directory containing only Move bytecode files (`.mv` extension).
* The association will publish the the `diem root`  public key to the `shared storage`:
```
cargo run -p diem-genesis-tool -- \
    diem-root-key \
    --config config_file.yaml
```
* The association will publish the the `treasury compliance` public key to the `shared storage`:
```
cargo run -p diem-genesis-tool -- \
    diem-treasury-compliance-key \
    --config config_file.yaml
```
* Upon both OW and OP completing their portion of this process, the association will build a genesis waypoint:
```
cargo run -p diem-genesis-tool -- \
    create-waypoint \
    --config config_file.yaml
```

The layout is a toml configuration file of the following format:
```
[operator] = ["alice", "bob"]
[owner] = ["carol", "dave"]
diem_root = "erin"
treasury_compliance = "fred"
```
where each field maps to a role as described in this document.

### Validator Owners

* Each Validator Owner member will upload their key to GitHub:
```
cargo run -p diem-genesis-tool -- \
    owner-key \
    --config config_file.yaml
```
* Each OW will select the OP responsible for operating the validator node. This selection is done by specifying the name of the OP (as registered in the shared Github):
```
cargo run -p diem-genesis-tool --
    set-operator \
    --config config_file.yaml \
    --operator-name $OPERATOR_NAME
```

### Validator Operators

* Each Validator Operator member will upload their key to GitHub:
```
cargo run -p diem-genesis-tool --
    operator-key \
    --config config_file.yaml
```
* For each validator managed by an operator, the operator will upload a signed validator-config. The owner corresponds to the name of the OW (as registered in the shared Github). The namespace in GitHub correlates to the operator namespace:
```
cargo run -p diem-genesis-tool --
    validator-config \
    --config config_file.yaml \
    --owner-name $OWNER_NAME \
    --validator-address "/dns/$VALIDATOR_DNS/tcp/$VALIDATOR_PORT" \
    --fullnode-address "/dns/$VFN_DNS/tcp/$VFN_PORT" \
```
* Upon receiving signal from the association, OPs can now build genesis:
```
cargo run -p diem-genesis-tool -- \
    genesis \
    --config config_file.yaml \
    --path $PATH_TO_GENESIS \
```
* Similarly, the association should publish a genesis waypoint, and the OP should insert it into their storage (using the management tool):
```
cargo run -p diem-genesist-tool -- \
    insert-waypoint \
    --config config_file.yaml \
    --waypoint $WAYPOINT
```
* Perform a verify that ensures the local store maps to Genesis and Genesis maps
  to the waypoint:
```
cargo run -p diem-genesis-tool -- \
    verify \
    --config config_file.yaml \
    --genesis_path $PATH_TO_GENESIS
```

### Important Notes

* A namespace in Vault is represented as a subdirectory for secrets and a prefix followed by `__` for transit, e.g., `namespace__`.
* A namespace in GitHub is represented by a subdirectory
* The GitHub repository and repository owner translate into the following url: `https://github.org/REPOSITORY_OWNER/REPOSITORY`
