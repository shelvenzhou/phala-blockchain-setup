# Chain Setup Scripts for Phat Contract Cluster

## Resources

All the contracts are compiled from <https://github.com/Phala-Network/phala-blockchain/tree/master/crates/pink-drivers>.

## Usage

### Cluster Setup

To setup the blockchain, run

```shell
ENDPOINT=ws://localhost:9944 \
WORKERS=http://localhost:8000 \
GKS=http://localhost:8000 \
yarn setup:drivers
```

This will
- Register the Workers and setup their endpoints;
- Register the Gatekeepers;
- Upload the System contract code in the `res/` folder;
- Create Cluster 0x0 with `Alice` as the owner and the System contract above;
- Register two Drivers to the System contract
  - the log server printing all the Phat contracts' log;
  - the SideVM deployer controlling which contracts can start the SideVM;

### SideVM Auth

To authorized certain contract to call the `start_sidevm`. First, upload your contract using <https://phat.phala.network/> and get the contract id, then run

```shell
AUTH_CONTRACT=0x_your_contract_id \
ENDPOINT=ws://localhost:9944 \
WORKERS=http://localhost:8000 \
GKS=http://localhost:8000 \
yarn cluster:auth_sidevm
```

### Dump Logs

Dump the full log from the SideVM logger in a worker:

```
ENDPOINT=ws://localhost:9944 \
WORKERS=http://localhost:8000 \
yarn util:dump_logs
```
