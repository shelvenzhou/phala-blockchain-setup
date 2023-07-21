require('dotenv').config();

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { typeDefinitions } = require('@polkadot/types');
const { ContractPromise } = require('@polkadot/api-contract');
const Phala = require('@phala/sdk');
const fs = require('fs');
const crypto = require('crypto');
const { PRuntimeApi } = require('./utils/pruntime');

const CENTS = 10_000_000_000;
const SECONDS = 1_000_000_000_000;
const defaultTxConfig = { gasLimit: "10000000000000" };

const BLOCK_INTERVAL = 12_000;

function loadContractFile(contractFile) {
    const metadata = JSON.parse(fs.readFileSync(contractFile));
    const constructor = metadata.spec.constructors.find(c => c.label == 'default').selector;
    const name = metadata.contract.name;
    const wasm = metadata.source.wasm;
    return { wasm, metadata, constructor, name };
}

async function estimateFee(api, system, cert, contract, salt) {
    // Estimate gas limit
    /*
        InkInstantiate {
            code_hash: sp_core::H256,
            salt: Vec<u8>,
            instantiate_data: Vec<u8>,
            /// Amount of tokens deposit to the caller.
            deposit: u128,
            /// Amount of tokens transfer from the caller to the target contract.
            transfer: u128,
        },
     */
    const instantiateReturn = await system.instantiate({
        codeHash: contract.metadata.source.hash,
        salt,
        instantiateData: contract.constructor, // please concat with args if needed
        deposit: 0,
        transfer: 0,
        estimating: true
    }, cert);

    // console.log("instantiate result:", instantiateReturn);
    const queryResponse = api.createType('InkResponse', instantiateReturn);
    const queryResult = queryResponse.result.toHuman()
    // console.log("InkMessageReturn", queryResult.Ok.InkMessageReturn);
    // const instantiateResult = api.createType('ContractInstantiateResult', queryResult.Ok.result);
    // console.assert(instantiateResult.result.isOk, 'fee estimation failed');
    return instantiateReturn;
}

async function deployContract(api, txqueue, system, pair, cert, contract, clusterId, salt) {
    console.log(`Contract: deploying ${contract.name}`);

    // upload the contract
    await txqueue.submit(
        api.tx.phalaPhatContracts.clusterUploadResource(clusterId, 'InkCode', contract.wasm),
        pair);

    // Not sure how much time it would take to sync the code into pruntime
    console.log('Waiting the code to be synced into pruntime');
    await sleep(10000);

    salt = salt ? salt : hex(crypto.randomBytes(4));
    let estimatedFee = await estimateFee(api, system, cert, contract, salt);

    const { events: deployEvents } = await txqueue.submit(
        /*
        pub fn instantiate_contract(
            origin: OriginFor<T>,
            code_index: CodeIndex<CodeHash<T>>,
            data: Vec<u8>,
            salt: Vec<u8>,
            cluster_id: ContractClusterId,
            transfer: u128,
            gas_limit: u64,
            storage_deposit_limit: Option<u128>,
        ) -> DispatchResult {
        */
        api.tx.phalaPhatContracts.instantiateContract(
            { WasmCode: contract.metadata.source.hash },
            contract.constructor,
            salt,
            clusterId,
            0,
            estimatedFee.gasRequired.refTime,
            estimatedFee.storageDeposit.asCharge || 0,
            0,
        ),
        pair
    );
    const contractIds = deployEvents
        .filter(ev => ev.event.section == 'phalaPhatContracts' && ev.event.method == 'Instantiating')
        .map(ev => ev.event.data[0].toString());
    const numContracts = 1;
    console.assert(contractIds.length == numContracts, 'Incorrect length:', `${contractIds.length} vs ${numContracts}`);
    contract.address = contractIds[0];
    await checkUntilEq(
        async () => (await api.query.phalaPhatContracts.clusterContracts(clusterId))
            .filter(c => contractIds.includes(c.toString()))
            .length,
        numContracts,
        8 * BLOCK_INTERVAL
    );
    await checkUntil(
        async () => (await api.query.phalaRegistry.contractKeys(contract.address)).isSome,
        8 * BLOCK_INTERVAL
    );
    console.log(`Contract: ${contract.name} deployed to ${contract.address}`);
}

async function deployDriverContract(api, txqueue, system, pair, cert, contract, clusterId, name, salt) {
    // check the existense of driver contract
    const { output } = await system.query["system::getDriver"](cert, {}, name);
    if (output?.asOk.isSome) {
        contract.address = output?.asOk.unwrap().toHex();
        console.log(`Driver ${name} exists in ${contract.address}`);
        return contract.address;
    }

    await deployContract(api, txqueue, system, pair, cert, contract, clusterId, salt);

    // use query to estimate the required gas for system::setDriver
    const { gasRequired, storageDeposit } = await system.query["system::setDriver"](cert, {}, name, contract.address);
    const options = {
        value: 0,
        gasLimit: gasRequired,
        storageDepositLimit: storageDeposit.isCharge ? storageDeposit.asCharge : null
    };
    await txqueue.submit(
        system.tx["system::setDriver"](options, name, contract.address),
        pair
    );
    await txqueue.submit(
        system.tx["system::grantAdmin"](defaultTxConfig, contract.address),
        pair
    );

    console.log('Driver: wait for registration');
    await checkUntil(
        async () => {
            const { output } = await system.query["system::getDriver"](cert, {}, name);
            return output?.asOk.isSome && output?.asOk.unwrap().eq(contract.address);
        },
        8 * BLOCK_INTERVAL
    );
    console.log(`Driver ${name} set to ${contract.address}`)
    return contract.address;
}

async function uploadSystemCode(api, txqueue, pair, wasm) {
    console.log(`Uploading system code`);
    await txqueue.submit(
        api.tx.sudo.sudo(api.tx.phalaPhatContracts.setPinkSystemCode(hex(wasm))),
        pair
    );
    await checkUntil(async () => {
        let code = await api.query.phalaPhatContracts.pinkSystemCode();
        return code[1] == wasm;
    }, 8 * BLOCK_INTERVAL);
    console.log(`Uploaded system code`);
}

class TxQueue {
    constructor(api) {
        this.nonceTracker = {};
        this.api = api;
    }
    async nextNonce(address) {
        const byCache = this.nonceTracker[address] || 0;
        const byRpc = (await this.api.rpc.system.accountNextIndex(address)).toNumber();
        return Math.max(byCache, byRpc);
    }
    markNonceFailed(address, nonce) {
        if (!this.nonceTracker[address]) {
            return;
        }
        if (nonce < this.nonceTracker[address]) {
            this.nonceTracker[address] = nonce;
        }
    }
    async submit(txBuilder, signer, waitForFinalization = false) {
        const address = signer.address;
        const nonce = await this.nextNonce(address);
        this.nonceTracker[address] = nonce + 1;
        let hash;
        return new Promise(async (resolve, reject) => {
            const unsub = await txBuilder.signAndSend(signer, { nonce }, (result) => {
                if (result.status.isInBlock) {
                    for (const e of result.events) {
                        const { event: { data, method, section } } = e;
                        if (section === 'system' && method === 'ExtrinsicFailed') {
                            unsub();
                            reject(data[0].toHuman())
                        }
                    }
                    if (!waitForFinalization) {
                        unsub();
                        resolve({
                            hash: result.status.asInBlock,
                            events: result.events,
                        });
                    } else {
                        hash = result.status.asInBlock;
                    }
                } else if (result.status.isFinalized) {
                    resolve({
                        hash,
                        events: result.events,
                    })
                } else if (result.status.isInvalid) {
                    unsub();
                    this.markNonceFailed(address, nonce);
                    reject('Invalid transaction');
                }
            });
        });
    }
}

async function sleep(t) {
    await new Promise(resolve => {
        setTimeout(resolve, t);
    });
}

async function checkUntil(async_fn, timeout) {
    const t0 = new Date().getTime();
    while (true) {
        if (await async_fn()) {
            return;
        }
        const t = new Date().getTime();
        if (t - t0 >= timeout) {
            throw new Error('timeout');
        }
        await sleep(100);
    }
}

async function checkUntilEq(async_fn, expected, timeout, verbose = true) {
    const t0 = new Date().getTime();
    let lastActual = undefined;
    while (true) {
        const actual = await async_fn();
        if (actual == expected) {
            return;
        }
        if (actual != lastActual && verbose) {
            console.log(`Waiting... (current = ${actual}, expected = ${expected})`)
            lastActual = actual;
        }
        const t = new Date().getTime();
        if (t - t0 >= timeout) {
            throw new Error('timeout');
        }
        await sleep(100);
    }
}

function hex(b) {
    if (typeof b != "string") {
        b = Buffer.from(b).toString('hex');
    }
    if (!b.startsWith('0x')) {
        return '0x' + b;
    } else {
        return b;
    }
}

async function forceRegisterWorker(api, txpool, pair, worker) {
    console.log('Worker: registering', worker);
    await txpool.submit(
        api.tx.sudo.sudo(
            api.tx.phalaRegistry.forceRegisterWorker(worker, worker, null)
        ),
        pair,
    );
    await checkUntil(
        async () => (await api.query.phalaRegistry.workers(worker)).isSome,
        8 * BLOCK_INTERVAL
    );
    console.log('Worker: added');
}

async function setupGatekeeper(api, txpool, pair, worker) {
    const gatekeepers = await api.query.phalaRegistry.gatekeeper();
    if (gatekeepers.toHuman().includes(worker)) {
        console.log('Gatekeeper: skip', worker);
        return;
    }
    console.log('Gatekeeper: registering');
    await txpool.submit(
        api.tx.sudo.sudo(
            api.tx.phalaRegistry.registerGatekeeper(worker)
        ),
        pair,
    );
    await checkUntil(
        async () => (await api.query.phalaRegistry.gatekeeper()).toHuman().includes(worker),
        8 * BLOCK_INTERVAL
    );
    console.log('Gatekeeper: added');
    await checkUntil(
        async () => (await api.query.phalaRegistry.gatekeeperMasterPubkey()).isSome,
        8 * BLOCK_INTERVAL
    );
    console.log('Gatekeeper: master key ready');
}

async function deployCluster(api, txqueue, sudoer, owner, workers, treasury, defaultCluster = '0x0000000000000000000000000000000000000000000000000000000000000001') {
    const clusterInfo = await api.query.phalaPhatContracts.clusters(defaultCluster);
    if (clusterInfo.isSome) {
        return { clusterId: defaultCluster, systemContract: clusterInfo.unwrap().systemContract.toHex() };
    }
    console.log('Cluster: creating');
    // crete contract cluster and wait for the setup
    const { events } = await txqueue.submit(
        api.tx.sudo.sudo(api.tx.phalaPhatContracts.addCluster(
            owner,
            'Public', // can be {'OnlyOwner': accountId}
            workers,
            "100000000000000", // 100 PHA
            1, 1, 1, treasury.address
        )),
        sudoer
    );
    const ev = events[1].event;
    console.assert(ev.section == 'phalaPhatContracts' && ev.method == 'ClusterCreated');
    const clusterId = ev.data[0].toString();
    const systemContract = ev.data[1].toString();
    console.log('Cluster: created on chain', clusterId);

    console.log('Cluster: wait for GK key generation');
    await checkUntil(
        async () => (await api.query.phalaRegistry.clusterKeys(clusterId)).isSome,
        8 * BLOCK_INTERVAL
    );

    console.log('Cluster: wait for system contract instantiation');
    await checkUntil(
        async () => (await api.query.phalaRegistry.contractKeys(systemContract)).isSome,
        8 * BLOCK_INTERVAL
    );
    return { clusterId, systemContract };
}

async function contractApi(api, pruntimeUrl, contract) {
    const newApi = await api.clone().isReady;
    const phala = await Phala.create({ api: newApi, baseURL: pruntimeUrl, contractId: contract.address, autoDeposit: true });
    const contractApi = new ContractPromise(
        phala.api,
        contract.metadata,
        contract.address,
    );
    contractApi.sidevmQuery = phala.sidevmQuery;
    contractApi.instantiate = phala.instantiate;
    return contractApi;
}

function toBytes(s) {
    let utf8Encode = new TextEncoder();
    return utf8Encode.encode(s)
}

function loadUrls(exp, defaultVal) {
    if (!exp) {
        return defaultVal
    }
    return exp.trim().split(',');
}

async function main() {
    const nodeUrl = process.env.ENDPOINT || 'wss://poc5.phala.network/ws';
    const workerUrls = loadUrls(process.env.WORKERS, ['https://poc5.phala.network/tee-api-1']);
    const gatekeeperUrls = loadUrls(process.env.GKS, ['https://poc5.phala.network/gk-api']);

    const sudoAccount = process.env.SUDO || '//Alice';
    const treasuryAccount = process.env.TREASURY || '//Treasury';
    const driversDir = process.env.DRIVERS_DIR || './res';

    const contractSystem = loadContractFile(`${driversDir}/system.contract`);
    const contractSidevmop = loadContractFile(`${driversDir}/sidevm_deployer.contract`);
    const contractLogServer = loadContractFile(`${driversDir}/log_server.contract`);
    const contractTokenomic = loadContractFile(`${driversDir}/tokenomic.contract`);
    const contractQjs = loadContractFile(`${driversDir}/qjs.contract`);
    const logServerSidevmWasm = fs.readFileSync(`${driversDir}/log_server.sidevm.wasm`, 'hex');

    // Connect to the chain
    const wsProvider = new WsProvider(nodeUrl);
    const api = await ApiPromise.create({
        provider: wsProvider,
        types: {
            ...Phala.types,
            'GistQuote': {
                username: 'String',
                accountId: 'AccountId',
            },
            ...typeDefinitions.contracts.types,
        }
    });
    const txqueue = new TxQueue(api);

    // Prepare accounts
    const keyring = new Keyring({ type: 'sr25519' });
    const sudo = keyring.addFromUri(sudoAccount);
    const treasury = keyring.addFromUri(treasuryAccount);
    const certSudo = await Phala.signCertificate({ api, pair: sudo });

    // Connect to pruntimes
    const workers = await Promise.all(workerUrls.map(async w => {
        let api = new PRuntimeApi(w);
        let pubkey = hex((await api.getInfo()).publicKey);
        return {
            url: w,
            pubkey: pubkey,
            api: api,
        };
    }));
    console.log('Workers:', workers);

    // Basic phala network setup
    for (const w of workers) {
        await forceRegisterWorker(api, txqueue, sudo, w.pubkey);
        await w.api.addEndpoint({ encodedEndpointType: [1], endpoint: w.url }); // EndpointType: 0 for I2P and 1 for HTTP
    }
    if (gatekeeperUrls) {
        const gatekeepers = await Promise.all(gatekeeperUrls.map(async w => {
            let api = new PRuntimeApi(w);
            let pubkey = hex((await api.getInfo()).publicKey);
            return {
                url: w,
                pubkey: pubkey,
                api: api,
            };
        }));
        console.log('Gatekeepers', gatekeepers);
        for (const w of gatekeepers) {
            await forceRegisterWorker(api, txqueue, sudo, w.pubkey);
            await setupGatekeeper(api, txqueue, sudo, w.pubkey);
        }
    }

    // Upload the pink-system wasm to the chain. It is required to create a cluster.
    await uploadSystemCode(api, txqueue, sudo, contractSystem.wasm);

    const { clusterId, systemContract } = await deployCluster(api, txqueue, sudo, sudo.address, workers.map(w => w.pubkey), treasury);
    contractSystem.address = systemContract;
    console.log('Cluster system contract address:', systemContract);

    let default_worker = workers[0];
    let pruntimeUrl = default_worker.url;
    console.log(`Connect to ${pruntimeUrl} for query`);

    const system = await contractApi(api, pruntimeUrl, contractSystem);

    // Transfer some tokens to the cluster for owner
    await txqueue.submit(
        api.tx.phalaPhatContracts.transferToCluster(CENTS * 100, clusterId, sudo.address),
        sudo,
    );

    // Deploy the tokenomic contract
    await deployDriverContract(api, txqueue, system, sudo, certSudo, contractTokenomic, clusterId, "ContractDeposit");

    // Stake some tokens to the system contract
    const stakedCents = 42;
    await txqueue.submit(
        api.tx.phalaPhatTokenomic.adjustStake(systemContract, CENTS * stakedCents),
        sudo
    );
    // Contract weight should be affected
    await checkUntilEq(
        async () => {
            const { weight } = (await default_worker.api.getContractInfo(systemContract));
            return weight;
        },
        stakedCents,
        10 * BLOCK_INTERVAL
    );

    // Total stakes to the contract should be changed
    const total = await api.query.phalaPhatTokenomic.contractTotalStakes(systemContract);
    console.assert(total.eq(CENTS * stakedCents), "total stake does not match");

    // Stakes of the user
    const stakesOfOwner = await api.query.phalaPhatTokenomic.contractUserStakes.entries(sudo.address);
    console.log('Stakes of cluster owner:');
    stakesOfOwner.forEach(([key, stake]) => {
        console.log('contract:', key.args[1].toHex());
        console.log('   stake:', stake.toHuman());
    });

    // Deploy the QuickJS engine
    const { output } = await system.query["system::getDriver"](certSudo, {}, 'JsDelegate');
    if (output?.asOk.isSome) {
        contractQjs.address = output?.asOk.unwrap().toHex();
        console.log(`Driver JsDelegate exists in ${contractQjs.address}`);
    } else {
        console.log('Waiting the qjs to be synced into pruntime');
        await txqueue.submit(api.tx.phalaPhatContracts.clusterUploadResource(clusterId, 'IndeterministicInkCode', contractQjs.wasm), sudo);
        console.log(`Set JsDelegate code`);
        await txqueue.submit(
            system.tx["system::setDriver"]({ gasLimit: "10000000000000" }, 'JsDelegate', contractQjs.metadata.source.hash),
            sudo
        );
        console.log('Driver: wait for registration');
        await checkUntil(async () => {
            const { output } = await system.query["system::getDriver"](
                certSudo,
                {},
                "JsDelegate"
            );
            return output?.asOk.isSome;
        }, 8 * BLOCK_INTERVAL);
    }

    // Deploy driver: Sidevm deployer
    await deployDriverContract(api, txqueue, system, sudo, certSudo, contractSidevmop, clusterId, "SidevmOperation");

    const sidevmDeployer = await contractApi(api, pruntimeUrl, contractSidevmop);

    // Allow the logger to deploy sidevm
    const salt = hex(crypto.randomBytes(4));
    const { id: loggerId } = await default_worker.api.calculateContractId({
        deployer: hex(sudo.publicKey),
        clusterId,
        codeHash: contractLogServer.metadata.source.hash,
        salt,
    });
    console.log(`calculated loggerId = ${loggerId}`);

    // authrize contract to start sidevm in advance
    await txqueue.submit(
        sidevmDeployer.tx.allow(defaultTxConfig, loggerId),
        sudo
    );
    console.log('SideVM: allowing logger contract');
    await checkUntil(
        async () => {
            let { output } = await sidevmDeployer.query['sidevmOperation::canDeploy'](certSudo, {}, loggerId);
            return output.asOk;
        },
        8 * BLOCK_INTERVAL
    );

    // Upload the logger's sidevm wasm code
    await txqueue.submit(
        api.tx.phalaPhatContracts.clusterUploadResource(clusterId, 'SidevmCode', hex(logServerSidevmWasm)),
        sudo);
    console.log('Waiting the code to be synced into pruntime');
    await sleep(10000);

    // Deploy the logger contract
    await deployDriverContract(api, txqueue, system, sudo, certSudo, contractLogServer, clusterId, "PinkLogger", salt);

    await sleep(2000);
    const logger = await contractApi(api, pruntimeUrl, contractLogServer);
    // Trigger some contract logs
    for (var i = 0; i < 5; i++) {
        await logger.query.logTest(certSudo, {}, "hello " + i);
    }
    // Query input: a JSON doc with three optinal fields:
    const condition = {
        // What to do. Only `GetLog` is supported currently
        action: 'GetLog',
        // The target contract to query. Default to all contracts
        contract: contractLogServer.address,
        // The sequence number start from. Default to 0.
        from: 1,
        // Max number of items should returned. Default to not limited.
        count: 2,
    };
    const data = hex(toBytes(JSON.stringify(condition)));
    const hexlog = await logger.sidevmQuery(data, certSudo);

    // Log parsing
    const resp = api.createType('InkResponse', hexlog);
    const result = resp.result.toHuman()
    const text = result.Ok.InkMessageReturn
    console.log('log:', text)

    // Sample query response:
    const _ = {
        "next": 3, // Sequence number for the next query. For pagination.
        "records": [
            {
                "blockNumber": 0,
                "contract": "0x0101010101010101010101010101010101010101010101010101010101010101",
                "inQuery": true,
                "level": 0,
                "message": "hello", // Log content
                "sequence": 0,
                "timestamp": 1,
                "type": "Log" // Type of the records. could be one of ['Log', 'Event', 'MessageOutput']
            },
            {
                "blockNumber": 1,
                "contract": "0x0101010101010101010101010101010101010101010101010101010101010101",
                "payload": "0x01020304",
                "sequence": 1,
                "topics": [
                    "0x0202020202020202020202020202020202020202020202020202020202020202",
                    "0x0303030303030303030303030303030303030303030303030303030303030303"
                ],
                "type": "Event"
            },
            {
                "blockNumber": 2,
                "contract": "0x0202020202020202020202020202020202020202020202020202020202020202",
                "nonce": "0x0102030405",
                "origin": "0x0101010101010101010101010101010101010101010101010101010101010101",
                "output": "0x0504030201",
                "sequence": 2,
                "type": "MessageOutput"
            }
        ]
    };
}

main().then(process.exit).catch(err => console.error('Crashed', err)).finally(() => process.exit(-1));
