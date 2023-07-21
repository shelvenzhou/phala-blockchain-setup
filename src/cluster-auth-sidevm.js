require('dotenv').config();

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { ContractPromise } = require('@polkadot/api-contract');
const Phala = require('@phala/sdk');
const fs = require('fs');
const crypto = require('crypto');
const { PRuntimeApi } = require('./utils/pruntime');

function loadContractFile(contractFile) {
    const metadata = JSON.parse(fs.readFileSync(contractFile));
    const constructor = metadata.V3.spec.constructors.find(c => c.label == 'default').selector;
    const name = metadata.contract.name;
    const wasm = metadata.source.wasm;
    return { wasm, metadata, constructor, name };
}

async function deployContract(api, txqueue, pair, contract, clusterId, salt) {
    console.log(`Contract: deploying ${contract.name}`);
    // upload the contract
    const { events: deployEvents } = await txqueue.submit(
        api.tx.utility.batchAll(
            [
                api.tx.phalaFatContracts.clusterUploadResource(clusterId, 'InkCode', contract.wasm),
                api.tx.phalaFatContracts.instantiateContract(
                    { WasmCode: contract.metadata.source.hash },
                    contract.constructor,
                    salt ? salt : hex(crypto.randomBytes(4)),
                    clusterId,
                )
            ]
        ),
        pair
    );
    const contractIds = deployEvents
        .filter(ev => ev.event.section == 'phalaFatContracts' && ev.event.method == 'Instantiating')
        .map(ev => ev.event.data[0].toString());
    const numContracts = 1;
    console.assert(contractIds.length == numContracts, 'Incorrect length:', `${contractIds.length} vs ${numContracts}`);
    contract.address = contractIds[0];
    await checkUntilEq(
        async () => (await api.query.phalaFatContracts.clusterContracts(clusterId))
            .filter(c => contractIds.includes(c.toString()))
            .length,
        numContracts,
        4 * 6000
    );
    await checkUntil(
        async () => (await api.query.phalaRegistry.contractKeys(contract.address)).isSome,
        4 * 6000
    );
    console.log(`Contract: ${contract.name} deployed to ${contract.address}`);
}

async function getDriverContract(system, cert, contract, name) {
    const { output } = await system.query["system::getDriver"](cert, {}, name);
    if (!output.isSome) {
        console.log(`Driver ${name} not found`);
        return;
    }

    let address = output.unwrap();
    console.log(`Driver ${name} set to ${address}`)
    contract.address = address;
    return address;
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

async function deployCluster(api, txqueue, sudoer, owner, workers, defaultCluster = '0x0000000000000000000000000000000000000000000000000000000000000001') {
    const clusterInfo = await api.query.phalaFatContracts.clusters(defaultCluster);
    if (clusterInfo.isSome) {
        return { clusterId: defaultCluster, systemContract: clusterInfo.unwrap().systemContract.toHex() };
    }
    console.log('Cluster: creating');
    // crete contract cluster and wait for the setup
    const { events } = await txqueue.submit(
        api.tx.sudo.sudo(api.tx.phalaFatContracts.addCluster(
            owner,
            'Public', // can be {'OnlyOwner': accountId}
            workers
        )),
        sudoer
    );
    const ev = events[1].event;
    console.assert(ev.section == 'phalaFatContracts' && ev.method == 'ClusterCreated');
    const clusterId = ev.data[0].toString();
    const systemContract = ev.data[1].toString();
    console.log('Cluster: created', clusterId)
    await checkUntil(
        async () => (await api.query.phalaRegistry.clusterKeys(clusterId)).isSome,
        4 * 6000
    );
    await checkUntil(
        async () => (await api.query.phalaRegistry.contractKeys(systemContract)).isSome,
        4 * 6000
    );
    return { clusterId, systemContract };
}

async function contractApi(api, pruntimeUrl, contract) {
    const newApi = await api.clone().isReady;
    const phala = await Phala.create({ api: newApi, baseURL: pruntimeUrl, contractId: contract.address });
    const contractApi = new ContractPromise(
        phala.api,
        contract.metadata,
        contract.address,
    );
    contractApi.sidevmQuery = phala.sidevmQuery;
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

    const contractSystem = loadContractFile('./res/system.contract');
    const contractSidevmop = loadContractFile('./res/sidevm_deployer.contract');

    const toAuthContract = process.env.AUTH_CONTRACT;
    if (toAuthContract == undefined) {
        console.log('No authorize target');
        return -1;
    }

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
        }
    });
    const txqueue = new TxQueue(api);

    // Prepare accounts
    const keyring = new Keyring({ type: 'sr25519' })
    const alice = keyring.addFromUri('//Alice')
    const certAlice = await Phala.signCertificate({ api, pair: alice });

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
    const gatekeepers = await Promise.all(gatekeeperUrls.map(async w => {
        let api = new PRuntimeApi(w);
        let pubkey = hex((await api.getInfo()).publicKey);
        return {
            url: w,
            pubkey: pubkey,
            api: api,
        };
    }));
    console.log('Workers:', workers);
    console.log('Gatekeepers', gatekeepers);

    const { clusterId, systemContract } = await deployCluster(api, txqueue, alice, alice.address, workers.map(w => w.pubkey));
    contractSystem.address = systemContract;

    let default_worker = workers[0];
    let pruntimeUrl = default_worker.url;
    console.log(`Connect to ${pruntimeUrl} for query`);

    // Get System and Driver contracts
    const system = await contractApi(api, pruntimeUrl, contractSystem);
    await getDriverContract(system, certAlice, contractSidevmop, "SidevmOperation");
    const sidevmDeployer = await contractApi(api, pruntimeUrl, contractSidevmop);

    // Auth `toAuthContract` to deploy SideVM
    await txqueue.submit(
        sidevmDeployer.tx.allow({}, toAuthContract),
        alice
    );
    await checkUntil(
        async () => {
            let { output } = await sidevmDeployer.query.inWhitelist(certAlice, {}, toAuthContract);
            // console.log(`in whitelist: ${output}`);
            return output.valueOf();
        },
        4 * 6000
    );
    console.log(`${toAuthContract} authorized`);
}

main().then(process.exit).catch(err => console.error('Crashed', err)).finally(() => process.exit(-1));
