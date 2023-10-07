require('dotenv').config();

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { blake2AsHex } = require('@polkadot/util-crypto');
const { options, OnChainRegistry, signCertificate, PinkContractPromise, signAndSend, PinkCodePromise, PinkLoggerContractPromise } = require('@phala/sdk');
const fs = require('fs');
const crypto = require('crypto');
const { PRuntimeApi } = require('./utils/pruntime');

const CENTS = 10_000_000_000;
const defaultTxConfig = { gasLimit: "10000000000000" };

const BLOCK_INTERVAL = 3_000;

function loadContractFile(contractFile) {
    const metadata = JSON.parse(fs.readFileSync(contractFile));
    const name = metadata.contract.name;
    const wasm = metadata.source.wasm;
    return { metadata, name, wasm };
}

async function uploadResource(api, system, pair, cert, clusterId, codeType, wasm) {
    let hash = blake2AsHex(wasm);
    console.log(`Upload ${codeType} ${hash}`);
    let type = codeType == "SidevmCode" ? 'Sidevm' : 'Ink';
    const { output } = await system.query["system::codeExists"](pair.address, { cert }, hash, type);
    if (output.asOk.toPrimitive()) {
        console.log("Code exists")
        return;
    }

    await signAndSend(
        api.tx.phalaPhatContracts.clusterUploadResource(clusterId, codeType, wasm),
        pair
    );
    await checkUntil(async () => {
        const { output } = await system.query["system::codeExists"](pair.address, { cert }, hash, type);
        return output.asOk.toPrimitive();
    }, 8 * BLOCK_INTERVAL);
    console.log("Code uploaded")
}

async function uploadAndDeployContract(api, phatRegistry, pair, cert, contract, salt) {
    console.log(`Contract: uploading ${contract.name}`);
    const codePromise = new PinkCodePromise(api, phatRegistry, contract.metadata, contract.wasm);
    const uploadResult = await signAndSend(codePromise.tx.default(defaultTxConfig), pair);
    await uploadResult.waitFinalized(pair, cert, 8 * BLOCK_INTERVAL);
    console.log("uploaded");

    console.log(`Contract: instantiating ${contract.name}`);
    let instantiateResult
    try {
        const { blueprint } = uploadResult;
        const { gasRequired, storageDeposit, salt: saltRand } = await blueprint.query.default(pair.address, { cert });
        salt = salt ? salt : saltRand;
        instantiateResult = await signAndSend(
            blueprint.tx.default({ gasLimit: gasRequired.refTime * 10, storageDepositLimit: storageDeposit.isCharge ? storageDeposit.asCharge : null, salt }),
            pair
        )
        await instantiateResult.waitFinalized();
    } catch (err) {
        console.log(`Instantiate failed: ${err}`)
        console.error(err)
        return process.exit(1)
    }

    const { contractId } = instantiateResult
    contract.address = contractId;
    console.log(`Contract: ${contract.name} deployed to ${contract.address}`);
}

async function deployDriverContract(api, phatRegistry, system, pair, cert, contract, driverName, salt) {
    // check the existense of driver contract
    const { output } = await system.query["system::getDriver"](pair.address, { cert }, driverName);
    if (output?.asOk.isSome) {
        contract.address = output?.asOk.unwrap().toHex();
        console.log(`Driver ${driverName} exists in ${contract.address}`);
        return contract.address;
    }

    await uploadAndDeployContract(api, phatRegistry, pair, cert, contract, salt);

    // use query to estimate the required gas for system::setDriver
    const { gasRequired, storageDeposit } = await system.query["system::setDriver"](pair.address, { cert }, driverName, contract.address);
    const options = {
        value: 0,
        gasLimit: gasRequired,
        storageDepositLimit: storageDeposit.isCharge ? storageDeposit.asCharge : null
    };
    await signAndSend(system.tx["system::setDriver"](options, driverName, contract.address), pair);
    await signAndSend(system.tx["system::grantAdmin"](defaultTxConfig, contract.address), pair);

    console.log('Driver: wait for registration');
    await checkUntil(
        async () => {
            const { output } = await system.query["system::getDriver"](pair.address, { cert }, driverName);
            return output?.asOk.isSome && output?.asOk.unwrap().eq(contract.address);
        },
        8 * BLOCK_INTERVAL
    );
    console.log(`Driver ${driverName} set to ${contract.address}`)
    return contract.address;
}

async function uploadSystemCode(api, pair, wasm) {
    console.log(`Uploading system code`);
    await signAndSend(
        api.tx.sudo.sudo(api.tx.phalaPhatContracts.setPinkSystemCode(hex(wasm))),
        pair
    );
    await checkUntil(async () => {
        let code = await api.query.phalaPhatContracts.pinkSystemCode();
        return code[1] == wasm;
    }, 8 * BLOCK_INTERVAL);
    console.log(`Uploaded system code`);
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

async function forceRegisterWorker(api, pair, worker) {
    console.log('Worker: registering', worker);
    await signAndSend(
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

async function setupGatekeeper(api, pair, worker) {
    const gatekeepers = await api.query.phalaRegistry.gatekeeper();
    if (gatekeepers.toHuman().includes(worker)) {
        console.log('Gatekeeper: skip', worker);
        return;
    }
    console.log('Gatekeeper: registering');
    await signAndSend(
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

async function getOrDeployCluster(api, sudoer, owner, workers, treasury, defaultCluster = '0x0000000000000000000000000000000000000000000000000000000000000001') {
    const clusterInfo = await api.query.phalaPhatContracts.clusters(defaultCluster);
    if (clusterInfo.isSome) {
        return { clusterId: defaultCluster, systemContract: clusterInfo.unwrap().systemContract.toHex() };
    }
    console.log('Cluster: creating');
    // crete contract cluster and wait for the setup
    const { events } = await signAndSend(
        api.tx.sudo.sudo(api.tx.phalaPhatContracts.addCluster(
            owner,
            'Public', // can be {'OnlyOwner': accountId}
            workers,
            "10000000000000000", // 10000 PHA
            5, 50000000000, 1000000000, treasury.address
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

async function contractApi(api, phatRegistry, contract) {
    const contractKey = await phatRegistry.getContractKeyOrFail(contract.address);
    const contractApi = new PinkContractPromise(api, phatRegistry, contract.metadata, contract.address, contractKey);
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
    const api = await ApiPromise.create(
        options({
            provider: new WsProvider(nodeUrl),
            noInitWarn: true,
        })
    );

    // Prepare accounts
    const keyring = new Keyring({ type: 'sr25519' });
    const sudo = keyring.addFromUri(sudoAccount);
    const treasury = keyring.addFromUri(treasuryAccount);
    const certSudo = await signCertificate({ pair: sudo });

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
        await forceRegisterWorker(api, sudo, w.pubkey);
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
            await forceRegisterWorker(api, sudo, w.pubkey);
            await setupGatekeeper(api, sudo, w.pubkey);
        }
    }

    // Upload the pink-system wasm to the chain. It is required to create a cluster.
    await uploadSystemCode(api, sudo, contractSystem.wasm);

    const { clusterId, systemContract } = await getOrDeployCluster(api, sudo, sudo.address, workers.map(w => w.pubkey), treasury);
    contractSystem.address = systemContract;
    console.log('Cluster system contract address:', systemContract);

    const phatRegistry = await OnChainRegistry.create(api)
    const default_worker = workers[0];
    console.log(`Connect to ${default_worker.url} for query`);

    const system = await contractApi(api, phatRegistry, contractSystem);

    // Deploy the tokenomic contract
    await deployDriverContract(api, phatRegistry, system, sudo, certSudo, contractTokenomic, "ContractDeposit");

    // Stake some tokens to the system contract
    console.log(`Stake to system contract`);
    const stakedCents = 42;
    await signAndSend(
        api.tx.phalaPhatTokenomic.adjustStake(systemContract, CENTS * stakedCents),
        sudo
    );
    // Contract weight should be affected
    await checkUntilEq(
        async () => {
            const { weight } = await default_worker.api.getContractInfo(systemContract);
            return weight;
        },
        stakedCents,
        8 * BLOCK_INTERVAL
    );

    // Total stakes to the contract should be changed
    const total = await api.query.phalaPhatTokenomic.contractTotalStakes(systemContract);
    console.assert(total.eq(CENTS * stakedCents), "total stake does not match");

    // Stakes of the user
    const stakesOfOwner = await api.query.phalaPhatTokenomic.contractUserStakes.entries(sudo.address);
    console.log('Stakes of cluster owner:');
    stakesOfOwner.forEach(([key, stake]) => {
        console.log('\tcontract:', key.args[1].toHex());
        console.log('\t   stake:', stake.toHuman());
    });

    // Deploy the QuickJS engine
    const { output } = await system.query["system::getDriver"](sudo.address, { cert: certSudo }, "JsDelegate");
    if (output?.asOk.isSome) {
        contractQjs.address = output?.asOk.unwrap().toHex();
        console.log(`Driver JsDelegate exists in ${contractQjs.address}`);
    } else {
        await uploadResource(api, system, sudo, certSudo, clusterId, 'IndeterministicInkCode', contractQjs.wasm);

        await signAndSend(system.tx["system::setDriver"](defaultTxConfig, "JsDelegate", contractQjs.metadata.source.hash), sudo);
        console.log("Driver: wait for registration");
        await checkUntil(async () => {
            const { output } = await system.query["system::getDriver"](
                sudo.address, { cert: certSudo },
                "JsDelegate"
            );
            return output?.asOk.isSome;
        }, 8 * BLOCK_INTERVAL);
    }

    // Deploy driver: Sidevm deployer
    await deployDriverContract(api, phatRegistry, system, sudo, certSudo, contractSidevmop, "SidevmOperation");

    const sidevmDeployer = await contractApi(api, phatRegistry, contractSidevmop);

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
    await sidevmDeployer.tx.allow(defaultTxConfig, loggerId).signAndSend(sudo);
    console.log('SideVM: allowing logger contract');
    await checkUntil(
        async () => {
            let { output } = await sidevmDeployer.query['sidevmOperation::canDeploy'](sudo.address, { cert: certSudo }, loggerId);
            return output.asOk.toPrimitive();
        },
        8 * BLOCK_INTERVAL
    );

    // Upload the logger's sidevm wasm code
    await uploadResource(api, system, sudo, certSudo, clusterId, 'SidevmCode', hex(logServerSidevmWasm));
    // Deploy the logger contract
    await deployDriverContract(api, phatRegistry, system, sudo, certSudo, contractLogServer, "PinkLogger", salt);

    const pinkLogger = await PinkLoggerContractPromise.create(api, phatRegistry, phatRegistry.systemContract);
    const { records } = await pinkLogger.getLog(systemContract);
    console.log("Log records:");
    for (let rec of records) {
        if (rec['type'] === 'Log') {
            const d = new Date(rec['timestamp'])
            console.log(`\t${rec['type']} #${rec['blockNumber']} [${d.toISOString()}] ${rec['message']}`)
        } else if (rec['type'] === 'MessageOutput') {
            console.log(`\t${rec['type']} #${rec['blockNumber']} ${rec['output']}`)
        } else {
            console.log(`\t${rec['type']} ${JSON.stringify(rec)}`)
        }
    }
}

main().then(process.exit).catch(err => console.error('Crashed', err)).finally(() => process.exit(-1));
