require('dotenv').config();

const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { ContractPromise } = require('@polkadot/api-contract');
const Phala = require('@phala/sdk');
const fs = require('fs');

function loadContractFile(contractFile) {
    const metadata = JSON.parse(fs.readFileSync(contractFile));
    const constructor = metadata.spec.constructors.find(c => c.label == 'default').selector;
    const name = metadata.contract.name;
    const wasm = metadata.source.wasm;
    return { wasm, metadata, constructor, name };
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

async function contractApi(api, pruntimeUrl, contract, contractId) {
    const newApi = await api.clone().isReady;
    const phala = await Phala.create({ api: newApi, baseURL: pruntimeUrl, contractId });
    const contractApi = new ContractPromise(
        phala.api,
        contract.metadata,
        contractId,
    );
    contractApi.sidevmQuery = phala.sidevmQuery;
    return contractApi;
}

function toBytes(s) {
    let utf8Encode = new TextEncoder();
    return utf8Encode.encode(s)
}

async function getLogs(api, logger, cert, from) {
    // Query input: a JSON doc with three optinal fields:
    const condition = {
        action: 'GetLog',
        contract: '',
        from,
        count: undefined,
    };
    const data = hex(toBytes(JSON.stringify(condition)));
    const hexlog = await logger.sidevmQuery(data, cert);
    const resp = api.createType('InkResponse', hexlog);
    const result = resp.result.toHuman();
    const logJson = result.Ok.InkMessageReturn;
    return JSON.parse(logJson);
}

async function main() {
    const nodeUrl = process.env.ENDPOINT || 'wss://poc5.phala.network/ws';
    const clusterId = process.env.CLUSTER || '0x0000000000000000000000000000000000000000000000000000000000000001';
    const pruntimeUrl = process.env.WORKERS;
    // const contractId = '0x7cf778c0a9d293d75a1991fbf0ab0ef687f390767e52a076d44f8be266d51011';

    const contractLogServer = loadContractFile('./res/log_server.contract');
    const contractSystem = loadContractFile('./res/system.contract');

    // Connect to the chain
    const wsProvider = new WsProvider(nodeUrl);
    const api = await ApiPromise.create({
        provider: wsProvider,
        types: Phala.types,
    });

    // Prepare accounts
    const keyring = new Keyring({ type: 'sr25519' })
    const alice = keyring.addFromUri('//Alice')
    const certAlice = await Phala.signCertificate({ api, pair: alice });

    console.log(`Connect to ${pruntimeUrl} for query`);

    const clusterInfo = (await api.query.phalaFatContracts.clusters(clusterId)).unwrap();
    const systemId = clusterInfo.systemContract.toHex();
    console.log('Contract found', {systemId});

    const system = await contractApi(api, pruntimeUrl, contractSystem, systemId);
    const loggerLookup = await system.query["system::getDriver"](certAlice, {}, 'PinkLogger');
    const loggerId = loggerLookup.output.unwrap().toHex();
    console.log('Contract found', {loggerId});

    const logger = await contractApi(api, pruntimeUrl, contractLogServer, loggerId);

    let from = 0;
    let fullLog = [];
    while (true) {
        const logs = await getLogs(api, logger, certAlice, from);
        if (logs.records.length == 0) {
            break;
        }
        fullLog = fullLog.concat(logs.records);
        from = logs.next;
    }

    console.log(JSON.stringify(fullLog, undefined, 2));
}

main().then(process.exit).catch(err => console.error(err.message)).finally(() => process.exit(-1));
