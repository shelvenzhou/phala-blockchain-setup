const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { BN } = require('@polkadot/util');
const { typeDefinitions } = require('@polkadot/types');
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

async function contractApi(api, pruntimeUrl, contract, address) {
    const newApi = await api.clone().isReady;
    const phala = await Phala.create({ api: newApi, baseURL: pruntimeUrl, contractId: address, autoDeposit: true });
    const contractApi = new ContractPromise(
        phala.api,
        contract.metadata,
        address,
    );
    contractApi.sidevmQuery = phala.sidevmQuery;
    contractApi.instantiate = phala.instantiate;
    contractApi.pkApi = api;
    return contractApi;
}

async function buildContract(metadata, workerUrl, nodeUrl, address) {
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
    return await contractApi(api, workerUrl, metadata, address);
}

async function main() {
    const nodeUrl = process.env.ENDPOINT || 'wss://api.phala.network/ws';
    const workerUrl = process.env.WORKER_URL || 'https://phat-cluster-de.phala.network/pruntime-01';
    const sudoAccount = process.env.SUDO || '//Alice';
    const driversDir = process.env.DRIVERS_DIR || './res';
    const systemAddress = process.env.SYSTEM_ADDRESS || '0x9dc2f09872e69f622cedbb3743aea482c740d9973f30f45c26cb8ed9782e6ab2';
    const contractSystem = loadContractFile(`${driversDir}/system.contract`);

    const jsCodeHash = '0x304e981815c4c8de466160edec99bf648b43530b7d02a052f0033344e8f79df3';
    const jsDriverName = "JsDelegate";

    const estNodeUrl = 'wss://poc5.phala.network/ws';
    const estWorkerUrl = 'https://poc5.phala.network/tee-api-1';
    const estSystemAddress = '0x0f564a85665e5e616050f2739734fe53a215802e0b2618fad38d179b14fd2cfc';

    const system = await buildContract(contractSystem, workerUrl, nodeUrl, systemAddress);
    const estSystem = await buildContract(contractSystem, estWorkerUrl, estNodeUrl, estSystemAddress);

    // Prepare accounts
    const keyring = new Keyring({ type: 'sr25519' });
    const sudo = keyring.addFromUri(sudoAccount);
    const certSudo = await Phala.signCertificate({ api: estSystem.pkApi, pair: sudo });

    const { gasRequired: { refTime }, storageDeposit } = await estSystem.query["system::setDriver"](certSudo, {}, jsDriverName, jsCodeHash);
    const gasLimit = refTime * 10;
    const storageDepositLimit = storageDeposit.isCharge ? storageDeposit.asCharge.add(new BN(100)).mul(new BN(1_000_000_000)) : null;
    const options = {
        value: 0,
        gasLimit,
        storageDepositLimit,
    };
    const tx = system.tx["system::setDriver"](options, jsDriverName, jsCodeHash);

    console.log();
    console.log();
    console.log('Sudo account   :', sudoAccount);
    console.log('Node URL       :', nodeUrl);
    console.log('Worker URL     :', workerUrl);
    console.log('System address :', systemAddress);
    console.log('Est Worker URL :', estWorkerUrl);
    console.log('Est System addr:', estSystemAddress);
    console.log('JS code hash   :', jsCodeHash);
    console.log('JS driver name :', jsDriverName);
    console.log(`Estimated gas: ${refTime}, storageDeposit: ${storageDeposit}, gasLimit: ${gasLimit}, storageDepositLimit: ${storageDepositLimit}`);
    console.log('Encoded tx for system::setDriver :', tx.toHex());
}

main().then(process.exit).catch(err => console.error('Crashed', err)).finally(() => process.exit(-1));
