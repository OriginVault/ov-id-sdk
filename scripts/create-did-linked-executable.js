import { createResource, packageStore } from '../index.js';

const createDIDLinkedExecutable = async () => {
    const { agent, privateKeyStore, did, cheqdMainnetProvider } = await packageStore.initialize();
    const resource = await createResource({
        filePath: './src/testExecutable.ts',
        did,
        name: 'ballin',
        version: '0.0.2',
        provider: cheqdMainnetProvider,
        agent: agent,
        keyStore: privateKeyStore,
        resourceType: 'Executable',
        noDeletion: true
    });

    console.log(resource);
}

createDIDLinkedExecutable();

