import { agent } from './veramoAgent.js';
import { v5 as uuidv5 } from 'uuid';
import { getVerifiedAuthentication, } from './storePrivateKeys.js';
import { privateKeyStore, cheqdMainnetProvider } from './veramoAgent.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getDID } from './identityManager.js';

// Define __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function createResource({ didString, filePath, name }) {
    const did = await getDID(didString);
    const verificationMethod = await getVerifiedAuthentication(didString);
    const key = did.keys[0];

    // Extract the last part of the DID string to use as the collectionId
    const collectionId = didString.split(':').pop() || '';
    const resourceId = uuidv5(didString + '#resource', uuidv5.URL);
    const privateKey = await privateKeyStore.getKey({ alias: key.kid });

    // Call createResource function
    const jsonFilePath = path.resolve(__dirname, filePath); // Use the passed filePath

    const signInputs = [{
        verificationMethodId: verificationMethod.id, // Replace with actual ID
        keyType: 'Ed25519', // Ensure this matches the DIDDoc
        privateKeyHex: privateKey.privateKeyHex,
    } as any];

    const params = {
        options: {
            kms: 'local',
            provider: cheqdMainnetProvider,
            network: "mainnet",
            payload: {
                did: didString,
                key: key.kid,
                collectionId, // Use the last part of the DID string as collection ID
                id: resourceId, // Generated resource ID
                name, // Replace with a human-readable name
                resourceType: 'CL-Schema', // Replace with actual resource type
                version: '1.0', // Optional version
                data: Buffer.from(fs.readFileSync(jsonFilePath)),
            },
            signInputs,
            file: jsonFilePath, // Updated file path
            fee: {
                amount: [{ denom: 'ncheq', amount: '2500000000' }], // Replace with actual fee amount
                gas: '1000000', // Replace with actual gas limit
            }
        }
    };

    return await cheqdMainnetProvider.createResource(params, { agent, kms: 'local' } as any);
}

export async function updateResource({ didString, filePath, name, resourceId }) {
    const did = await getDID(didString);
    const verificationMethod = await getVerifiedAuthentication(didString);
    const key = did.keys[0];

    // Extract the last part of the DID string to use as the collectionId
    const collectionId = didString.split(':').pop() || '';
    const privateKey = await privateKeyStore.getKey({ alias: key.kid });

    // Call updateResource function
    const jsonFilePath = path.resolve(__dirname, filePath); // Use the passed filePath

    const signInputs = [{
        verificationMethodId: verificationMethod.id, // Replace with actual ID
        keyType: 'Ed25519', // Ensure this matches the DIDDoc
        privateKeyHex: privateKey.privateKeyHex,
    } as any];

    const params = {
        options: {
            kms: 'local',
            provider: cheqdMainnetProvider,
            network: "mainnet",
            payload: {
                did: didString,
                key: key.kid,
                collectionId, // Use the last part of the DID string as collection ID
                id: resourceId, // Use the provided resource ID
                name, // Replace with a human-readable name
                resourceType: 'CL-Schema', // Replace with actual resource type
                version: '1.0', // Optional version
                data: Buffer.from(fs.readFileSync(jsonFilePath)),
            },
            signInputs,
            file: jsonFilePath, // Updated file path
            fee: {
                amount: [{ denom: 'ncheq', amount: '2500000000' }], // Replace with actual fee amount
                gas: '1000000', // Replace with actual gas limit
            }
        }
    };

    return await cheqdMainnetProvider.createResource(params, { agent, kms: 'local' } as any);
}
