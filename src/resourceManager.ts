import { v5 as uuidv5 } from 'uuid';
import { getVerifiedAuthentication, } from './storePrivateKeys.js';
import fs from 'fs';
import path from 'path';
import { getDIDKeys } from './identityManager.js';

let jsonFilePath;

const cleanUp = () => {
    if (jsonFilePath) fs.unlinkSync(jsonFilePath);
}

export async function createResource({ data, did, name, directory, provider, agent, keyStore, resourceId, resourceType }: { data: any, did: string, name: string, provider: any, agent: any, keyStore: any, resourceId?: string, directory?: string, resourceType?: string }) {    
    try {
        const resolvedDid = await getDIDKeys(did, agent);

        if (!resolvedDid) {
            console.log("Could not resolve DID", did);
            return undefined;
        }
        
        const { meta } = resolvedDid;
        const { keyName: id, kid: key } = meta as { keyName: string, kid: string };
        
        const verificationMethod = await getVerifiedAuthentication(id);

        // Extract the last part of the DID string to use as the collectionId
        const collectionId = id.split(':').pop() || '';
       
        const fileRelativePath = uuidv5(name, uuidv5.URL); // Use sanitized name
        const resourceUUID = resourceId || uuidv5(fileRelativePath + new Date().toISOString(), uuidv5.URL);
        const privateKey = await keyStore.getKey({ alias: key });

        jsonFilePath = await generateResourceFile(collectionId, fileRelativePath, data);
        // Check if the file exists before reading
        if (!fs.existsSync(jsonFilePath)) {
            throw new Error(`File not found: ${jsonFilePath}`);
        }

        const signInputs = [{
            verificationMethodId: verificationMethod.id,
            keyType: 'Ed25519',
            privateKeyHex: privateKey.privateKeyHex,
        }];
        const params = {
            options: {
                kms: 'local',
                provider,
                network: "mainnet",
                payload: {
                    did: id,
                    key: key,
                    collectionId,
                    id: resourceUUID,
                    name,
                    resourceType,
                    data: Buffer.from(fs.readFileSync(jsonFilePath)),
                },
                signInputs,
                file: jsonFilePath, 
                fee: {
                    amount: [{ denom: 'ncheq', amount: '2500000000' }],
                    gas: '2000000',
                }
            }
        };
        try {
            const result = await provider.createResource(params, { agent, kms: 'local' });
            cleanUp();
            if (result) {
                // Return the link to the cheqd resolver
                return `https://resolver.cheqd.net/1.0/identifiers/${did}/resources/${resourceUUID}`;
            }
            return undefined;
        } catch (error) {
            cleanUp();
            throw `Error creating resource: ${error}`;
        }
    }
    catch (error) {
        console.error("Check data formatting and RPC endpoint connection. Error creating resource:", error);
        cleanUp();
        return undefined;
    }
}

export function generateResourceFile(dirPath, filePath, data) {
    const jsonFilePath = path.resolve(dirPath, filePath);
    // Ensure the directory exists before writing the file
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
    // Convert data to JSON and write to file
    fs.writeFileSync(jsonFilePath, JSON.stringify(data, null, 2));
    // Check if the file was created successfully
    if (!fs.existsSync(jsonFilePath)) {
        throw new Error(`File generation failed: ${jsonFilePath}`);
    }
    console.log(`File generated at: ${jsonFilePath}`);
    return jsonFilePath;
}

export async function getResources({ did, agent }) {
    const resolvedDid = await agent.resolveDid({ didUrl: typeof did === 'string' ? did : did.did });
    console.log('DID', resolvedDid);
}

