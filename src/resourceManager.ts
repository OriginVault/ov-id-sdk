import { v5 as uuidv5 } from 'uuid';
import { getVerifiedAuthentication, } from './storePrivateKeys.js';
import { CheqdNetwork } from '@cheqd/sdk';
import type { MemoryPrivateKeyStore } from '@veramo/key-manager';
import { ICheqdCreateLinkedResourceArgs, ResourcePayload, ISignInputs, IDIDManager, IKeyManager, ICredentialIssuer, ICredentialVerifier, IResolver, TAgent, IDataStore, ICheqd, IOVAgent } from '@originvault/ov-types';
import fs from 'fs';
import path from 'path';
import { getDIDKeys } from './identityManager.js';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { co2 } from "@tgwf/co2";

let jsonFilePath;

const cleanUp = () => {
    if (jsonFilePath) fs.unlinkSync(jsonFilePath);
}

export async function createResource({ data, did, name, version, provider, agent, keyStore, resourceId, resourceType }: { data: any, did: string, name: string, version: string, provider: CheqdDIDProvider, agent: TAgent<IKeyManager & IDIDManager & ICredentialIssuer & ICredentialVerifier & IResolver & IDataStore & ICheqd>, keyStore: MemoryPrivateKeyStore, resourceId?: string, resourceType?: string, }) {    
    try {
        const resolvedDid = await getDIDKeys(did);

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

        const signInputs: ISignInputs[] = [{
            verificationMethodId: verificationMethod?.id || '',
            keyType: 'Ed25519',
            privateKeyHex: privateKey.privateKeyHex,
        }];

        const payload: ResourcePayload = {
            collectionId,
            id: resourceUUID,
            name,
            resourceType,
            data: Buffer.from(fs.readFileSync(jsonFilePath)),
        }

        if(version) {
            payload.version = version;
        }

        const options: ICheqdCreateLinkedResourceArgs = {
            kms: 'local',
            network: CheqdNetwork.Mainnet,
            payload,
            signInputs,
            file: jsonFilePath, 
            fee: {
                amount: [{ denom: 'ncheq', amount: '2500000000' }],
                gas: '2000000',
            }
        }

        const params = {
            options,
        }
        
        const co2Emission = new co2();
        const co2EmissionResult = co2Emission.perByte(JSON.stringify(params).length, false);
        
        console.log(`🌱 ${name}@${version} - Resource size in carbon grams: ${co2EmissionResult.toFixed(5)}g`);
        
        try {
            const result = await provider.createResource(params, { agent });
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

export function generateResourceFile(dirPath: string, filePath: string, data: any) {
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

export async function getResources({ did, agent }: { did: string, agent: IOVAgent }) {
    const resolvedDid = await agent.resolveDid({ didUrl: did });
    console.log('DID', resolvedDid);
}

