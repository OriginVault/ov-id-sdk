import { agent } from './veramoAgent.js';
import base58 from 'bs58';
import { storePrivateKey } from './storePrivateKeys.js';
import { ed25519 } from '@noble/curves/ed25519';
import multibase from 'multibase';
import { v5 as uuidv5 } from 'uuid';
import os from 'os';
import inquirer from 'inquirer';
import { DIDAssertionCredentialSubject, DIDAssertionCredential } from '@originvault/ov-types';
import { getDevelopmentEnvironmentMetadata } from './environment.js';
import { getPublicKeyMultibase, getVerifiedAuthentication, base64ToHex, hexToBase64, retrievePrivateKey, KEYRING_FILE, ensureKeyring, encryptionKey } from './storePrivateKeys.js';
import { convertPrivateKeyToRecovery, encryptPrivateKey, decryptPrivateKey } from './encryption.js';
import { privateKeyStore, cheqdMainnetProvider } from './veramoAgent.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import axios from 'axios';

// Define __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function createDID(props: { method: string, alias: string }): Promise<{ did: string, mnemonic: string }> {
    try {
        const primaryDid = await getPrimaryDID();
        if (!primaryDid) {
            throw new Error("Primary DID not found.");
        }

        const primaryAuthentication = await getVerifiedAuthentication(primaryDid);
        console.log("🔑 primaryAuthentication", primaryAuthentication);
        const method = props.method || 'cheqd:testnet';
       
        const uuid = uuidv5(primaryDid + new Date().toISOString(), uuidv5.URL);
        const didString = props.alias || `did:${method}:${uuid}`;

        const createdKey = await agent.keyManagerCreate({
            type: 'Ed25519',
            kms: 'local',
        });

        if (!createdKey) {
            console.error("❌ Error importing key");
            throw new Error("Error importing key to key manager");
        }

        const { publicKeyHex, kid } = createdKey
        const didKid = `${didString}#${kid}`;

        const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');

        const prefix = Buffer.from([0xed, 0x01]);
        const prefixedPublicKey = Buffer.concat([prefix, publicKeyBuffer]);

        const publicKeyBase58 = base58.encode(prefixedPublicKey);
        const publicKeyMultibase = `z${publicKeyBase58}`;

        console.log("🔄 In Progress: Creating DID", didString);

        const did = await agent.didManagerCreate({
            provider: `did:${method}`,
            alias: didString,
            options: {
                document: {
                    id: didString,
                    service: [],
                    authentication: [
                      didKid
                    ],
                    controller: [didString],
                    verificationMethod: [
                        {
                            id: didKid,
                            type: 'Ed25519VerificationKey2020',
                            controller: [didString],
                            publicKeyHex,
                            publicKeyMultibase,
                        }
                    ]
                }
            }
            
        });

        const privateKey = await privateKeyStore.getKey({ alias: kid });

        console.log("Saving private key to keyring");
        await storePrivateKey(didString, Buffer.from(privateKey.privateKeyHex, 'hex'));

        const mnemonic = await convertPrivateKeyToRecovery(hexToBase64(privateKey.privateKeyHex));

        return { did, mnemonic };
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        throw error;
    }
}

export async function importDID(didString: string, privateKey: string, method: string): Promise<any> {
    try {
        // Convert the private key from hex to Uint8Array
        const privateKeyBytes = Uint8Array.from(Buffer.from(privateKey, 'base64'));
        // Derive public key
        const privateKeySub = privateKeyBytes.subarray(0, 32);
        const publicKeyBytes = await ed25519.getPublicKey(privateKeySub);
        const derivedPublicKey = Buffer.from(publicKeyBytes).toString('base64');

        // Get the public key multibase from the DID document
        const verifiedAuthentication = await getVerifiedAuthentication(didString);

        const publicKeyMultibase = verifiedAuthentication.publicKeyMultibase;
        const publicKeyBuffer = multibase.decode(Buffer.from(publicKeyMultibase, 'utf-8'));
        const publicKeySliced = publicKeyBuffer.slice(2);
        const documentPublicKey = Buffer.from(publicKeySliced).toString('base64');

        // Compare derived public key with the public key in the DID document
        if (derivedPublicKey !== documentPublicKey) {
            console.error("❌ Private key does not match the public key in DID document");
            return false;
        }

        console.log("✅ Private key matches the public key in DID document");

           const verificationSteps: DIDAssertionCredentialSubject['verificationSteps'] = [
            {
                step: "Get public key multibase from resolved DID",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Convert private key from base64 to Uint8Array",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Derive public key from private key",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Convert derived public key to base64",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Convert public key multibase to buffer and remove prefix",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },      
            {
                step: "Convert sliced public key to base64 for comparison",
                result: 'Passed',
                timestamp: new Date().toISOString()
            }
        ];
        
        const did = await agent.didManagerImport({
            did: didString,
            keys: [{
                kid: verifiedAuthentication.id,
                type: 'Ed25519',
                kms: 'local',
                privateKeyHex: base64ToHex(privateKey),
            }],
            provider: `did:${method}`,
            alias: didString
        });

        const credentialId = uuidv5(didString + new Date().toISOString(), uuidv5.URL); // Generate a UUID from the did
        const credential: DIDAssertionCredential = {
            id: credentialId,
            issuer: { id: didString },
            credentialSubject: {
                id: didString,
                assertionType: "did-import-verification",
                assertionDate: new Date().toISOString(),
                assertionResult: 'Passed',
                verificationSteps,
            },
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            expirationDate: new Date().toISOString()
        };

        const signedVC = await agent.createVerifiableCredential({
            credential,
            proofFormat: 'jwt'
        });

        console.log("✅ Signed VC", signedVC);


        await storePrivateKey(didString, privateKeySub);

        return did;
    } catch (error) {
        console.error("❌ Error importing DID:", error);
        throw error;
    }
} 

export async function getDID(didString: string): Promise<any> {
    let did: any;
    try {
        did = await agent.didManagerGet({
            did: didString
        });
    } catch (error) {
        console.warn("❌ DID not loaded in agent", error);
        console.log("Looking for did in keyring");
        const privateKey = await retrievePrivateKey(didString);
        if (!privateKey) {
            throw new Error("DID not found in keyring");
        }
        return { id: didString, keys: [privateKey] };
    }
    return did;
}

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


// ✅ Fetch DID Configuration from a Domain
async function fetchDomainDID(domain: string): Promise<string | null> {
    try {
        const url = `https://${domain}/.well-known/did-configuration.json`;
        const response = await axios.get(url);
        const data = response.data;
        if (data?.linked_dids?.length) {
            return data.linked_dids[0].id; // Use the first listed DID
        }
    } catch (error) {
        console.error(`❌ Failed to fetch DID configuration from ${domain}:`, error);
    }
    return null;
}


export async function setPrimaryDID(did: string, privateKey: string, password: string): Promise<boolean | any> {
    ensureKeyring(); // Ensure keyring is initialized
    if (!privateKey) {
        console.error("❌ Private key must be provided to set primary DID");
        return false;
    }
    console.log("🔑 Setting primary DID", did);
    const publicKeyMultibase = await getPublicKeyMultibase(did);
    if (!publicKeyMultibase) return false;
    try {
        const kr = await ensureKeyring();
        // Convert the private key from base64 to Uint8Array
        const privateKeyBytes = Uint8Array.from(Buffer.from(privateKey, 'base64'));
        // Derive public key
        const privateKeySub = privateKeyBytes.subarray(0, 32);
        const publicKeyBytes = await ed25519.getPublicKey(privateKeySub);
        const derivedPublicKey = Buffer.from(publicKeyBytes).toString('base64');
        // Convert base64 to buffer to base58
        const publicKeyBuffer = multibase.decode(Buffer.from(publicKeyMultibase, 'utf-8'));
        // Remove the first byte (Multibase prefix)
        const publicKeySliced = publicKeyBuffer.slice(2);
        // Convert to Base64 for comparison
        const documentPublicKey = Buffer.from(publicKeySliced).toString('base64');
        // Compare without the multibase prefix
        if (derivedPublicKey !== documentPublicKey) {
            console.error("❌ Private key does not match the public key in DID document");
            return false;
        }

        const verificationSteps: DIDAssertionCredentialSubject['verificationSteps'] = [
            {
                step: "Get public key multibase from resolved DID",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Convert private key from base64 to Uint8Array",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Derive public key from private key",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Convert derived public key to base64",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },
            {
                step: "Convert public key multibase to buffer and remove prefix",
                result: 'Passed',
                timestamp: new Date().toISOString()
            },      
            {
                step: "Convert sliced public key to base64 for comparison",
                result: 'Passed',
                timestamp: new Date().toISOString()
            }
        ];

        console.log("✅ Private key verified against resolved DID");
        // Add the key pair to the keyring using the raw private key
        const pair = kr.addFromSeed(privateKeySub, { did, isPrimary: true });
        kr.addPair(pair);

         // ✅ Ensure the DID is imported into Veramo
        try {
            await agent.didManagerImport({
                did,
                provider: "did:cheqd",
                controllerKeyId: did,
                keys: [
                    {
                        kid: "default",
                        type: "Ed25519",
                        privateKeyHex: base64ToHex(privateKey),
                        kms: "local"
                    }
                ]
            });
            console.log("✅ DID successfully imported into Veramo.");

            const credentialId = uuidv5(did + new Date().toISOString(), uuidv5.URL); // Generate a UUID from the did
            const credential: DIDAssertionCredential = {
                id: credentialId,
                issuer: { id: did },
                credentialSubject: {
                    id: did,
                    assertionType: "did-key-verification",
                    assertionDate: new Date().toISOString(),
                    assertionResult: 'Passed',
                    verificationSteps,
                },
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential'],
                expirationDate: new Date().toISOString()
            };

            const signedVC = await agent.createVerifiableCredential({
                credential,
                proofFormat: 'jwt'
            });

            console.log("✅ Signed VC", signedVC);
            
            // ✅ Encrypt and store the private key
            const encryptedPrivateKey = encryptPrivateKey(privateKey, password);

            if(process.env.NODE_ENV === 'development') {
                const environmentMetadata = await getDevelopmentEnvironmentMetadata();

                const environmentCredential: DIDAssertionCredential = {
                    id: credentialId,
                    issuer: { id: did },
                    credentialSubject: {
                        id: did,
                        assertionType: "environment-metadata",
                        assertionDate: new Date().toISOString(),
                        assertionDetails: environmentMetadata,
                        assertionResult: 'Passed',
                        verificationSteps: [
                            {
                                step: "Get development environment metadata using read-package-json-fast & process.env",
                                result: 'Passed',
                                timestamp: new Date().toISOString()
                            }
                        ]
                    },
                    '@context': ['https://www.w3.org/2018/credentials/v1'],
                    type: ['VerifiableCredential'],
                    expirationDate: new Date().toISOString()
                };

                const signedEnvironmentVC = await agent.createVerifiableCredential({
                    credential: environmentCredential,
                    proofFormat: 'jwt'
                });

                console.log("✅ Signed Environment VC", signedEnvironmentVC);

                const storedKeys = {
                    encryptedPrivateKey,
                    meta: { did, isPrimary: true, didCredential: signedVC, environmentCredential: signedEnvironmentVC },
                };

                fs.writeFileSync(KEYRING_FILE, JSON.stringify(storedKeys, null, 2));
            } else {
                const storedKeys = {
                    encryptedPrivateKey,
                    meta: { did, isPrimary: true, didCredential: signedVC },
                };

                fs.writeFileSync(KEYRING_FILE, JSON.stringify(storedKeys, null, 2));
            }

            const passwordFilePath = path.join(os.homedir(), '.encrypted-password');
            if (!encryptionKey) {
                const { encryptionKey } = await inquirer.prompt([
                    {
                        type: 'password',
                        name: 'encryptionKey',
                        message: 'Enter an encryption key to encrypt the password:',
                        mask: '*', 
                    },
                ]);

                if(!encryptionKey) {
                    console.warn("❌ No encryption key provided, password will not be encrypted");
                    fs.writeFileSync(passwordFilePath, JSON.stringify(password));
                }

                 // Encrypt the password
                const encryptedPassword = encryptPrivateKey(password, encryptionKey);
                // Store the encrypted password in a file
                fs.writeFileSync(passwordFilePath, JSON.stringify(encryptedPassword));
                fs.writeFileSync(passwordFilePath, JSON.stringify(encryptionKey));
            } else {
                // Encrypt the password
                const encryptedPassword = encryptPrivateKey(password, encryptionKey);
                // Store the encrypted password in a file
                fs.writeFileSync(passwordFilePath, JSON.stringify(encryptedPassword));
            }

            return signedVC;
        } catch (error) {
            console.error("❌ Failed to import DID into Veramo:", error);
            return false;
        }
    } catch (error) {
        console.error("❌ Error setting primary DID:", error);
        return false;
    }
}

export async function getPrimaryDID(): Promise<string | null> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs();
        const primaryPair = pairs.find(p => p.meta?.isPrimary);
        const did = (primaryPair?.meta?.did || '') as string;
        
        if(did) return did;
        
        try {
            const storedData = fs.readFileSync(KEYRING_FILE, 'utf8');
            const { meta } = JSON.parse(storedData);
            if(!meta) return null;
            const { did, didCredential } = meta;
            if(!didCredential) return null;
            if(did) return did;
        } catch (error) {
            console.error("❌ Error accessing keyring. File may not exist",);
            return null;
        }
        
        const domain = process.env.SDK_DOMAIN;
        const detectedHostname = os.hostname();
        console.log("Detected Hostname:", detectedHostname);
        console.log("🔑 Domain", domain);
        if (!domain) {
            console.error("❌ No domain set for SDK validation.");
            return null;
        }
        return await fetchDomainDID(domain);
    } catch (error) {
        console.error("❌ Error accessing keyring:", error);
        return null;
    }
}

export async function verifyPrimaryDID(password: string): Promise<string | boolean | null> {
    try {
        const storedData = fs.readFileSync(KEYRING_FILE, 'utf8');
        const { encryptedPrivateKey, meta } = JSON.parse(storedData);
        if(!encryptedPrivateKey) return false;
        
        const did = meta.did;
        const privateKey = decryptPrivateKey(encryptedPrivateKey, password);
        if (!privateKey) {
            console.error("❌ Failed to decrypt private key");
            return false;
        }

        // Import the DID using the decrypted private key
        try {
            await agent.didManagerImport({
                did: did,
                provider: "did:cheqd",
                controllerKeyId: privateKey, // Associate with private key
                keys: [
                    {
                        kid: "default",
                        type: "Ed25519",
                        privateKeyHex: base64ToHex(privateKey), // Remove "0x" prefix if present
                        kms: "local"
                    }
                ]
            });

            console.log("✅ Primary DID successfully verified and ready to use");
        } catch (error) {
            console.error("❌ Failed to import DID into Veramo:", error);
            return false;
        }

        if (did) return did;
        
        const domain = process.env.SDK_DOMAIN;
        const detectedHostname = os.hostname();
        console.log("Detected Hostname:", detectedHostname);
        console.log("🔑 Domain", domain);
        if (!domain) {
            console.error("❌ No domain set for SDK validation.");
            return false;
        }
        return await fetchDomainDID(domain);
    } catch (error) {
        console.error("❌ Error accessing keyring:", error);
        return false;
    }
}