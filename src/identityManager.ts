import { userAgent, ensurePrimaryDIDWallet, PRIMARY_DID_WALLET_FILE } from './userAgent.js';
import { bases } from 'multiformats/basics';
import { storeEncryptionKey, storePrivateKey } from './storePrivateKeys.js';
import { ed25519 } from '@noble/curves/ed25519';
import multibase from 'multibase';
import { v5 as uuidv5 } from 'uuid';
import { fromString } from 'uint8arrays';
import os from 'os';
import inquirer from 'inquirer';
import { parentAgent } from './parentAgent.js';
import { getEnvironmentMetadata } from './environment.js';
import { MemoryPrivateKeyStore } from '@veramo/key-manager';
import { privateKeyStore } from './OVAgent.js';
import { getPublicKeyMultibase, getVerifiedAuthentication, base64ToHex, hexToBase64, retrieveKeys, ensureKeyring, getEncryptionKey } from './storePrivateKeys.js';
import { convertPrivateKeyToRecovery, encryptPrivateKey, decryptPrivateKey } from './encryption.js';
import fs from 'fs';
import path from 'path';
import { IOVAgent, ICheqdCreateIdentifierArgs, IIdentifier, DIDAssertionCredential, VerifiableCredential, DIDDocument } from '@originvault/ov-types';
import axios from 'axios';
import { KeyringPair$Meta } from '@polkadot/keyring/types.js';
import dotenv from 'dotenv';

dotenv.config();

const MULTICODEC_ED25519_HEADER = new Uint8Array([0xed, 0x01]);

function toMultibaseRaw(key) {
    const multibase = new Uint8Array(MULTICODEC_ED25519_HEADER.length + key.length);

    multibase.set(MULTICODEC_ED25519_HEADER);
    multibase.set(key, MULTICODEC_ED25519_HEADER.length);

	return bases['base58btc'].encode(multibase);
}

function isValidHex(str: string): boolean {
    return /^[0-9a-fA-F]*$/.test(str);
}

export async function createDID(props: { method: string, agent?: IOVAgent, alias?: string, isPrimary?: boolean, signingDid?: string }): Promise<{ did: IIdentifier, mnemonic: string, publicKeyHex: string, privateKeyHex: string, credentials: VerifiableCredential[] }> {
    const createAgent = props.agent || parentAgent;
    if(!createAgent) {
        throw new Error("Agent not found");
    }
    try {
        const method = props.method || 'cheqd:testnet';
       
        const uuid = uuidv5(Math.random().toString(36).substring(2, 15) + new Date().toISOString(), uuidv5.URL);
        let didString = props.alias || `did:${method}:${uuid}`;

        const createdKey = await createAgent.keyManagerCreate({
            type: 'Ed25519',
            kms: 'local',
        });

        if (!createdKey) {
            console.error("❌ Error importing key");
            throw new Error("Error importing key to key manager");
        }

        const { publicKeyHex, kid } = createdKey
        const didKid = `${didString}#${kid}`;
        const publicKey = fromString(publicKeyHex, 'hex');
        const publicKeyMultibase = toMultibaseRaw(publicKey);

        console.log("🔄 In Progress: Creating DID", didString);

        const options: any = {
            provider: `did:${method}`,
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
            
        }

        const did = await createAgent.didManagerCreate(method === 'key' ? {
            provider: `did:key`,
        } : options);

        console.log("🔄 DID Created", did);
        didString = did.did;

        console.log("🔄 In Progress: Storing private key", kid);
        const privateKey = await privateKeyStore.getKey({ alias: kid });
        await storePrivateKey(didString, Buffer.from(privateKey.privateKeyHex, 'hex'), kid);
        let issuer = props.signingDid || didString;
        const credentialId = uuidv5(didString + new Date().toISOString(), uuidv5.URL); // Generate a UUID from the did
        const credential: DIDAssertionCredential = {
            id: credentialId,
            issuer: { id: issuer },
            credentialSubject: {
                id: didString,
                assertionType: "did-creation",
                assertionDate: new Date().toISOString(),
                assertionResult: 'Passed',
            },
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            expirationDate: new Date().toISOString()
        };

        const mnemonic = await convertPrivateKeyToRecovery(hexToBase64(privateKey.privateKeyHex));

        const signedCreation = await createAgent.createVerifiableCredential({
            credential,
            proofFormat: 'jwt'
        });

        return { did, mnemonic, publicKeyHex, privateKeyHex: privateKey.privateKeyHex, credentials: [signedCreation] };
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        throw error;
    }
}

export async function createDIDWithAdmin(props: { method: string, agent: IOVAgent,  publisherDID: string, keyStore?: MemoryPrivateKeyStore, alias?: string, isPrimary?: boolean}): Promise<{ did: IIdentifier, mnemonic: string, adminMnemonic: string, credentials: VerifiableCredential[] }> {
    const createAgent = props.agent;
    const publisherDID = props.publisherDID;
    if(!createAgent || !publisherDID) {
        throw new Error("Cannot create DID without agent and publisher DID");
    }
    try {
        ensurePrimaryDIDWallet();
        if (!publisherDID && !props.isPrimary) {
            throw new Error("Primary DID not found.");
        }

        const method = props.method || 'cheqd:testnet';
        const uuid = uuidv5(publisherDID + new Date().toISOString(), uuidv5.URL);
        const didString = props.alias || `did:${method}:${uuid}`;

        const createdKey = await createAgent.keyManagerCreate({
            type: 'Ed25519',
            kms: 'local',
        });

        const adminKey = await createAgent.keyManagerCreate({
            type: 'Ed25519',
            kms: 'local',
        });

        const { publicKeyHex, kid } = createdKey;
        const { publicKeyHex: adminPublicKeyHex, kid: adminKid } = adminKey;
        const didKid = `${didString}#${kid}`;
        const adminDidKid = `${didString}#${adminKid}`;

        const publicKey = fromString(publicKeyHex, 'hex');
        const publicKeyMultibase = toMultibaseRaw(publicKey);
        const adminPublicKey = fromString(adminPublicKeyHex, 'hex');
        const adminPublicKeyMultibase = toMultibaseRaw(adminPublicKey);

        console.log("🔄 In Progress: Creating DID", didString);

        const privateKey = await props.keyStore?.getKey({ alias: kid }) || await privateKeyStore.getKey({ alias: kid });
        const adminPrivateKey = await props.keyStore?.getKey({ alias: adminKid }) || await privateKeyStore.getKey({ alias: adminKid });


        const publisher = await createAgent.resolveDid({ didUrl: publisherDID });
        if(!publisher || !publisher.didDocument) {
            throw new Error("Publisher DID not found.");
        }

        //update publisher DID with new admin key
        try {
            console.log("🔄 In Progress: Updating publisher DID", publisher.didDocument.id);
            const updatedPublisher = await updateDID({
                didString: publisherDID,
                agent: createAgent,
                document: {
                ...publisher.didDocument,
                verificationMethod: [
                    ...(publisher.didDocument as any)?.verificationMethod,
                    {
                        id: adminDidKid,
                        type: 'Ed25519VerificationKey2020',
                        controller: publisherDID,
                        publicKeyHex: adminPublicKeyHex,
                        publicKeyMultibase: adminPublicKeyMultibase,
                        }
                    ]
                },
                keyStore: props.keyStore || privateKeyStore
            });
            console.log("🔄 In Progress: Updated publisher DID", updatedPublisher);
        } catch (error) {
            console.error("❌ Error updating publisher DID:", error);
        }

        const createArgs: ICheqdCreateIdentifierArgs = {
            kms: 'local',
            keys: [
                {
                    kid: adminKid,
                    type: 'Ed25519',
                    privateKeyHex: adminPrivateKey?.privateKeyHex,
                    publicKeyHex: adminPublicKeyHex,
                },
                {
                    kid: adminDidKid,
                    type: 'Ed25519',
                    privateKeyHex: privateKey?.privateKeyHex,
                    publicKeyHex,
                }
            ],
            alias: didString,
            document: {
                id: didString,
                service: [],
                authentication: [
                    didKid, 
                    adminKid,
                ],
                controller: [didString, publisherDID],
                verificationMethod: [
                    {
                        id: didKid,
                        type: 'Ed25519VerificationKey2020',
                        controller: didString,
                        publicKeyHex,
                        publicKeyMultibase,
                    },
                    {
                        id: adminKid,
                        type: 'Ed25519VerificationKey2020',
                        controller: publisherDID,
                        publicKeyHex: adminPublicKeyHex,
                        publicKeyMultibase: adminPublicKeyMultibase,
                    }
                ]
            }
        }

        console.log("🔄 In Progress: Creating DID", didString);

        const did = await createAgent.didManagerCreate({ options: createArgs });

        console.log("Saving private key to keyring");
        await storePrivateKey(didString, Buffer.from(privateKey.privateKeyHex, 'hex'), kid);
        await storePrivateKey(adminDidKid, Buffer.from(adminPrivateKey.privateKeyHex, 'hex'), adminKid);

        const credentialId = uuidv5(didString + new Date().toISOString(), uuidv5.URL); // Generate a UUID from the did
        const credential: DIDAssertionCredential = {
            id: credentialId,
            issuer: { id: didString },
            credentialSubject: {
                id: didString,
                assertionType: "did-creation",
                assertionDate: new Date().toISOString(),
                assertionResult: 'Passed',
            },
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            expirationDate: new Date().toISOString()
        };

        const mnemonic = await convertPrivateKeyToRecovery(hexToBase64(privateKey.privateKeyHex));
        const adminMnemonic = await convertPrivateKeyToRecovery(hexToBase64(adminPrivateKey.privateKeyHex));
        const signedCreation = await createAgent.createVerifiableCredential({
            credential,
            proofFormat: 'jwt'
        });

        return { did, mnemonic, adminMnemonic, credentials: [signedCreation] };
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        throw error;
    }
}

export async function updateDID(props: { didString: string, agent: IOVAgent,  document: DIDDocument, keyStore: MemoryPrivateKeyStore}): Promise<{ did: IIdentifier }> {
    const agent = props.agent;
    if(!agent) {
        throw new Error("Cannot update DID without agent");
    }
    try {
        console.log("🔄 In Progress: Updating DID", props.didString);

        if(!props.document.verificationMethod) {
            throw new Error("Verification method ID not found");
        }

        const privateKey = await props.keyStore.getKey({ alias: props.document.verificationMethod[0].id });
        const storedKey = await agent.keyManagerGet({ kid: props.document.verificationMethod[0].id });
        const privateKeyHex = privateKey?.privateKeyHex || '';
        if (!isValidHex(privateKeyHex)) {
            throw new Error("Invalid privateKeyHex: must be a valid hexadecimal string");
        }
        const updatedDid = await agent.didManagerUpdate({
            did: props.didString,
            document: props.document,
            options: {
				kms: 'local',
				keys: [
                    {
                        kid: props.document.verificationMethod[0].id,
                        type: 'Ed25519',
                        privateKeyHex: privateKeyHex,
                        publicKeyHex: storedKey?.publicKeyHex,
                    }
                ]
			}
        });
        return { did: updatedDid };
    } catch (error) {
        console.error("❌ Error updating DID:", error);
        throw error;
    }
}

export async function importDID({ didString, privateKey, method, agent }: { didString: string, privateKey: string, method: string, agent?: IOVAgent}): Promise<{ did: IIdentifier, credentials: VerifiableCredential[] }> {
    const importAgent = agent || parentAgent;
    if(!importAgent) {
        throw new Error("Agent not found");
    }
    try {
        // Convert the private key from hex to Uint8Array
        const privateKeyBytes = Buffer.from(privateKey, 'base64');
        // Derive public key
        const privateKeySub = privateKeyBytes.subarray(0, 32);
        const publicKeyBytes = ed25519.getPublicKey(privateKeySub);

        const derivedPublicKeyMultibase = toMultibaseRaw(publicKeyBytes);

        // Get the public key multibase from the DID document
        const verifiedAuthentication = await getVerifiedAuthentication(didString, importAgent);

        const publicKeyMultibase = verifiedAuthentication?.publicKeyMultibase;

        if(!publicKeyMultibase) {
            console.error("❌ Public key multibase not found");
            return {
                did: {
                    did: 'Public key multibase not found',
                    provider: `did:${method}`,
                    keys: [],
                    services: [],
                },
                credentials: [],
            };
        }


        // Compare derived public key with the public key in the DID document
        if (derivedPublicKeyMultibase !== publicKeyMultibase) {
            console.error("❌ Private key does not match the public key in DID document");
            return {
                did: {
                    did: 'Private key does not match the public key in DID document',
                    provider: `did:${method}`,
                    keys: [],
                    services: [],
                },
                credentials: [],
            };
        }


        const verificationSteps: DIDAssertionCredential['credentialSubject']['verificationSteps'] = [
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
        
        const did = await importAgent.didManagerImport({
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

        const signedImport = await importAgent.createVerifiableCredential({
            credential,
            proofFormat: 'jwt'
        });

        await storePrivateKey(didString, privateKeySub, verifiedAuthentication.id);

        try {
            const getDid = await getDIDKeys(didString);
            if(!getDid) {
                console.error("❌ Error confirming import:");
                return {
                    did: {
                        did: 'Private key does not match the public key in DID document',
                        provider: `did:${method}`,
                        keys: [],
                        services: [],
                    },
                    credentials: [],
                };
            }
        } catch (error) {
            console.error("❌ Error confirming import:", error);
            return {
                did: {
                    did: 'Private key does not match the public key in DID document',
                    provider: `did:${method}`,
                    keys: [],
                    services: [],
                },
                credentials: [],
            };
        }

        return { did, credentials: [signedImport] };
    } catch (error) {
        console.error("❌ Error importing DID:", error);
        throw error;
    }
} 

export async function getDIDKeys(did: string | any): Promise<KeyringPair$Meta | undefined> {
    let didString: any;
    if (typeof did === 'string') {
        didString = did;
    } else if (typeof did === 'object') {
        didString = did.did;
    }

    try {
        const keys = await retrieveKeys(didString);

        if (!keys) {
            throw new Error("DID not found in keyring");
        }

        return keys;
    } catch (error) {
        console.error("❌ Error getting DID keys:", error);
        return undefined;
    }
}

export async function listDIDs(agent: IOVAgent, provider?: string, ): Promise<IIdentifier[]> {
    try {
        if(!provider) {
            const findDids = await agent.didManagerFind();
            return findDids;
        }
        
        const providerDids = await agent.didManagerFind({
            provider: provider,
        });
        return providerDids;
    } catch (error) {
        console.error("❌ Error listing DIDs:", error);
        return [];
    }
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
    ensurePrimaryDIDWallet();
    if (!privateKey) {
        console.error("❌ Private key must be provided to set primary DID");
        return false;
    }
    console.log("🔑 Setting primary DID", did);
    if(!userAgent) {
        console.error("❌ User agent not found");
        return false;
    }
    const publicKeyMultibase = await getPublicKeyMultibase(did, userAgent);
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

        const verificationSteps: DIDAssertionCredential['credentialSubject']['verificationSteps'] = [
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

        // Add the key pair to the keyring using the raw private key
        const pair = kr.addFromSeed(privateKeySub, { did, isPrimary: true });
        kr.addPair(pair);

         // ✅ Ensure the DID is imported into Veramo
        try {
            await userAgent?.didManagerImport({
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

            const signedImport = await userAgent?.createVerifiableCredential({
                credential,
                proofFormat: 'jwt'
            });
            
            const privateKeyBuffer = Uint8Array.from(Buffer.from(privateKey, 'base64'));
            await storePrivateKey(did, privateKeyBuffer, "default");
            // ✅ Encrypt and store the private key
            const encryptedPrivateKey = encryptPrivateKey(privateKey, password);

            const packageJsonPath = path.join(__dirname, '../package.json');
            const environmentMetadata = await getEnvironmentMetadata(packageJsonPath);

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

            const signedEnvironmentVC = await userAgent?.createVerifiableCredential({
                credential: environmentCredential,
                proofFormat: 'jwt'
            });

            console.log("✅ Signed Environment VC", signedEnvironmentVC);

            const storedKeys = {
                encryptedPrivateKey,
                meta: { did, isPrimary: true, didCredential: signedImport, environmentCredential: signedEnvironmentVC },
            };

            fs.writeFileSync(PRIMARY_DID_WALLET_FILE, JSON.stringify(storedKeys, null, 2));
            
            const encryptionKey = await getEncryptionKey();
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
                // Store the encryption key in a file
                storeEncryptionKey(encryptionKey);
            } else {
                // Encrypt the password
                const encryptedPassword = encryptPrivateKey(password, encryptionKey);
                // Store the encrypted password in a file
                fs.writeFileSync(passwordFilePath, JSON.stringify(encryptedPassword));
            }

            return { credentials: [signedImport, signedEnvironmentVC] };
        } catch (error) {
            console.error("❌ Failed to import DID into Veramo:", error);
            return false;
        }
    } catch (error) {
        console.error("❌ Error setting primary DID:", error);
        return false;
    }
}

export async function verifyPrimaryDID(password: string): Promise<string | false | null> {
    ensurePrimaryDIDWallet();
    try {
        const storedData = fs.readFileSync(PRIMARY_DID_WALLET_FILE, 'utf8');
        const { encryptedPrivateKey, meta } = JSON.parse(storedData);
        if(!encryptedPrivateKey) return false;
        
        const did: string = meta.did;
        const privateKey = decryptPrivateKey(encryptedPrivateKey, password);
        if (!privateKey) {
            console.error("❌ Failed to decrypt private key");
            return false;
        }

        // Import the DID using the decrypted private key
        try {
            await userAgent?.didManagerImport({
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