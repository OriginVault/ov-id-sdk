import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import axios from "axios";
import os from 'os';
import path from 'path';
import { agent } from './veramoAgent.js';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2'; // Ensure correct import
import multibase from 'multibase';
import dotenv from 'dotenv';
import fs from 'fs';
import { v5 as uuidv5 } from 'uuid'; // Import the uuid library
import { encryptPrivateKey, decryptPrivateKey } from './encryption.js';
import { encryptData } from './dataManager.js';
import { DIDAssertionCredentialSubject, DIDAssertionCredential } from '@originvault/ov-types';
import { getDevelopmentEnvironmentMetadata, getProductionEnvironmentMetadata } from './environment.js';
import inquirer from 'inquirer';

dotenv.config();

ed25519.etc.sha512Sync = sha512;

// Initialize keyring
let keyring: Keyring | undefined;

const KEYRING_FILE = path.join(os.homedir(), '.cheqd-did-keyring.json');

// Define the path for the encryption key file
const encryptionKeyFilePath = path.join(os.homedir(), '.encryption-key');

let encryptionKey: string | undefined;

async function initializeEncryptionKey() {
    if (!fs.existsSync(encryptionKeyFilePath)) {
        // Prompt for the encryption key if the file does not exist
        const { encryptionKey: inputKey } = await inquirer.prompt([
            {
                type: 'password',
                name: 'encryptionKey',
                message: 'Enter an encryption key to encrypt the password:',
                mask: '*',
            },
        ]);
        // Store the encryption key in the file
        fs.writeFileSync(encryptionKeyFilePath, JSON.stringify({ key: inputKey }), 'utf8');
        encryptionKey = inputKey;
    } else {
        const { key } = JSON.parse(fs.readFileSync(encryptionKeyFilePath, 'utf8'));
        encryptionKey = key;
    }
}

// Call the initialization function at the start
initializeEncryptionKey().catch(error => {
    console.error("❌ Error initializing encryption key:", error);
});

// Ensure the keyring is initialized
async function ensureKeyring(): Promise<Keyring> {
    if (!encryptionKey) {
        await initializeEncryptionKey();
    }
    
    if (!keyring) {
        await cryptoWaitReady();
        keyring = new Keyring({ type: 'ed25519' });

        if (fs.existsSync(KEYRING_FILE)) {
            const storedData = JSON.parse(fs.readFileSync(KEYRING_FILE, 'utf8'));
            if (storedData && storedData.meta) {
                const keys = storedData.meta.keys || [];
                keys.forEach((key: any) => {
                    keyring?.addPair(key);
                });
            }
        }
    }
    return keyring;
}

// Exported functions
export const getVerifiedAuthentication = async (did: string) => {
    const resolvedDid = await agent.resolveDid({ didUrl: did });
    if (!resolvedDid) {
        console.error("❌ DID could not be resolved", did);
        return false;
    }
    const didDoc = resolvedDid.didDocument;
    const authentication = didDoc?.authentication?.[0];
    if (!authentication) {
        console.error("❌ No authentication found for DID", did);
        return false;
    }
    const verificationMethods = didDoc.verificationMethod;
    if (!verificationMethods) {
        console.error("❌ No verification method found for DID", did);
        return false;
    }
    const verifiedAuthentication = verificationMethods.find(method => method.id === authentication);
    if (!verifiedAuthentication) {
        console.error("❌ Could not find verification method for standard did authentication", did);
        return false;
    }
    return verifiedAuthentication;
}

export const getPublicKeyMultibase = async (did: string) => {
    const verifiedAuthentication = await getVerifiedAuthentication(did);
    if (!verifiedAuthentication) {
        return false;
    }
    const publicKeyMultibase = verifiedAuthentication.publicKeyMultibase;
    return publicKeyMultibase;
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

export async function getPrivateKeyForPrimaryDID(password: string) {
    const storedData = fs.readFileSync(KEYRING_FILE, 'utf8');
    const { encryptedPrivateKey } = JSON.parse(storedData);
    if(!encryptedPrivateKey) return false;

    const privateKey = decryptPrivateKey(encryptedPrivateKey, password);
    if (!privateKey) {
        console.error("❌ Failed to decrypt private key");
        return false;
    }

    return privateKey;
}

export async function storePrivateKey(did: string, privateKey: Uint8Array): Promise<void> {
    try {
        // Check the length of the private key
        if (privateKey.length === 64) {
            console.warn("Using only the first 32 bytes of the 64-byte private key.");
            privateKey = privateKey.slice(0, 32); // Use only the first 32 bytes
        } else if (privateKey.length !== 32) {
            throw new Error("Invalid private key length. Expected 32 bytes or 64 bytes.");
        }

        const kr = await ensureKeyring();

        const pair = kr.addFromSeed(privateKey, { did, isPrimary: false });
        kr.addPair(pair);

        fs.writeFileSync(KEYRING_FILE, JSON.stringify(kr.getPairs(), null, 2));
        console.log("🔑 Private Key Stored");
    } catch (error) {
        console.error("❌ Error storing private key:", error);
        throw error;
    }
}

export async function retrievePrivateKey(did: string): Promise<string | null> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs();
        console.log("🔑 Pairs", pairs);
        const pair = pairs.find(p => p.meta.did === did);
        return pair ? pair.address : null;
    } catch (error) {
        console.error("❌ Error retrieving private key:", error);
        return null;
    }
}

export async function listAllKeys(): Promise<{ did: string; privateKey: string; isPrimary: boolean }[]> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs();
        return pairs.map(pair => ({
            did: pair.meta.did as string,
            privateKey: pair.address,
            isPrimary: pair.meta.isPrimary as boolean
        }));
    } catch (error) {
        console.error("❌ Error listing keys:", error);
        return [];
    }
}

export async function deleteKey(did: string): Promise<boolean> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs();
        const pair = pairs.find(p => p.meta.did === did);
        if (pair) {
            kr.removePair(pair.address);
            return true;
        }
        return false;
    } catch (error) {
        console.error("❌ Error deleting key:", error);
        return false;
    }
}

export async function encryptDataForDID(did: string, message: string): Promise<{ encryptedMessage: string, nonce: string } | null> {
    const publicKeyMultibase = await getPublicKeyMultibase(did);
    if (!publicKeyMultibase) return null;
    
    const decodedPublicKey = multibase.decode(Buffer.from(publicKeyMultibase, 'utf-8')).slice(2);
    const encryptedData = await encryptData(decodedPublicKey, message);
    return encryptedData;
}

export function base64ToHex(base64) {
    // Decode the Base64 string to a byte array
    const binaryString = atob(base64); // atob decodes a Base64 string
    const byteArray = new Uint8Array(binaryString.length);
    
    for (let i = 0; i < binaryString.length; i++) {
        byteArray[i] = binaryString.charCodeAt(i);
    }

    // Convert the byte array to a hexadecimal string
    let hexString = '';
    byteArray.forEach(byte => {
        const hex = byte.toString(16).padStart(2, '0'); // Convert to hex and pad with zero if needed
        hexString += hex;
    });

    return hexString;
}

export function setPrimaryVc(signedVC: any) {
    // Log the signed VC
    console.log("Setting primary VC:", signedVC);

    // Example: Store the signed VC in a file
    const vcFilePath = path.join(os.homedir(), 'primary-vc.json');
    try {
        fs.writeFileSync(vcFilePath, JSON.stringify(signedVC, null, 2));
        console.log("✅ Primary VC stored successfully at", vcFilePath);
    } catch (error) {
        console.error("❌ Error storing primary VC:", error);
    }
}

export async function getPrimaryVC(): Promise<any | null> {
    try {
        const storedData = fs.readFileSync(KEYRING_FILE, 'utf8');
        const { meta } = JSON.parse(storedData);
        if (meta && meta.credential) {
            return meta.credential; // Return the signed VC
        }
        console.error("❌ No primary VC found in keyring.");
        return null;
    } catch (error) {
        console.error("❌ Error accessing keyring:", error);
        return null;
    }
}

export function getStoredPassword(): string | null {
    ensurePasswordFileExists();
    const passwordFilePath = path.join(os.homedir(), '.encrypted-password');
    const encryptedPassword = JSON.parse(fs.readFileSync(passwordFilePath, 'utf8').trim());

    if(!encryptedPassword.iv) {
        return encryptedPassword;
    }

    try {
        return decryptPrivateKey(encryptedPassword, process.env.ENCRYPTION_KEY || '');
    } catch (error) {
        console.error(`❌ Error retrieving stored password: ${error}`);
        return null;
    }
}

export function hexToBase64(hex: string): string {
    // Convert hex string to byte array
    const byteArray = new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
    
    // Convert byte array to Base64 string
    const binaryString = String.fromCharCode(...byteArray);
    return btoa(binaryString); // btoa encodes a binary string to Base64
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

// ✅ Ensure the password file exists
function ensurePasswordFileExists() {
    const passwordFilePath = path.join(os.homedir(), '.encrypted-password');
    if (!fs.existsSync(passwordFilePath)) {
        fs.writeFileSync(passwordFilePath, JSON.stringify("")); // Create an empty password file
    }
}
