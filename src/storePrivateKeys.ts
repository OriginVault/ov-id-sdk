import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import os from 'os';
import path from 'path';
import { userAgent } from './userAgent.js';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2'; // Ensure correct import
import dotenv from 'dotenv';
import fs from 'fs';
import { DIDResolutionResult, VerificationMethod } from 'did-resolver';
import { decryptPrivateKey } from './encryption.js';
import inquirer from 'inquirer';
import { KeyringPair$Json } from '@polkadot/keyring/types.js';
import { VerifiableCredential } from '@originvault/ov-types';

dotenv.config();

ed25519.etc.sha512Sync = sha512;

// Initialize keyring
let keyring: Keyring | undefined;

export const KEYRING_FILE = path.join(os.homedir(), '.originvault-cheqd-did-keyring.json');

// Define the path for the encryption key file

const keyStore = {
    encryptionKeyFilePath: path.join(os.homedir(), '.originvault-encryption-key'),
    privateEncryptionKey: process.env.ENCRYPTION_KEY || 'admin-key',
}

async function initializeEncryptionKey() {
    try {
        const keyPath = path.join(os.homedir(), '.originvault-encryption-key');
        if (!fs.existsSync(keyPath)) {
            if(process.env.ENCRYPTION_KEY) {
                keyStore.privateEncryptionKey = process.env.ENCRYPTION_KEY;
                keyStore.encryptionKeyFilePath = keyPath;
                return;
            }
            const { encryptionKey: inputKey } = await inquirer.prompt([
                {
                    type: 'password',
                    name: 'encryptionKey',
                    message: 'Enter an encryption key to encrypt the password:',
                    mask: '*',
                },
            ]);
            // Store the encryption key in the file
            fs.writeFileSync(keyPath, JSON.stringify({ key: inputKey }), 'utf8');
            keyStore.privateEncryptionKey = inputKey;
            keyStore.encryptionKeyFilePath = keyPath;
        } else {
            const { key } = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
            keyStore.privateEncryptionKey = key;
        }
    } catch (error) {
        console.error("❌ Error initializing encryption key:", error);
        throw error;
    }
}

export async function getEncryptionKey(): Promise<string> {
    await initializeEncryptionKey();
    return keyStore.privateEncryptionKey;
}

// Ensure the keyring is initialized
export async function ensureKeyring(): Promise<Keyring> {
    await initializeEncryptionKey();
    
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
export const getVerifiedAuthentication = async (did: string): Promise<VerificationMethod | null> => {
    let resolvedDid: DIDResolutionResult | undefined = await userAgent?.resolveDid({ didUrl: did });
    if (!resolvedDid) {
        console.error("❌ DID could not be resolved", did);
        return null;
    }
    const didDoc = resolvedDid.didDocument;
    const authentication = didDoc?.authentication?.[0];
    if (!authentication) {
        console.error("❌ No authentication found for DID", did);
        return null;
    }
    const verificationMethods = didDoc.verificationMethod;
    if (!verificationMethods) {
        console.error("❌ No verification method found for DID", did);
        return null;
    }
    const verifiedAuthentication = verificationMethods.find(method => method.id === authentication);
    if (!verifiedAuthentication) {
        console.error("❌ Could not find verification method for standard did authentication", did);
        return null;
    }
    return verifiedAuthentication;
}

export const getPublicKeyMultibase = async (did: string): Promise<string | undefined> => {
    const verifiedAuthentication = await getVerifiedAuthentication(did);
    if (!verifiedAuthentication) {
        return undefined;
    }
    const publicKeyMultibase = verifiedAuthentication.publicKeyMultibase;
    return publicKeyMultibase;
}


export async function getPrivateKeyForPrimaryDID(password: string) {
    await ensureKeyring();
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

export async function storePrivateKey(keyName: string, privateKey: Uint8Array, kid: string): Promise<void> {
    try {
        // Check the length of the private key
        if (privateKey.length === 64) {
            privateKey = privateKey.slice(0, 32); // Use only the first 32 bytes
        } else if (privateKey.length !== 32) {
            throw new Error("Invalid private key length. Expected 32 bytes or 64 bytes.");
        }

        const kr = await ensureKeyring();

        const pair = kr.addFromSeed(privateKey, { keyName, isPrimary: false, kid });
        kr.addPair(pair);
        
        fs.writeFileSync(KEYRING_FILE, JSON.stringify(kr.getPairs().map(pair => pair.toJson()), null, 2));

        // Check if the private key is stored correctly
        const storedData = JSON.parse(fs.readFileSync(KEYRING_FILE, 'utf8'));
        const isKeyStored = storedData.some((pair: any) => pair.address === pair.address); // Adjust this condition as needed
        if (!isKeyStored) {
            console.error("❌ Private Key not found in the keyring file.");
        }
    } catch (error) {
        console.error("❌ Error storing private key:", error);
        throw error;
    }
}

export async function retrievePrivateKey(keyName: string): Promise<KeyringPair$Json | undefined> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs().map(pair => pair.toJson());

        const pair = pairs.find(p => p.meta.keyName === keyName);
        return pair;
    } catch (error) {
        console.error("❌ Error retrieving private key:", error);
        return undefined;
    }
}

export async function listAllKeys(): Promise<{ did: string; privateKey: string; isPrimary: boolean }[]> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs().map(pair => pair.toJson());
        return pairs.map(pair => ({
            did: pair.meta.keyName as string,
            privateKey: pair.address,
            isPrimary: pair.meta.isPrimary as boolean,
            kid: pair.meta.kid as string
        }));
    } catch (error) {
        console.error("❌ Error listing keys:", error);
        return [];
    }
}

export async function deleteKey(did: string): Promise<boolean> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs().map(pair => pair.toJson());
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

export function setPrimaryVc(signedVC: VerifiableCredential) {
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

export async function getPrimaryVC(): Promise<VerifiableCredential | null> {
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

// ✅ Ensure the password file exists
function ensurePasswordFileExists() {
    const passwordFilePath = path.join(os.homedir(), '.encrypted-password');
    if (!fs.existsSync(passwordFilePath)) {
        fs.writeFileSync(passwordFilePath, JSON.stringify("")); // Create an empty password file
    }
}
