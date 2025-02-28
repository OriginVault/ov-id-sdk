import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import axios from "axios";
import os from 'os';
import path from 'path';
import { agent } from './veramoAgent.js';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2'; // Ensure correct import
import * as bip39 from 'bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import multibase from 'multibase';
import dotenv from 'dotenv';
import fs from 'fs';
import { encryptPrivateKey, decryptPrivateKey } from './encryption.js';
import { encryptData } from './dataManager.js';

dotenv.config();

ed25519.etc.sha512Sync = sha512;

async function convertRecoveryToPrivateKey(mnemonic) {
    try {
      const entropy = bip39.mnemonicToEntropy(mnemonic, wordlist)
      const privateKey = Buffer.from(entropy, 'hex');

      const privateKeyBase64 = async () => {
        const publicKey = await ed25519.getPublicKey(privateKey);

        // Step 3: Concatenate private and public keys
        const fullKey = Buffer.concat([privateKey, publicKey]);

        return fullKey.toString('base64');
      }

      return privateKeyBase64();
    } catch (error) {
        console.error("Error converting recovery phrase:", error);
        throw error;
    }
}

export async function convertPrivateKeyToRecovery(privateKey) {
    try {
        // Decode base64 private key to Uint8Array
        const decodedKey = Buffer.from(privateKey, 'base64');
        
        if (!(decodedKey instanceof Uint8Array)) {
            throw new Error("Private key is not a Uint8Array");
        }

        console.log("🔑 Private Key (Hex):", Buffer.from(decodedKey).toString('hex'));

        // Validate private key length
        if (decodedKey.length !== 64) {
            throw new Error(`Invalid private key length: Expected 64 bytes, got ${decodedKey.length}`);
        }

        // Extract the private key (first 32 bytes)
        const privateKeySlice = decodedKey.subarray(0, 32);

        // Convert private key to mnemonic
        const mnemonic = bip39.entropyToMnemonic(privateKeySlice, wordlist);

        return mnemonic;
    } catch (error) {
        console.error("❌ Error converting private key to recovery phrase:", error);
        throw error;
    }
}

// Initialize keyring
let keyring: Keyring | undefined;

async function ensureKeyring(): Promise<Keyring> {
    if (!keyring) {
        await cryptoWaitReady();
        keyring = new Keyring({ type: 'ed25519' });
    }
    return keyring;
}

const KEYRING_FILE = path.join(os.homedir(), '.cheqd-did-keyring.json');

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

const getPublicKeyMultibase = async (did: string) => {
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
    const publicKeyMultibase = verifiedAuthentication.publicKeyMultibase;
    if (!publicKeyMultibase) {
        console.error("❌ No public key multibase found for verification method", did);
        return false;
    }
    return publicKeyMultibase;
}

// ✅ Set the primary DID (User Defined or Domain Verified)
export async function setPrimaryDID(did: string, privateKey: string, password: string): Promise<boolean> {
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

              // ✅ Encrypt and store the private key
            const encryptedPrivateKey = encryptPrivateKey(privateKey, password);

            const storedKeys = {
                encryptedPrivateKey,
                meta: { did, isPrimary: true }
            };

            fs.writeFileSync(KEYRING_FILE, JSON.stringify(storedKeys, null, 2));

            return true;
        } catch (error) {
            console.error("❌ Failed to import DID into Veramo:", error);
            return false;
        }
    } catch (error) {
        console.error("❌ Error setting primary DID:", error);
        return false;
    }
}

// ✅ Retrieve the primary DID
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
            if(meta) return meta.did;
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

// ✅ Retrieve the primary DID
export async function verifyPrimaryDID(password: string): Promise<string | boolean | null> {
    try {
        console.log("🔑 Verifying Primary DID", password);
        const kr = await ensureKeyring();
        const pairs = kr.getPairs();
        const primaryPair = pairs.find(p => p.meta?.isPrimary);
        let did = (primaryPair?.meta?.did || '') as string;

        if(did) return did;

        const storedData = fs.readFileSync(KEYRING_FILE, 'utf8');
        const { encryptedPrivateKey, meta } = JSON.parse(storedData);
        if(!encryptedPrivateKey) return false;
        did = meta.did;
        console.log("🔑 Did", storedData);
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
            console.log("✅ DID successfully imported into Veramo.");
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


export async function storePrivateKey(did: string, privateKey: string): Promise<void> {
    try {
        const kr = await ensureKeyring();
        const pair = kr.addFromUri(privateKey, { did, isPrimary: false });
        kr.addPair(pair);
    } catch (error) {
        console.error("❌ Error storing private key:", error);
        throw error;
    }
}

export async function retrievePrivateKey(did: string): Promise<string | null> {
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs();
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

function base64ToHex(base64) {
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
