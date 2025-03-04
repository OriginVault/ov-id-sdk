import crypto from 'crypto';
import * as bip39 from 'bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import * as ed25519 from '@noble/ed25519';

export function encryptPrivateKey(privateKey, password) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(password).digest();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    let encrypted = cipher.update(privateKey, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    return { iv: iv.toString('hex'), encrypted };
}


export function decryptPrivateKey(encryptedData: { iv: string, encrypted: string }, password: string): string | null {
    try {
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const key = crypto.createHash('sha256').update(password).digest();
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf-8');
        decrypted += decipher.final('utf-8');

        return decrypted;
    } catch (error) {
        console.error("❌ Decryption failed");
        return null;
    }
}


export async function convertRecoveryToPrivateKey(mnemonic) {
    try {
      console.log("🔑 Converting recovery to private key", mnemonic);
      const entropy = bip39.mnemonicToEntropy(mnemonic, wordlist)
      console.log("🔑 Entropy", entropy);
      const privateKey = Buffer.from(entropy, 'hex');
      console.log("🔑 Private Key", privateKey);

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