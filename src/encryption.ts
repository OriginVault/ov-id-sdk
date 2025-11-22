import crypto from 'crypto';
import { promisify } from 'util';
import * as bip39 from 'bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import * as ed25519 from '@noble/ed25519';
import { getPublicKeyMultibase } from './storePrivateKeys.js';
import { encryptData } from './dataManager.js';
import multibase from 'multibase';

export interface SecureEncryptionResult {
  encryptedData: string;
  iv: string;
  salt: string;
  authTag: string;
  algorithm: string;
}

export async function encryptPrivateKeySecure(
  privateKey: string, 
  password: string
): Promise<SecureEncryptionResult> {
  try {
    // Validate inputs
    if (!privateKey || privateKey.trim() === '') {
      throw new Error('Secure encryption failed: Private key cannot be empty');
    }
    if (!password || password.trim() === '') {
      throw new Error('Secure encryption failed: Password cannot be empty');
    }

    // Generate cryptographically secure salt and IV
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Derive key using scrypt (much stronger than SHA256)
    const scryptAsync = promisify(crypto.scrypt);
    const derivedKey = await scryptAsync(password, salt, 32) as Buffer;
    
    // Use AES-256-GCM for authenticated encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
    
    let encryptedData = cipher.update(privateKey, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    
    // Get authentication tag for integrity verification
    const authTag = cipher.getAuthTag();
    
    // Zero out derived key from memory
    derivedKey.fill(0);
    
    return {
      encryptedData,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm: 'aes-256-gcm'
    };
  } catch (error) {
    throw new Error(`Secure encryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}


export async function decryptPrivateKeySecure(
  encryptedResult: SecureEncryptionResult,
  password: string
): Promise<string> {
  try {
    // Derive the same key using stored salt
    const salt = Buffer.from(encryptedResult.salt, 'hex');
    const scryptAsync = promisify(crypto.scrypt);
    const derivedKey = await scryptAsync(password, salt, 32) as Buffer;
    
    // Prepare for decryption
    const iv = Buffer.from(encryptedResult.iv, 'hex');
    const authTag = Buffer.from(encryptedResult.authTag, 'hex');
    
    // Use AES-256-GCM for authenticated decryption
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
    decipher.setAuthTag(authTag);
    
    let decryptedData = decipher.update(encryptedResult.encryptedData, 'hex', 'utf8');
    decryptedData += decipher.final('utf8');
    
    // Zero out derived key from memory
    derivedKey.fill(0);
    
    return decryptedData;
  } catch (error) {
    throw new Error(`Secure decryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// Legacy compatibility function - handles both old and new encryption formats
export async function decryptPrivateKeyLegacy(
  encryptedData: { iv: string, encrypted: string } | SecureEncryptionResult,
  password: string
): Promise<string | null> {
  try {
    // Check if it's the new secure format
    if ('salt' in encryptedData && 'authTag' in encryptedData && 'algorithm' in encryptedData) {
      return await decryptPrivateKeySecure(encryptedData as SecureEncryptionResult, password);
    }
    
    // Handle old format - this is deprecated and should be migrated
    console.warn('⚠️  Using deprecated encryption format - please migrate to secure storage');
    const oldFormat = encryptedData as { iv: string, encrypted: string };
    const iv = Buffer.from(oldFormat.iv, 'hex');
    const key = crypto.createHash('sha256').update(password).digest();
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(oldFormat.encrypted, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
  } catch (error) {
    console.error("❌ Decryption failed:", error);
    return null;
  }
}


export async function encryptDataForDID(did: string, message: string): Promise<{ encryptedMessage: string, nonce: string } | null> {
    const publicKeyMultibase = await getPublicKeyMultibase(did);
    if (!publicKeyMultibase) return null;
    
    const decodedPublicKey = multibase.decode(Buffer.from(publicKeyMultibase, 'utf-8')).slice(2);
    const encryptedData = await encryptData(decodedPublicKey, message);
    return encryptedData;
}


export async function convertRecoveryToPrivateKey(mnemonic: string): Promise<string> {
    try {
      if (!mnemonic || mnemonic.trim() === '') {
        throw new Error('Error converting recovery phrase: Mnemonic cannot be empty');
      }

      const entropy = bip39.mnemonicToEntropy(mnemonic, wordlist);
      const privateKey = Buffer.from(entropy, 'hex');

      const publicKey = await ed25519.getPublicKey(privateKey);

      // Step 3: Concatenate private and public keys
      const fullKey = Buffer.concat([privateKey, publicKey]);

      return fullKey.toString('base64');
    } catch (error) {
        console.error("Error converting recovery phrase:", error);
        throw new Error(`Error converting recovery phrase: ${error instanceof Error ? error.message : String(error)}`);
    }
}

export async function convertPrivateKeyToRecovery(privateKey: string): Promise<string> {
    try {
        if (!privateKey || privateKey.trim() === '') {
            throw new Error('Error converting private key to recovery phrase: Private key cannot be empty');
        }

        // Decode base64 private key to Uint8Array
        const decodedKey = Buffer.from(privateKey, 'base64');
        
        if (!(decodedKey instanceof Uint8Array)) {
            throw new Error("Private key is not a Uint8Array");
        }

        // Validate private key length
        if (decodedKey.length !== 64 && decodedKey.length !== 32) {
            throw new Error(`Invalid private key length: Expected 64 or 32 bytes, got ${decodedKey.length}`);
        }

        // Extract the private key (first 32 bytes)
        const privateKeySlice = decodedKey.length === 64 ? decodedKey.subarray(0, 32) : decodedKey;

        // Convert private key to mnemonic
        const mnemonic = bip39.entropyToMnemonic(privateKeySlice, wordlist);

        return mnemonic;
    } catch (error) {
        console.error("❌ Error converting private key to recovery phrase:", error);
        throw new Error(`Error converting private key to recovery phrase: ${error instanceof Error ? error.message : String(error)}`);
    }
}

export async function convertHexKeyToRecovery(hexKey: string): Promise<string> {
    try {
        if (!hexKey || hexKey.trim() === '') {
            throw new Error('Error converting hex key to recovery phrase: Hex key cannot be empty');
        }

        // Validate hex format
        if (!/^[0-9a-fA-F]+$/.test(hexKey)) {
            throw new Error('Error converting hex key to recovery phrase: Invalid hex format');
        }

        // Convert from hex
        const decodedKey = Buffer.from(hexKey, 'hex');
        console.log("🔑 Decoded key length:", decodedKey.length);

        // Extract the private key (first 32 bytes)
        const recovery = await convertPrivateKeyToRecovery(decodedKey.toString('base64'));

        return recovery;
    } catch (error) {
        console.error("❌ Error converting hex key to recovery phrase:", error);
        throw new Error(`Error converting hex key to recovery phrase: ${error instanceof Error ? error.message : String(error)}`);
    }
}

// Enhanced key encryption service for secure key storage
export interface EncryptedKeyData {
  encryptedData: string;
  iv: string;
  salt: string;
  algorithm: string;
  keyDerivation: string;
}

export class KeyEncryptionService {
  private encryptionKey: Buffer;
  private keyDerivationSalt: Buffer;

  constructor(encryptionKey: string) {
    this.keyDerivationSalt = crypto.randomBytes(32);
    this.encryptionKey = Buffer.from(encryptionKey, 'utf8');
  }

  /**
   * Encrypt a key using the encryption key
   */
  async encryptKey(keyData: string): Promise<EncryptedKeyData> {
    const salt = crypto.randomBytes(32);
    const derivedKey = await this.deriveKey(this.encryptionKey, salt);
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
    
    let encrypted = cipher.update(keyData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encryptedData: encrypted + authTag.toString('hex'),
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      algorithm: 'aes-256-gcm',
      keyDerivation: 'scrypt'
    };
  }

  /**
   * Decrypt a key using the encryption key
   */
  async decryptKey(encryptedKey: EncryptedKeyData): Promise<string> {
    const salt = Buffer.from(encryptedKey.salt, 'hex');
    const derivedKey = await this.deriveKey(this.encryptionKey, salt);
    
    const iv = Buffer.from(encryptedKey.iv, 'hex');
    const encryptedData = encryptedKey.encryptedData;
    
    // Extract auth tag (last 32 hex chars)
    const authTag = Buffer.from(encryptedData.slice(-32), 'hex');
    const ciphertext = encryptedData.slice(0, -32);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  private async deriveKey(key: Buffer, salt: Buffer): Promise<Buffer> {
    const scryptAsync = promisify(crypto.scrypt);
    return (await scryptAsync(key, salt, 32)) as Buffer;
  }
}

// Helper functions for key encryption
export async function encryptKeyWithService(keyData: string, encryptionKey: string): Promise<EncryptedKeyData> {
  const service = new KeyEncryptionService(encryptionKey);
  return await service.encryptKey(keyData);
}

export async function decryptKeyWithService(encryptedKey: EncryptedKeyData, encryptionKey: string): Promise<string> {
  const service = new KeyEncryptionService(encryptionKey);
  return await service.decryptKey(encryptedKey);
}
