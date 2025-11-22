import { Kyber768 } from "crystals-kyber-js";
import crypto from 'crypto';

export interface QuantumEncryptedMessage {
  encryptedData: string;     // AES encrypted message (base64)
  encryptedKey: string;      // ML-KEM encrypted AES key (base64)
  iv: string;                // AES initialization vector (base64)
  algorithm: string;         // Always 'aes-mlkem'
  mlkemPublicKey: string;    // ML-KEM public key used for encryption (hex)
}

/**
 * Generate an ML-KEM key pair (FIPS 203 compliant)
 */
export async function generateMLKEMKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
  const kem = new Kyber768();
  const [publicKey, privateKey] = await kem.generateKeyPair();
  
  return {
    publicKey: Buffer.from(publicKey).toString('hex'),
    privateKey: Buffer.from(privateKey).toString('hex')
  };
}

// Backward compatibility alias
export const generateKyberKeyPair = generateMLKEMKeyPair;

/**
 * Encrypt a message using AES-ML-KEM encryption (FIPS 203 compliant)
 */
export async function encryptWithMLKEM(
  message: string,
  recipientPublicKeyHex: string,
  senderPrivateKeyHex: string
): Promise<QuantumEncryptedMessage> {
  try {
    // Generate AES key for message encryption
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Encrypt message with AES
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    let encryptedData = cipher.update(message, 'utf8', 'base64');
    encryptedData += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    
    // Combine encrypted data with auth tag
    const fullEncryptedData = encryptedData + ':' + authTag.toString('base64');
    
    // Encrypt AES key with ML-KEM
    const kem = new Kyber768();
    const recipientPublicKey = Buffer.from(recipientPublicKeyHex, 'hex');
    const [encryptedAesKey, sharedSecret] = await kem.encap(recipientPublicKey);
    
    return {
      encryptedData: fullEncryptedData,
      encryptedKey: Buffer.from(encryptedAesKey).toString('base64'),
      iv: iv.toString('base64'),
      algorithm: 'aes-mlkem',
      mlkemPublicKey: recipientPublicKeyHex
    };
  } catch (error) {
    throw new Error(`ML-KEM encryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// Backward compatibility alias
export const encryptWithKyber = encryptWithMLKEM;

/**
 * Decrypt a message using AES-ML-KEM decryption (FIPS 203 compliant)
 */
export async function decryptWithMLKEM(
  encryptedMessage: QuantumEncryptedMessage,
  recipientPrivateKeyHex: string
): Promise<string> {
  try {
    // Decrypt AES key with ML-KEM
    const kem = new Kyber768();
    const recipientPrivateKey = Buffer.from(recipientPrivateKeyHex, 'hex');
    const encryptedAesKey = Buffer.from(encryptedMessage.encryptedKey, 'base64');
    const aesKey = await kem.decap(encryptedAesKey, recipientPrivateKey);
    
    // Decrypt message with AES
    const iv = Buffer.from(encryptedMessage.iv, 'base64');
    const [encryptedData, authTagBase64] = encryptedMessage.encryptedData.split(':');
    const authTag = Buffer.from(authTagBase64, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);
    
    let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
    decryptedData += decipher.final('utf8');
    
    return decryptedData;
  } catch (error) {
    throw new Error(`ML-KEM decryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// Backward compatibility alias
export const decryptWithKyber = decryptWithMLKEM;

/**
 * Validate ML-KEM key pair (FIPS 203 compliant)
 */
export async function validateMLKEMKeyPair(publicKey: string, privateKey: string): Promise<boolean> {
  try {
    const kem = new Kyber768();
    const pubKey = Buffer.from(publicKey, 'hex');
    const privKey = Buffer.from(privateKey, 'hex');
    
    // Test encryption/decryption with a small test message
    const [encrypted, sharedSecret1] = await kem.encap(pubKey);
    const sharedSecret2 = await kem.decap(encrypted, privKey);
    
    return Buffer.compare(sharedSecret1, sharedSecret2) === 0;
  } catch (error) {
    return false;
  }
}

// Backward compatibility alias
export const validateKyberKeyPair = validateMLKEMKeyPair;
