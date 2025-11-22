import crypto from 'crypto';

/**
 * AES-RSA Encryption for DIDComm Messages
 * 
 * Solves the RSA message size limitation by using:
 * 1. AES for message encryption (no size limits)
 * 2. RSA for AES key encryption (secure key exchange)
 * 
 * This allows large messages to be encrypted with public/private key pairs.
 */

export interface AESRSAEncryptedMessage {
  encryptedData: string;     // AES encrypted message (base64)
  encryptedKey: string;      // RSA encrypted AES key (base64)
  iv: string;                // AES initialization vector (base64)
  algorithm: string;         // Always 'aes-rsa'
}

/**
 * Encrypt a message using AES-RSA encryption
 * 
 * @param message - The message to encrypt
 * @param publicKeyPem - The recipient's RSA public key in PEM format
 * @returns AESRSAEncryptedMessage object
 */
export function encryptWithPublicKeyAESRSA(message: string, publicKeyPem: string): AESRSAEncryptedMessage {
  try {
    // Validate message
    if (!message || typeof message !== 'string' || message.length === 0) {
      throw new Error('Invalid message: must be a non-empty string');
    }
    
    // Validate and clean the public key
    if (!publicKeyPem || typeof publicKeyPem !== 'string') {
      throw new Error('Invalid public key: must be a non-empty string');
    }
    
    // Ensure proper PEM format
    let cleanedKey = publicKeyPem.trim();
    if (!cleanedKey.includes('-----BEGIN PUBLIC KEY-----')) {
      throw new Error('Invalid public key format: must be in PEM format');
    }
    
    // Normalize line endings and ensure proper formatting
    // Handle literal \n characters from environment variables
    cleanedKey = cleanedKey.replace(/\\n/g, '\n').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    
    // Step 1: Generate a random AES key (256-bit)
    const aesKey = crypto.randomBytes(32);
    
    // Step 2: Generate a random IV for AES
    const iv = crypto.randomBytes(16);
    
    // Step 3: Encrypt the message with AES-256-CBC
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    
    let encryptedData = cipher.update(message, 'utf8', 'base64');
    encryptedData += cipher.final('base64');
    
    // Step 4: Encrypt the AES key with RSA
    const encryptedKey = crypto.publicEncrypt({
      key: cleanedKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    }, aesKey).toString('base64');
    
    return {
      encryptedData,
      encryptedKey,
      iv: iv.toString('base64'),
      algorithm: 'aes-rsa'
    };
    
  } catch (error) {
    console.error('❌ AES-RSA encryption failed:', error);
    if (publicKeyPem && typeof publicKeyPem === 'string') {
      console.error('Public key preview:', publicKeyPem.substring(0, 100) + '...');
    }
    throw new Error(`AES-RSA encryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Decrypt an AES-RSA encrypted message using private key
 * 
 * @param aesRsaMessage - The AES-RSA encrypted message object
 * @param privateKeyPem - The recipient's RSA private key in PEM format
 * @returns Decrypted message string
 */
export function decryptWithPrivateKeyAESRSA(aesRsaMessage: AESRSAEncryptedMessage, privateKeyPem: string): string {
  try {
    // Validate the message format
    if (aesRsaMessage.algorithm !== 'aes-rsa') {
      throw new Error(`Unsupported algorithm: ${aesRsaMessage.algorithm}`);
    }
    
    // Validate and clean the private key
    if (!privateKeyPem || typeof privateKeyPem !== 'string') {
      throw new Error('Invalid private key: must be a non-empty string');
    }
    
    // Ensure proper PEM format
    let cleanedPrivateKey = privateKeyPem.trim();
    if (!cleanedPrivateKey.includes('-----BEGIN')) {
      throw new Error('Invalid private key format: must be in PEM format');
    }
    
    // Normalize line endings and ensure proper formatting
    // Handle literal \n characters from environment variables
    cleanedPrivateKey = cleanedPrivateKey.replace(/\\n/g, '\n').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    
    // Step 1: Decrypt the AES key with RSA
    const encryptedKeyBuffer = Buffer.from(aesRsaMessage.encryptedKey, 'base64');
    
    const aesKey = crypto.privateDecrypt({
      key: cleanedPrivateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    }, encryptedKeyBuffer);
    
    // Step 2: Decrypt the message with AES
    const iv = Buffer.from(aesRsaMessage.iv, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    
    let decryptedMessage = decipher.update(aesRsaMessage.encryptedData, 'base64', 'utf8');
    decryptedMessage += decipher.final('utf8');
    
    return decryptedMessage;
    
  } catch (error) {
    console.error('❌ AES-RSA decryption failed:', error);
    console.error('   Error details:', {
      name: error instanceof Error ? error.name : 'Unknown',
      message: error instanceof Error ? error.message : String(error),
      code: (error as any)?.code || 'N/A'
    });
    throw new Error(`AES-RSA decryption failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Convenience function to check if a message is AES-RSA encrypted
 */
export function isAESRSAEncryptedMessage(obj: any): obj is AESRSAEncryptedMessage {
  return !!(obj && 
         typeof obj === 'object' &&
         typeof obj.encryptedData === 'string' &&
         typeof obj.encryptedKey === 'string' &&
         typeof obj.iv === 'string' &&
         obj.algorithm === 'aes-rsa');
}
