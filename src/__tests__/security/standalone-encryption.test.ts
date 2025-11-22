import { promisify } from 'util';
import * as crypto from 'crypto';
import { EnvelopeEncryptionService } from '../../security/envelope-encryption.service.js';
import { 
  encryptWithPublicKeyAESRSA, 
  decryptWithPrivateKeyAESRSA 
} from '../../aesRsaEncryption.js';

// Standalone secure encryption functions (copied from encryption.ts to avoid import issues)
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
    throw new Error(`Secure encryption failed: ${error.message}`);
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
    throw new Error(`Secure decryption failed: ${error.message}`);
  }
}

describe('Standalone Security Functionality Tests', () => {
  let envelopeService: EnvelopeEncryptionService;
  let testKeyPair: crypto.KeyPairKeyObjectResult;

  beforeAll(() => {
    // Set up test environment
    process.env.OV_MASTER_ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    process.env.OV_ENABLE_ENVELOPE_ENCRYPTION = 'true';
    process.env.OV_ENABLE_MEMORY_PROTECTION = 'true';
    process.env.OV_KEY_ROTATION_ENABLED = 'true';
    
    // Generate test RSA key pair for AES-RSA tests
    testKeyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
  });

  beforeEach(() => {
    envelopeService = EnvelopeEncryptionService.getInstance();
  });

  afterAll(() => {
    // Clean up environment
    delete process.env.OV_MASTER_ENCRYPTION_KEY;
    delete process.env.OV_ENABLE_ENVELOPE_ENCRYPTION;
    delete process.env.OV_ENABLE_MEMORY_PROTECTION;
    delete process.env.OV_KEY_ROTATION_ENABLED;
  });

  describe('Envelope Encryption Service', () => {
    test('should encrypt and decrypt data correctly', async () => {
      const testData = 'This is highly sensitive test data that must be protected';
      
      // Encrypt
      const encryptedResult = await envelopeService.encrypt(testData);
      expect(encryptedResult).toBeDefined();
      expect(encryptedResult.encryptedData).toBeDefined();
      expect(encryptedResult.encryptedDEK).toBeDefined();
      expect(encryptedResult.keyId).toBeDefined();
      expect(encryptedResult.algorithm).toBe('AES-256-GCM');
      expect(encryptedResult.version).toBe(1);
      
      // Decrypt
      const decryptedData = await envelopeService.decrypt(encryptedResult);
      expect(decryptedData).toBe(testData);
    });

    test('should handle key rotation without data loss', async () => {
      const testData = 'Test data for key rotation';
      
      // Encrypt with current key
      const encryptedResult = await envelopeService.encrypt(testData);
      const originalKeyId = envelopeService.getCurrentKeyId();
      
      // Rotate keys
      const oldKeyId = await envelopeService.rotateKeys();
      expect(oldKeyId).toBe(originalKeyId);
      
      // Verify new key is different
      const newKeyId = envelopeService.getCurrentKeyId();
      expect(newKeyId).not.toBe(originalKeyId);
      
      // Decrypt with new key (should still work)
      const decryptedData = await envelopeService.decrypt(encryptedResult);
      expect(decryptedData).toBe(testData);
    });

    test('should protect against tampering', async () => {
      const testData = 'Test data for tampering protection';
      
      const encryptedResult = await envelopeService.encrypt(testData);
      
      // Tamper with the authentication tag (this should definitely fail)
      const tamperedResult = {
        ...encryptedResult,
        authTag: 'tampered-auth-tag'
      };
      
      // Should throw error when trying to decrypt tampered data
      await expect(envelopeService.decrypt(tamperedResult)).rejects.toThrow();
    });

    test('should generate unique key IDs', async () => {
      const keyId1 = envelopeService.getCurrentKeyId();
      
      await envelopeService.rotateKeys();
      const keyId2 = envelopeService.getCurrentKeyId();
      
      expect(keyId1).not.toBe(keyId2);
    });

    test('should track key metadata', async () => {
      const keyId = envelopeService.getCurrentKeyId();
      const metadata = envelopeService.getKeyMetadata(keyId);
      
      expect(metadata).toBeDefined();
      expect(metadata?.keyId).toBe(keyId);
      expect(metadata?.algorithm).toBe('AES-256-GCM');
      expect(metadata?.isActive).toBe(true);
    });
  });

  describe('Secure Encryption Functions', () => {
    test('should encrypt and decrypt private keys securely', async () => {
      const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const testPassword = 'test-password-123';
      
      // Encrypt
      const encryptedResult = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      expect(encryptedResult).toBeDefined();
      expect(encryptedResult.encryptedData).toBeDefined();
      expect(encryptedResult.iv).toBeDefined();
      expect(encryptedResult.salt).toBeDefined();
      expect(encryptedResult.authTag).toBeDefined();
      expect(encryptedResult.algorithm).toBe('aes-256-gcm');
      
      // Decrypt
      const decryptedKey = await decryptPrivateKeySecure(encryptedResult, testPassword);
      expect(decryptedKey).toBe(testPrivateKey);
    });

    test('should reject wrong password in decryption', async () => {
      const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const correctPassword = 'correct-password';
      const wrongPassword = 'wrong-password';
      
      // Encrypt with correct password
      const encryptedResult = await encryptPrivateKeySecure(testPrivateKey, correctPassword);
      
      // Try to decrypt with wrong password
      await expect(decryptPrivateKeySecure(encryptedResult, wrongPassword)).rejects.toThrow();
    });

    test('should use different IVs for same data', async () => {
      const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const testPassword = 'test-password';
      
      // Encrypt same data twice
      const encrypted1 = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      const encrypted2 = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      // IVs should be different
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.salt).not.toBe(encrypted2.salt);
      expect(encrypted1.encryptedData).not.toBe(encrypted2.encryptedData);
      
      // But both should decrypt to the same result
      const decrypted1 = await decryptPrivateKeySecure(encrypted1, testPassword);
      const decrypted2 = await decryptPrivateKeySecure(encrypted2, testPassword);
      expect(decrypted1).toBe(decrypted2);
      expect(decrypted1).toBe(testPrivateKey);
    });
  });

  describe('Performance Tests', () => {
    test('should handle multiple concurrent encryptions', async () => {
      const testData = 'Concurrent test data';
      const promises = [];
      
      // Create 10 concurrent encryption operations
      for (let i = 0; i < 10; i++) {
        promises.push(envelopeService.encrypt(testData + i));
      }
      
      const results = await Promise.all(promises);
      expect(results).toHaveLength(10);
      
      // Verify all results are different (different IVs/salts)
      const encryptedDataValues = results.map(r => r.encryptedData);
      const uniqueValues = new Set(encryptedDataValues);
      expect(uniqueValues.size).toBe(10);
    });

    test('should handle large data encryption', async () => {
      // Create 1MB of test data
      const largeData = 'x'.repeat(1024 * 1024);
      
      const startTime = Date.now();
      const encryptedResult = await envelopeService.encrypt(largeData);
      const encryptTime = Date.now() - startTime;
      
      const decryptStartTime = Date.now();
      const decryptedData = await envelopeService.decrypt(encryptedResult);
      const decryptTime = Date.now() - decryptStartTime;
      
      expect(decryptedData).toBe(largeData);
      expect(encryptTime).toBeLessThan(5000); // Should encrypt in less than 5 seconds
      expect(decryptTime).toBeLessThan(5000); // Should decrypt in less than 5 seconds
    });
  });

  describe('AES-RSA Encryption', () => {
    test('should encrypt and decrypt messages with RSA keys', () => {
      const message = 'Test message for AES-RSA encryption';
      
      const encrypted = encryptWithPublicKeyAESRSA(message, testKeyPair.publicKey);
      expect(encrypted.algorithm).toBe('aes-rsa');
      expect(encrypted.encryptedData).toBeDefined();
      expect(encrypted.encryptedKey).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, testKeyPair.privateKey);
      expect(decrypted).toBe(message);
    });

    test('should handle environment variable format private keys', () => {
      const message = 'Test message with env format key';
      
      // Simulate environment variable format with literal \n
      const envPrivateKey = testKeyPair.privateKey.replace(/\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, testKeyPair.publicKey);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, envPrivateKey);
      
      expect(decrypted).toBe(message);
    });

    test('should handle large messages with AES-RSA', () => {
      const message = 'A'.repeat(50000); // 50KB message
      
      const encrypted = encryptWithPublicKeyAESRSA(message, testKeyPair.publicKey);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, testKeyPair.privateKey);
      
      expect(decrypted).toBe(message);
    });

    test('should produce different encrypted data for same message', () => {
      const message = 'Test message for uniqueness';
      
      const encrypted1 = encryptWithPublicKeyAESRSA(message, testKeyPair.publicKey);
      const encrypted2 = encryptWithPublicKeyAESRSA(message, testKeyPair.publicKey);
      
      // Should be different due to random IV and AES key
      expect(encrypted1.encryptedData).not.toBe(encrypted2.encryptedData);
      expect(encrypted1.encryptedKey).not.toBe(encrypted2.encryptedKey);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      
      // But both should decrypt to the same message
      const decrypted1 = decryptWithPrivateKeyAESRSA(encrypted1, testKeyPair.privateKey);
      const decrypted2 = decryptWithPrivateKeyAESRSA(encrypted2, testKeyPair.privateKey);
      
      expect(decrypted1).toBe(message);
      expect(decrypted2).toBe(message);
    });
  });

  describe('Error Handling', () => {
    test('should handle encryption errors gracefully', async () => {
      // Test with invalid data
      await expect(envelopeService.encrypt(null as any)).rejects.toThrow();
    });

    test('should handle decryption errors gracefully', async () => {
      const invalidResult = {
        encryptedData: 'invalid',
        encryptedDEK: 'invalid',
        keyId: 'invalid',
        iv: 'invalid',
        salt: 'invalid',
        authTag: 'invalid',
        algorithm: 'AES-256-GCM',
        version: 1
      };
      
      await expect(envelopeService.decrypt(invalidResult)).rejects.toThrow();
    });

    test('should handle invalid password in secure encryption', async () => {
      const testPrivateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const testPassword = 'test-password';
      
      const encryptedResult = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      // Try with wrong password
      await expect(decryptPrivateKeySecure(encryptedResult, 'wrong-password')).rejects.toThrow();
    });

    test('should handle AES-RSA decryption errors', () => {
      const message = 'Test message';
      const encrypted = encryptWithPublicKeyAESRSA(message, testKeyPair.publicKey);
      
      // Test with wrong private key
      const wrongKeyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      expect(() => {
        decryptWithPrivateKeyAESRSA(encrypted, wrongKeyPair.privateKey);
      }).toThrow();
    });
  });
});
