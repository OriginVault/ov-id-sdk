import { 
  encryptWithPublicKeyAESRSA, 
  decryptWithPrivateKeyAESRSA, 
  isAESRSAEncryptedMessage,
  AESRSAEncryptedMessage 
} from '../../aesRsaEncryption.js';
import { createMockCredentials, expectToThrow, generateTestString } from '../utils/test-helpers.js';
import crypto from 'crypto';

describe('AES-RSA Encryption', () => {
  let mockCredentials: any;
  let testMessage: string;
  let publicKeyPem: string;
  let privateKeyPem: string;

  beforeAll(() => {
    mockCredentials = createMockCredentials();
    testMessage = generateTestString(100);
    
    // Generate RSA key pair for testing
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
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
    
    publicKeyPem = publicKey;
    privateKeyPem = privateKey;
  });

  describe('encryptWithPublicKeyAESRSA', () => {
    it('should encrypt a message successfully', async () => {
      const result = await encryptWithPublicKeyAESRSA(testMessage, publicKeyPem);
      
      expect(result).toBeDefined();
      expect(result.algorithm).toBe('aes-rsa');
      expect(result.encryptedData).toBeDefined();
      expect(result.encryptedKey).toBeDefined();
      expect(result.iv).toBeDefined();
      expect(typeof result.encryptedData).toBe('string');
      expect(typeof result.encryptedKey).toBe('string');
      expect(typeof result.iv).toBe('string');
    });

    it('should handle large messages', async () => {
      const largeMessage = generateTestString(10000);
      const result = await encryptWithPublicKeyAESRSA(largeMessage, publicKeyPem);
      
      expect(result).toBeDefined();
      expect(result.algorithm).toBe('aes-rsa');
    });

    it('should throw error for invalid message', async () => {
      await expectToThrow(
        () => encryptWithPublicKeyAESRSA('', publicKeyPem),
        'Invalid message: must be a non-empty string'
      );
    });

    it('should throw error for invalid public key', async () => {
      await expectToThrow(
        () => encryptWithPublicKeyAESRSA(testMessage, 'invalid-key'),
        'Invalid public key format: must be in PEM format'
      );
    });

    it('should handle public key with literal \\n characters', async () => {
      const keyWithLiteralNewlines = publicKeyPem.replace(/\n/g, '\\n');
      const result = await encryptWithPublicKeyAESRSA(testMessage, keyWithLiteralNewlines);
      
      expect(result).toBeDefined();
      expect(result.algorithm).toBe('aes-rsa');
    });
  });

  describe('decryptWithPrivateKeyAESRSA', () => {
    let encryptedMessage: AESRSAEncryptedMessage;

    beforeEach(async () => {
      encryptedMessage = await encryptWithPublicKeyAESRSA(testMessage, publicKeyPem);
    });

    it('should decrypt a message successfully', async () => {
      const decrypted = await decryptWithPrivateKeyAESRSA(encryptedMessage, privateKeyPem);
      
      expect(decrypted).toBe(testMessage);
    });

    it('should handle private key with literal \\n characters', async () => {
      const keyWithLiteralNewlines = privateKeyPem.replace(/\n/g, '\\n');
      const decrypted = await decryptWithPrivateKeyAESRSA(encryptedMessage, keyWithLiteralNewlines);
      
      expect(decrypted).toBe(testMessage);
    });

    it('should throw error for unsupported algorithm', async () => {
      const invalidMessage = { ...encryptedMessage, algorithm: 'unsupported' };
      
      await expectToThrow(
        () => decryptWithPrivateKeyAESRSA(invalidMessage, privateKeyPem),
        'Unsupported algorithm: unsupported'
      );
    });

    it('should throw error for invalid private key', async () => {
      await expectToThrow(
        () => decryptWithPrivateKeyAESRSA(encryptedMessage, 'invalid-key'),
        'Invalid private key format: must be in PEM format'
      );
    });

    it('should throw error for corrupted encrypted data', async () => {
      const corruptedMessage = { ...encryptedMessage, encryptedData: 'corrupted-data' };
      
      await expectToThrow(
        () => decryptWithPrivateKeyAESRSA(corruptedMessage, privateKeyPem),
        'AES-RSA decryption failed'
      );
    });
  });

  describe('isAESRSAEncryptedMessage', () => {
    let validMessage: AESRSAEncryptedMessage;

    beforeEach(async () => {
      validMessage = await encryptWithPublicKeyAESRSA(testMessage, publicKeyPem);
    });

    it('should return true for valid AES-RSA message', () => {
      expect(isAESRSAEncryptedMessage(validMessage)).toBe(true);
    });

    it('should return false for invalid message structure', () => {
      expect(isAESRSAEncryptedMessage({})).toBe(false);
      expect(isAESRSAEncryptedMessage(null)).toBe(false);
      expect(isAESRSAEncryptedMessage(undefined)).toBe(false);
    });

    it('should return false for message with wrong algorithm', () => {
      const invalidMessage = { ...validMessage, algorithm: 'wrong-algorithm' };
      expect(isAESRSAEncryptedMessage(invalidMessage)).toBe(false);
    });

    it('should return false for message with missing fields', () => {
      const { encryptedData, ...incompleteMessage } = validMessage;
      expect(isAESRSAEncryptedMessage(incompleteMessage)).toBe(false);
    });
  });

  describe('End-to-end encryption/decryption', () => {
    it('should successfully encrypt and decrypt various message types', async () => {
      const testCases = [
        'Simple text message',
        JSON.stringify({ complex: 'object', with: ['array', 'data'] }),
        generateTestString(5000),
        'Special characters: !@#$%^&*()_+-=[]{}|;:,.<>?',
        'Unicode: 🚀🌟💫✨🎉'
      ];

      for (const message of testCases) {
        const encrypted = await encryptWithPublicKeyAESRSA(message, publicKeyPem);
        const decrypted = await decryptWithPrivateKeyAESRSA(encrypted, privateKeyPem);
        
        expect(decrypted).toBe(message);
      }
    });

    it('should produce different encrypted results for same message', async () => {
      const encrypted1 = await encryptWithPublicKeyAESRSA(testMessage, publicKeyPem);
      const encrypted2 = await encryptWithPublicKeyAESRSA(testMessage, publicKeyPem);
      
      // Should be different due to random IV and AES key
      expect(encrypted1.encryptedData).not.toBe(encrypted2.encryptedData);
      expect(encrypted1.encryptedKey).not.toBe(encrypted2.encryptedKey);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      
      // But both should decrypt to the same message
      const decrypted1 = await decryptWithPrivateKeyAESRSA(encrypted1, privateKeyPem);
      const decrypted2 = await decryptWithPrivateKeyAESRSA(encrypted2, privateKeyPem);
      
      expect(decrypted1).toBe(testMessage);
      expect(decrypted2).toBe(testMessage);
    });
  });

  describe('Security properties', () => {
    it('should use AES-256-CBC for data encryption', async () => {
      const encrypted = await encryptWithPublicKeyAESRSA(testMessage, publicKeyPem);
      
      // Verify IV length (16 bytes for AES-256-CBC)
      const iv = Buffer.from(encrypted.iv, 'base64');
      expect(iv.length).toBe(16);
    });

    it('should use RSA-OAEP for key encryption', async () => {
      const encrypted = await encryptWithPublicKeyAESRSA(testMessage, publicKeyPem);
      
      // Verify encrypted key length (should be 256 bytes for 2048-bit RSA)
      const encryptedKey = Buffer.from(encrypted.encryptedKey, 'base64');
      expect(encryptedKey.length).toBe(256);
    });

    it('should handle key format validation', async () => {
      const invalidKeys = [
        'not-a-key',
        '-----BEGIN INVALID KEY-----',
        '',
        null,
        undefined
      ];

      for (const invalidKey of invalidKeys) {
        await expectToThrow(
          () => encryptWithPublicKeyAESRSA(testMessage, invalidKey as any),
          'Invalid public key'
        );
      }
    });
  });
});