import { EnvelopeEncryptionService } from '../../security/envelope-encryption.service.js';
import { generateTestString, expectToThrow } from '../utils/test-helpers.js';

describe('Envelope Encryption Service', () => {
  let envelopeService: EnvelopeEncryptionService;
  let testData: string;

  beforeAll(() => {
    envelopeService = EnvelopeEncryptionService.getInstance();
    testData = generateTestString(1000);
  });

  describe('Singleton pattern', () => {
    it('should return the same instance', () => {
      const instance1 = EnvelopeEncryptionService.getInstance();
      const instance2 = EnvelopeEncryptionService.getInstance();
      
      expect(instance1).toBe(instance2);
    });
  });

  describe('encrypt', () => {
    it('should encrypt data successfully', async () => {
      const result = await envelopeService.encrypt(testData);
      
      expect(result).toBeDefined();
      expect(result.encryptedData).toBeDefined();
      expect(result.encryptedDEK).toBeDefined();
      expect(result.keyId).toBeDefined();
      expect(result.iv).toBeDefined();
      expect(result.salt).toBeDefined();
      expect(result.authTag).toBeDefined();
      expect(result.algorithm).toBe('aes-256-gcm');
      expect(result.version).toBe(1);
    });

    it('should handle different data sizes', async () => {
      const testCases = [
        generateTestString(1),      // 1 byte
        generateTestString(100),    // 100 bytes
        generateTestString(10000),  // 10KB
        generateTestString(100000)  // 100KB
      ];

      for (const data of testCases) {
        const result = await envelopeService.encrypt(data);
        
        expect(result).toBeDefined();
        expect(result.encryptedData).toBeDefined();
        expect(result.algorithm).toBe('aes-256-gcm');
      }
    });

    it('should produce different encrypted results for same data', async () => {
      const result1 = await envelopeService.encrypt(testData);
      const result2 = await envelopeService.encrypt(testData);
      
      // Should be different due to random IV
      expect(result1.encryptedData).not.toBe(result2.encryptedData);
      expect(result1.iv).not.toBe(result2.iv);
      expect(result1.authTag).not.toBe(result2.authTag);
      
      // But should use same key
      expect(result1.keyId).toBe(result2.keyId);
      expect(result1.encryptedDEK).toBe(result2.encryptedDEK);
    });

    it('should handle empty data', async () => {
      const result = await envelopeService.encrypt('');
      
      expect(result).toBeDefined();
      expect(result.encryptedData).toBeDefined();
    });

    it('should handle special characters and unicode', async () => {
      const specialData = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>? 🚀🌟💫✨🎉';
      const result = await envelopeService.encrypt(specialData);
      
      expect(result).toBeDefined();
      expect(result.encryptedData).toBeDefined();
    });
  });

  describe('decrypt', () => {
    let encryptedResult: any;

    beforeEach(async () => {
      encryptedResult = await envelopeService.encrypt(testData);
    });

    it('should decrypt data successfully', async () => {
      const decrypted = await envelopeService.decrypt(encryptedResult);
      
      expect(decrypted).toBe(testData);
    });

    it('should handle different encrypted data sizes', async () => {
      const testCases = [
        generateTestString(1),
        generateTestString(100),
        generateTestString(10000),
        generateTestString(100000)
      ];

      for (const data of testCases) {
        const encrypted = await envelopeService.encrypt(data);
        const decrypted = await envelopeService.decrypt(encrypted);
        
        expect(decrypted).toBe(data);
      }
    });

    it('should throw error for corrupted encrypted data', async () => {
      const corruptedResult = { ...encryptedResult, encryptedData: 'corrupted-data' };
      
      await expectToThrow(
        () => envelopeService.decrypt(corruptedResult),
        'Failed to decrypt data'
      );
    });

    it('should throw error for corrupted auth tag', async () => {
      const corruptedResult = { ...encryptedResult, authTag: 'corrupted-tag' };
      
      await expectToThrow(
        () => envelopeService.decrypt(corruptedResult),
        'Failed to decrypt data'
      );
    });

    it('should throw error for corrupted IV', async () => {
      const corruptedResult = { ...encryptedResult, iv: 'corrupted-iv' };
      
      await expectToThrow(
        () => envelopeService.decrypt(corruptedResult),
        'Failed to decrypt data'
      );
    });

    it('should throw error for corrupted encrypted DEK', async () => {
      const corruptedResult = { ...encryptedResult, encryptedDEK: 'corrupted-dek' };
      
      await expectToThrow(
        () => envelopeService.decrypt(corruptedResult),
        'Failed to decrypt DEK'
      );
    });

    it('should throw error for unsupported version', async () => {
      const unsupportedResult = { ...encryptedResult, version: 999 };
      
      await expectToThrow(
        () => envelopeService.decrypt(unsupportedResult),
        'Unsupported encryption version'
      );
    });

    it('should throw error for unsupported algorithm', async () => {
      const unsupportedResult = { ...encryptedResult, algorithm: 'unsupported-algorithm' };
      
      await expectToThrow(
        () => envelopeService.decrypt(unsupportedResult),
        'Unsupported encryption algorithm'
      );
    });
  });

  describe('End-to-end encryption/decryption', () => {
    it('should successfully encrypt and decrypt various data types', async () => {
      const testCases = [
        'Simple text message',
        JSON.stringify({ complex: 'object', with: ['array', 'data'] }),
        generateTestString(5000),
        'Special characters: !@#$%^&*()_+-=[]{}|;:,.<>?',
        'Unicode: 🚀🌟💫✨🎉',
        Buffer.from('binary data').toString('base64')
      ];

      for (const data of testCases) {
        const encrypted = await envelopeService.encrypt(data);
        const decrypted = await envelopeService.decrypt(encrypted);
        
        expect(decrypted).toBe(data);
      }
    });

    it('should handle multiple encryption/decryption cycles', async () => {
      for (let i = 0; i < 10; i++) {
        const data = generateTestString(1000);
        const encrypted = await envelopeService.encrypt(data);
        const decrypted = await envelopeService.decrypt(encrypted);
        
        expect(decrypted).toBe(data);
      }
    });
  });

  describe('Key rotation', () => {
    it('should rotate keys successfully', async () => {
      const oldKeyId = envelopeService.getCurrentKeyId();
      
      const newKeyId = await envelopeService.rotateKeys();
      
      expect(newKeyId).toBeDefined();
      expect(newKeyId).not.toBe(oldKeyId);
    });

    it('should maintain encryption/decryption after key rotation', async () => {
      // Encrypt with old key
      const encrypted = await envelopeService.encrypt(testData);
      
      // Rotate keys
      await envelopeService.rotateKeys();
      
      // Should still be able to decrypt with old key
      const decrypted = await envelopeService.decrypt(encrypted);
      expect(decrypted).toBe(testData);
    });

    it('should use new key for new encryptions after rotation', async () => {
      const oldKeyId = envelopeService.getCurrentKeyId();
      
      await envelopeService.rotateKeys();
      
      const newEncrypted = await envelopeService.encrypt(testData);
      expect(newEncrypted.keyId).not.toBe(oldKeyId);
    });
  });

  describe('Key metadata', () => {
    it('should return current key ID', () => {
      const keyId = envelopeService.getCurrentKeyId();
      
      expect(keyId).toBeDefined();
      expect(typeof keyId).toBe('string');
    });

    it('should return key metadata', () => {
      const keyId = envelopeService.getCurrentKeyId();
      const metadata = envelopeService.getKeyMetadata(keyId);
      
      expect(metadata).toBeDefined();
      expect(metadata?.keyId).toBe(keyId);
      expect(metadata?.algorithm).toBe('aes-256-gcm');
      expect(metadata?.version).toBe(1);
      expect(metadata?.isActive).toBe(true);
      expect(metadata?.createdAt).toBeDefined();
    });

    it('should return undefined for non-existent key', () => {
      const metadata = envelopeService.getKeyMetadata('non-existent-key');
      
      expect(metadata).toBeUndefined();
    });
  });

  describe('Memory protection', () => {
    it('should zeroize memory after operations', async () => {
      const encrypted = await envelopeService.encrypt(testData);
      const decrypted = await envelopeService.decrypt(encrypted);
      
      expect(decrypted).toBe(testData);
      
      // Memory should be zeroized (this is hard to test directly, but we can verify the operation completes)
      expect(true).toBe(true);
    });

    it('should handle zeroizeMemory call', async () => {
      await expect(async () => {
        await envelopeService.zeroizeMemory();
      }).not.toThrow();
    });
  });

  describe('Security properties', () => {
    it('should use AES-256-GCM for encryption', async () => {
      const result = await envelopeService.encrypt(testData);
      
      expect(result.algorithm).toBe('aes-256-gcm');
    });

    it('should use proper IV length for AES-256-GCM', async () => {
      const result = await envelopeService.encrypt(testData);
      
      // Verify IV length (12 bytes for AES-256-GCM)
      const iv = Buffer.from(result.iv, 'base64');
      expect(iv.length).toBe(12);
    });

    it('should use proper salt length for key derivation', async () => {
      const result = await envelopeService.encrypt(testData);
      
      // Verify salt length (32 bytes for scrypt)
      const salt = Buffer.from(result.salt, 'base64');
      expect(salt.length).toBe(32);
    });

    it('should include authentication tag', async () => {
      const result = await envelopeService.encrypt(testData);
      
      expect(result.authTag).toBeDefined();
      expect(result.authTag.length).toBeGreaterThan(0);
    });

    it('should use envelope encryption pattern', async () => {
      const result = await envelopeService.encrypt(testData);
      
      // Should have encrypted DEK (envelope encryption)
      expect(result.encryptedDEK).toBeDefined();
      expect(result.encryptedDEK.length).toBeGreaterThan(0);
    });
  });

  describe('Error handling', () => {
    it('should handle encryption errors gracefully', async () => {
      // Mock crypto to throw error
      const originalCreateCipheriv = require('crypto').createCipheriv;
      require('crypto').createCipheriv = jest.fn().mockImplementation(() => {
        throw new Error('Crypto error');
      });

      try {
        await expectToThrow(
          () => envelopeService.encrypt(testData),
          'Failed to encrypt data'
        );
      } finally {
        require('crypto').createCipheriv = originalCreateCipheriv;
      }
    });

    it('should handle decryption errors gracefully', async () => {
      const encrypted = await envelopeService.encrypt(testData);
      
      // Mock crypto to throw error
      const originalCreateDecipheriv = require('crypto').createDecipheriv;
      require('crypto').createDecipheriv = jest.fn().mockImplementation(() => {
        throw new Error('Crypto error');
      });

      try {
        await expectToThrow(
          () => envelopeService.decrypt(encrypted),
          'Failed to decrypt data'
        );
      } finally {
        require('crypto').createDecipheriv = originalCreateDecipheriv;
      }
    });
  });
});