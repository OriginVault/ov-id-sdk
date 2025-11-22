import {
  encryptPrivateKeySecure,
  decryptPrivateKeySecure,
  decryptPrivateKeyLegacy,
  convertRecoveryToPrivateKey,
  convertPrivateKeyToRecovery,
  convertHexKeyToRecovery,
  encryptDataForDID
} from '../../encryption.js';
import { createTestEnvironment, generateTestString, expectToThrow } from '../utils/test-helpers.js';

describe('Encryption Module', () => {
  let testEnvironment: any;
  let testPassword: string;
  let testPrivateKey: string;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    testPassword = generateTestString(16);
    testPrivateKey = generateTestString(64); // 32 bytes in hex
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('encryptPrivateKeySecure', () => {
    it('should encrypt a private key successfully', async () => {
      const result = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      expect(result).toBeDefined();
      expect(result.algorithm).toBe('aes-256-gcm');
      expect(result.encryptedData).toBeDefined();
      expect(result.iv).toBeDefined();
      expect(result.salt).toBeDefined();
      expect(result.authTag).toBeDefined();
      expect(typeof result.encryptedData).toBe('string');
      expect(typeof result.iv).toBe('string');
      expect(typeof result.salt).toBe('string');
      expect(typeof result.authTag).toBe('string');
    });

    it('should produce different results for same input', async () => {
      const result1 = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      const result2 = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      // Should be different due to random salt and IV
      expect(result1.encryptedData).not.toBe(result2.encryptedData);
      expect(result1.iv).not.toBe(result2.iv);
      expect(result1.salt).not.toBe(result2.salt);
      expect(result1.authTag).not.toBe(result2.authTag);
    });

    it('should handle empty private key', async () => {
      await expectToThrow(
        () => encryptPrivateKeySecure('', testPassword),
        'Secure encryption failed'
      );
    });

    it('should handle empty password', async () => {
      await expectToThrow(
        () => encryptPrivateKeySecure(testPrivateKey, ''),
        'Secure encryption failed'
      );
    });
  });

  describe('decryptPrivateKeySecure', () => {
    let encryptedResult: any;

    beforeEach(async () => {
      encryptedResult = await encryptPrivateKeySecure(testPrivateKey, testPassword);
    });

    it('should decrypt a private key successfully', async () => {
      const decrypted = await decryptPrivateKeySecure(encryptedResult, testPassword);
      
      expect(decrypted).toBe(testPrivateKey);
    });

    it('should throw error for wrong password', async () => {
      await expectToThrow(
        () => decryptPrivateKeySecure(encryptedResult, 'wrong-password'),
        'Secure decryption failed'
      );
    });

    it('should throw error for corrupted data', async () => {
      const corruptedResult = { ...encryptedResult, encryptedData: 'corrupted' };
      
      await expectToThrow(
        () => decryptPrivateKeySecure(corruptedResult, testPassword),
        'Secure decryption failed'
      );
    });

    it('should throw error for corrupted auth tag', async () => {
      const corruptedResult = { ...encryptedResult, authTag: 'corrupted' };
      
      await expectToThrow(
        () => decryptPrivateKeySecure(corruptedResult, testPassword),
        'Secure decryption failed'
      );
    });
  });

  describe('decryptPrivateKeyLegacy', () => {
    let secureEncryptedResult: any;
    let legacyEncryptedResult: any;

    beforeEach(async () => {
      secureEncryptedResult = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      // Create legacy format (simplified for testing)
      legacyEncryptedResult = {
        iv: 'test-iv',
        encrypted: 'test-encrypted'
      };
    });

    it('should decrypt secure format successfully', async () => {
      const decrypted = await decryptPrivateKeyLegacy(secureEncryptedResult, testPassword);
      
      expect(decrypted).toBe(testPrivateKey);
    });

    it('should handle legacy format with warning', async () => {
      // Mock console.warn to capture the warning
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      try {
        await decryptPrivateKeyLegacy(legacyEncryptedResult, testPassword);
        expect(consoleSpy).toHaveBeenCalledWith(
          expect.stringContaining('Using deprecated encryption format')
        );
      } finally {
        consoleSpy.mockRestore();
      }
    });

    it('should return null for invalid legacy data', async () => {
      const result = await decryptPrivateKeyLegacy(legacyEncryptedResult, 'wrong-password');
      
      expect(result).toBeNull();
    });
  });

  describe('convertRecoveryToPrivateKey', () => {
    it('should convert mnemonic to private key', async () => {
      const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
      const privateKey = await convertRecoveryToPrivateKey(mnemonic);
      
      expect(privateKey).toBeDefined();
      expect(typeof privateKey).toBe('string');
    });

    it('should throw error for invalid mnemonic', async () => {
      await expectToThrow(
        () => convertRecoveryToPrivateKey('invalid mnemonic'),
        'Error converting recovery phrase'
      );
    });

    it('should throw error for empty mnemonic', async () => {
      await expectToThrow(
        () => convertRecoveryToPrivateKey(''),
        'Error converting recovery phrase'
      );
    });
  });

  describe('convertPrivateKeyToRecovery', () => {
    it('should convert private key to mnemonic', async () => {
      const privateKey = 'test-private-key-base64';
      const mnemonic = await convertPrivateKeyToRecovery(privateKey);
      
      expect(mnemonic).toBeDefined();
      expect(typeof mnemonic).toBe('string');
      expect(mnemonic.split(' ').length).toBeGreaterThan(10); // Valid mnemonic should have 12+ words
    });

    it('should handle 64-byte private key', async () => {
      const privateKey64 = Buffer.alloc(64, 'a').toString('base64');
      const mnemonic = await convertPrivateKeyToRecovery(privateKey64);
      
      expect(mnemonic).toBeDefined();
      expect(typeof mnemonic).toBe('string');
    });

    it('should handle 32-byte private key', async () => {
      const privateKey32 = Buffer.alloc(32, 'b').toString('base64');
      const mnemonic = await convertPrivateKeyToRecovery(privateKey32);
      
      expect(mnemonic).toBeDefined();
      expect(typeof mnemonic).toBe('string');
    });

    it('should throw error for invalid private key length', async () => {
      const invalidKey = Buffer.alloc(16, 'c').toString('base64'); // 16 bytes
      
      await expectToThrow(
        () => convertPrivateKeyToRecovery(invalidKey),
        'Invalid private key length'
      );
    });

    it('should throw error for invalid base64', async () => {
      await expectToThrow(
        () => convertPrivateKeyToRecovery('invalid-base64!'),
        'Error converting private key to recovery phrase'
      );
    });
  });

  describe('convertHexKeyToRecovery', () => {
    it('should convert hex key to mnemonic', async () => {
      const hexKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      const mnemonic = await convertHexKeyToRecovery(hexKey);
      
      expect(mnemonic).toBeDefined();
      expect(typeof mnemonic).toBe('string');
    });

    it('should throw error for invalid hex', async () => {
      await expectToThrow(
        () => convertHexKeyToRecovery('invalid-hex'),
        'Error converting hex key to recovery phrase'
      );
    });
  });

  describe('encryptDataForDID', () => {
    it('should encrypt data for a DID', async () => {
      const testMessage = 'Test message for encryption';
      const result = await encryptDataForDID(testEnvironment.testDID, testMessage);
      
      expect(result).toBeDefined();
      expect(result?.encryptedMessage).toBeDefined();
      expect(result?.nonce).toBeDefined();
    });

    it('should return null for invalid DID', async () => {
      const result = await encryptDataForDID('invalid-did', 'test message');
      
      expect(result).toBeNull();
    });
  });

  describe('End-to-end encryption/decryption', () => {
    it('should successfully encrypt and decrypt private key', async () => {
      const originalKey = generateTestString(64);
      const password = generateTestString(16);
      
      const encrypted = await encryptPrivateKeySecure(originalKey, password);
      const decrypted = await decryptPrivateKeySecure(encrypted, password);
      
      expect(decrypted).toBe(originalKey);
    });

    it('should handle multiple encryption/decryption cycles', async () => {
      const originalKey = generateTestString(64);
      const password = generateTestString(16);
      
      for (let i = 0; i < 5; i++) {
        const encrypted = await encryptPrivateKeySecure(originalKey, password);
        const decrypted = await decryptPrivateKeySecure(encrypted, password);
        
        expect(decrypted).toBe(originalKey);
      }
    });
  });

  describe('Security properties', () => {
    it('should use AES-256-GCM for encryption', async () => {
      const result = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      expect(result.algorithm).toBe('aes-256-gcm');
    });

    it('should use scrypt for key derivation', async () => {
      const result = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      // Verify salt length (32 bytes for scrypt)
      const salt = Buffer.from(result.salt, 'hex');
      expect(salt.length).toBe(32);
    });

    it('should use proper IV length for AES-256-GCM', async () => {
      const result = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      // Verify IV length (16 bytes for AES-256-GCM)
      const iv = Buffer.from(result.iv, 'hex');
      expect(iv.length).toBe(16);
    });

    it('should include authentication tag', async () => {
      const result = await encryptPrivateKeySecure(testPrivateKey, testPassword);
      
      expect(result.authTag).toBeDefined();
      expect(result.authTag.length).toBeGreaterThan(0);
    });
  });
});