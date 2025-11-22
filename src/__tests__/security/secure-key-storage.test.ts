import { SecureKeyStorage } from '../../security/secure-key-storage.js';
import { createTestEnvironment, generateTestString, expectToThrow } from '../utils/test-helpers.js';
import fs from 'fs';
import path from 'path';
import os from 'os';

describe('Secure Key Storage', () => {
  let secureStorage: SecureKeyStorage;
  let testEnvironment: any;
  let testPassword: string;
  let testDID: string;
  let testPrivateKey: string;
  let testPublicKey: string;
  let tempDir: string;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    testPassword = generateTestString(16);
    testDID = testEnvironment.testDID;
    testPrivateKey = testEnvironment.testPrivateKey;
    testPublicKey = testEnvironment.testPublicKey;
    
    // Create temporary directory for testing
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-storage-test-'));
    
    // Mock the keystore path to use temp directory
    jest.spyOn(SecureKeyStorage.prototype as any, 'getKeystorePath').mockReturnValue(
      path.join(tempDir, '.secure-keystore.json')
    );
    
    secureStorage = SecureKeyStorage.getInstance();
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
    
    // Clean up temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('storeKey', () => {
    it('should store a key successfully', async () => {
      const keyId = generateTestString(16);
      
      await secureStorage.storeKey(
        keyId,
        testDID,
        testPrivateKey,
        testPublicKey,
        testPassword
      );

      // Verify key was stored by listing keys
      const keys = await secureStorage.listKeys();
      expect(keys.length).toBe(1);
      expect(keys[0].keyId).toBe(keyId);
      expect(keys[0].did).toBe(testDID);
      expect(keys[0].publicKeyHex).toBe(testPublicKey);
      expect(keys[0].isActive).toBe(true);
    });

    it('should handle multiple keys', async () => {
      const keyId1 = generateTestString(16);
      const keyId2 = generateTestString(16);
      const did2 = `did:key:${generateTestString(32)}`;
      const privateKey2 = generateTestString(64);
      const publicKey2 = generateTestString(64);

      await secureStorage.storeKey(keyId1, testDID, testPrivateKey, testPublicKey, testPassword);
      await secureStorage.storeKey(keyId2, did2, privateKey2, publicKey2, testPassword);

      const keys = await secureStorage.listKeys();
      expect(keys.length).toBe(2);
    });

    it('should throw error for empty keyId', async () => {
      await expectToThrow(
        () => secureStorage.storeKey('', testDID, testPrivateKey, testPublicKey, testPassword),
        'Key ID cannot be empty'
      );
    });

    it('should throw error for empty DID', async () => {
      await expectToThrow(
        () => secureStorage.storeKey('test-key', '', testPrivateKey, testPublicKey, testPassword),
        'DID cannot be empty'
      );
    });

    it('should throw error for empty private key', async () => {
      await expectToThrow(
        () => secureStorage.storeKey('test-key', testDID, '', testPublicKey, testPassword),
        'Private key cannot be empty'
      );
    });

    it('should throw error for empty password', async () => {
      await expectToThrow(
        () => secureStorage.storeKey('test-key', testDID, testPrivateKey, testPublicKey, ''),
        'Password cannot be empty'
      );
    });
  });

  describe('retrieveKey', () => {
    let storedKeyId: string;

    beforeEach(async () => {
      storedKeyId = generateTestString(16);
      await secureStorage.storeKey(
        storedKeyId,
        testDID,
        testPrivateKey,
        testPublicKey,
        testPassword
      );
    });

    it('should retrieve a key successfully', async () => {
      const result = await secureStorage.retrieveKey(storedKeyId, testPassword);

      expect(result).toBeDefined();
      expect(result?.privateKeyHex).toBe(testPrivateKey);
      expect(result?.publicKeyHex).toBe(testPublicKey);
    });

    it('should return null for non-existent key', async () => {
      const result = await secureStorage.retrieveKey('non-existent-key', testPassword);

      expect(result).toBeNull();
    });

    it('should return null for wrong password', async () => {
      const result = await secureStorage.retrieveKey(storedKeyId, 'wrong-password');

      expect(result).toBeNull();
    });

    it('should update lastAccessed timestamp', async () => {
      const keysBefore = await secureStorage.listKeys();
      const keyBefore = keysBefore.find(k => k.keyId === storedKeyId);
      const lastAccessedBefore = keyBefore?.lastAccessed;

      await secureStorage.retrieveKey(storedKeyId, testPassword);

      const keysAfter = await secureStorage.listKeys();
      const keyAfter = keysAfter.find(k => k.keyId === storedKeyId);
      const lastAccessedAfter = keyAfter?.lastAccessed;

      expect(lastAccessedAfter).toBeDefined();
      if (lastAccessedBefore && lastAccessedAfter) {
        expect(new Date(lastAccessedAfter).getTime()).toBeGreaterThan(
          new Date(lastAccessedBefore).getTime()
        );
      }
    });
  });

  describe('listKeys', () => {
    beforeEach(async () => {
      // Clear existing keys
      const keys = await secureStorage.listKeys();
      for (const key of keys) {
        await secureStorage.deleteKey(key.keyId);
      }
    });

    it('should return empty array when no keys exist', async () => {
      const keys = await secureStorage.listKeys();
      expect(keys).toEqual([]);
    });

    it('should return all stored keys', async () => {
      const keyId1 = generateTestString(16);
      const keyId2 = generateTestString(16);
      const did2 = `did:key:${generateTestString(32)}`;
      const privateKey2 = generateTestString(64);
      const publicKey2 = generateTestString(64);

      await secureStorage.storeKey(keyId1, testDID, testPrivateKey, testPublicKey, testPassword);
      await secureStorage.storeKey(keyId2, did2, privateKey2, publicKey2, testPassword);

      const keys = await secureStorage.listKeys();
      expect(keys.length).toBe(2);
      
      const keyIds = keys.map(k => k.keyId);
      expect(keyIds).toContain(keyId1);
      expect(keyIds).toContain(keyId2);
    });

    it('should include all required fields', async () => {
      const keyId = generateTestString(16);
      await secureStorage.storeKey(keyId, testDID, testPrivateKey, testPublicKey, testPassword);

      const keys = await secureStorage.listKeys();
      const key = keys.find(k => k.keyId === keyId);

      expect(key).toBeDefined();
      expect(key?.keyId).toBe(keyId);
      expect(key?.did).toBe(testDID);
      expect(key?.publicKeyHex).toBe(testPublicKey);
      expect(key?.createdAt).toBeDefined();
      expect(key?.isActive).toBe(true);
      expect(key?.encryptedPrivateKey).toBeDefined();
    });
  });

  describe('deleteKey', () => {
    let keyToDelete: string;

    beforeEach(async () => {
      keyToDelete = generateTestString(16);
      await secureStorage.storeKey(
        keyToDelete,
        testDID,
        testPrivateKey,
        testPublicKey,
        testPassword
      );
    });

    it('should delete a key successfully', async () => {
      const result = await secureStorage.deleteKey(keyToDelete);

      expect(result).toBe(true);

      const keys = await secureStorage.listKeys();
      const deletedKey = keys.find(k => k.keyId === keyToDelete);
      expect(deletedKey).toBeUndefined();
    });

    it('should return false for non-existent key', async () => {
      const result = await secureStorage.deleteKey('non-existent-key');

      expect(result).toBe(false);
    });

    it('should handle deletion of already deleted key', async () => {
      await secureStorage.deleteKey(keyToDelete);
      const result = await secureStorage.deleteKey(keyToDelete);

      expect(result).toBe(false);
    });
  });

  describe('Security properties', () => {
    it('should encrypt private keys with AES-256-GCM', async () => {
      const keyId = generateTestString(16);
      await secureStorage.storeKey(keyId, testDID, testPrivateKey, testPublicKey, testPassword);

      const keys = await secureStorage.listKeys();
      const key = keys.find(k => k.keyId === keyId);

      expect(key?.encryptedPrivateKey.algorithm).toBe('aes-256-gcm');
      expect(key?.encryptedPrivateKey.encryptedData).toBeDefined();
      expect(key?.encryptedPrivateKey.iv).toBeDefined();
      expect(key?.encryptedPrivateKey.salt).toBeDefined();
      expect(key?.encryptedPrivateKey.authTag).toBeDefined();
    });

    it('should use different salts for different keys', async () => {
      const keyId1 = generateTestString(16);
      const keyId2 = generateTestString(16);
      const did2 = `did:key:${generateTestString(32)}`;
      const privateKey2 = generateTestString(64);
      const publicKey2 = generateTestString(64);

      await secureStorage.storeKey(keyId1, testDID, testPrivateKey, testPublicKey, testPassword);
      await secureStorage.storeKey(keyId2, did2, privateKey2, publicKey2, testPassword);

      const keys = await secureStorage.listKeys();
      const key1 = keys.find(k => k.keyId === keyId1);
      const key2 = keys.find(k => k.keyId === keyId2);

      expect(key1?.encryptedPrivateKey.salt).not.toBe(key2?.encryptedPrivateKey.salt);
    });

    it('should not store private keys in plain text', async () => {
      const keyId = generateTestString(16);
      await secureStorage.storeKey(keyId, testDID, testPrivateKey, testPublicKey, testPassword);

      // Read the keystore file directly
      const keystorePath = (secureStorage as any).getKeystorePath();
      const keystoreContent = fs.readFileSync(keystorePath, 'utf8');
      const keystore = JSON.parse(keystoreContent);

      const storedKey = keystore.keys.find((k: any) => k.keyId === keyId);
      expect(storedKey.encryptedPrivateKey.encryptedData).not.toBe(testPrivateKey);
    });

    it('should handle key rotation', async () => {
      const keyId = generateTestString(16);
      
      // Store initial key
      await secureStorage.storeKey(keyId, testDID, testPrivateKey, testPublicKey, testPassword);
      
      // Rotate to new private key
      const newPrivateKey = generateTestString(64);
      const newPublicKey = generateTestString(64);
      
      await secureStorage.storeKey(keyId, testDID, newPrivateKey, newPublicKey, testPassword);

      const result = await secureStorage.retrieveKey(keyId, testPassword);
      expect(result?.privateKeyHex).toBe(newPrivateKey);
      expect(result?.publicKeyHex).toBe(newPublicKey);
    });
  });

  describe('Error handling', () => {
    it('should handle file system errors gracefully', async () => {
      // Mock fs.writeFileSync to throw error
      const originalWriteFileSync = fs.writeFileSync;
      fs.writeFileSync = jest.fn().mockImplementation(() => {
        throw new Error('File system error');
      });

      try {
        await expectToThrow(
          () => secureStorage.storeKey('test-key', testDID, testPrivateKey, testPublicKey, testPassword),
          'Failed to write keystore'
        );
      } finally {
        fs.writeFileSync = originalWriteFileSync;
      }
    });

    it('should handle corrupted keystore file', async () => {
      const keystorePath = (secureStorage as any).getKeystorePath();
      
      // Write corrupted JSON
      fs.writeFileSync(keystorePath, 'corrupted json content');

      await expectToThrow(
        () => secureStorage.listKeys(),
        'Failed to load keystore'
      );
    });

    it('should handle missing keystore file', async () => {
      const keystorePath = (secureStorage as any).getKeystorePath();
      
      // Remove keystore file
      if (fs.existsSync(keystorePath)) {
        fs.unlinkSync(keystorePath);
      }

      const keys = await secureStorage.listKeys();
      expect(keys).toEqual([]);
    });
  });

  describe('Backup and recovery', () => {
    it('should create backup files', async () => {
      const keyId = generateTestString(16);
      await secureStorage.storeKey(keyId, testDID, testPrivateKey, testPublicKey, testPassword);

      const backupPath = (secureStorage as any).getBackupPath();
      expect(fs.existsSync(backupPath)).toBe(true);
    });

    it('should handle backup creation errors', async () => {
      // Mock backup creation to fail
      const originalCreateBackup = (secureStorage as any).createBackup;
      (secureStorage as any).createBackup = jest.fn().mockRejectedValue(new Error('Backup failed'));

      const keyId = generateTestString(16);
      
      // Should not throw error even if backup fails
      await expect(async () => {
        await secureStorage.storeKey(keyId, testDID, testPrivateKey, testPublicKey, testPassword);
      }).not.toThrow();

      // Restore original method
      (secureStorage as any).createBackup = originalCreateBackup;
    });
  });
});