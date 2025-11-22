import { EnvelopeEncryptionService } from '../../security/envelope-encryption.service.js';
import { MemoryProtectionService } from '../../security/memory-protection.service.js';
import { SecurityBridgeService } from '../../shared/security-bridge.service.js';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';
import crypto from 'crypto';

// Configure Ed25519 hash function
ed25519.etc.sha512Sync = sha512;

describe('Standalone Security Tests', () => {
  let envelopeService: EnvelopeEncryptionService;
  let memoryService: MemoryProtectionService;
  let securityBridge: SecurityBridgeService;

  beforeEach(() => {
    envelopeService = EnvelopeEncryptionService.getInstance();
    memoryService = MemoryProtectionService.getInstance();
    securityBridge = SecurityBridgeService.getInstance({
      enableCrossRepoSync: false
    });
  });

  describe('Envelope Encryption', () => {
    test('should encrypt and decrypt data correctly', async () => {
      const testData = 'This is sensitive test data';
      
      const encrypted = await envelopeService.encrypt(testData);
      expect(encrypted).toBeDefined();
      expect(encrypted.encryptedData).toBeDefined();
      expect(encrypted.algorithm).toBe('AES-256-GCM');
      
      const decrypted = await envelopeService.decrypt(encrypted);
      expect(decrypted).toBe(testData);
    });

    test('should handle key rotation', async () => {
      const testData = 'Test data for key rotation';
      
      const encrypted1 = await envelopeService.encrypt(testData);
      const oldKeyId = encrypted1.keyId;
      
      const rotatedKeyId = await envelopeService.rotateKeys();
      expect(rotatedKeyId).toBe(oldKeyId);
      
      const encrypted2 = await envelopeService.encrypt(testData);
      expect(encrypted2.keyId).not.toBe(oldKeyId);
      
      // Both should be decryptable
      const decrypted1 = await envelopeService.decrypt(encrypted1);
      const decrypted2 = await envelopeService.decrypt(encrypted2);
      
      expect(decrypted1).toBe(testData);
      expect(decrypted2).toBe(testData);
    });

    test('should reject tampered data', async () => {
      const testData = 'Test data for tampering detection';
      
      const encrypted = await envelopeService.encrypt(testData);
      
      // Tamper with the encrypted data
      const tampered = { ...encrypted, encryptedData: 'tampered-data' };
      
      await expect(envelopeService.decrypt(tampered)).rejects.toThrow();
    });
  });

  describe('Memory Protection', () => {
    test('should register and zeroize buffers', () => {
      const buffer = Buffer.from('sensitive-data', 'utf8');
      const originalContent = buffer.toString();
      
      memoryService.registerSensitiveBuffer(buffer);
      expect(buffer.toString()).toBe(originalContent);
      
      memoryService.zeroizeBuffer(buffer);
      expect(buffer.toString()).toBe('\x00'.repeat(buffer.length));
    });

    test('should handle multiple buffers', () => {
      const buffers = [
        Buffer.from('data1', 'utf8'),
        Buffer.from('data2', 'utf8'),
        Buffer.from('data3', 'utf8')
      ];
      
      buffers.forEach(buffer => memoryService.registerSensitiveBuffer(buffer));
      
      memoryService.performCleanup();
      
      buffers.forEach(buffer => {
        expect(buffer.toString()).toBe('\x00'.repeat(buffer.length));
      });
    });

    test('should handle null buffers gracefully', () => {
      const nullBuffer = null as any;
      
      expect(() => memoryService.registerSensitiveBuffer(nullBuffer)).not.toThrow();
      expect(() => memoryService.zeroizeBuffer(nullBuffer)).not.toThrow();
    });
  });

  describe('Ed25519 Signatures', () => {
    test('should sign and verify messages', async () => {
      const privateKey = ed25519.utils.randomPrivateKey();
      const publicKey = await ed25519.getPublicKey(privateKey);
      
      const message = 'Test message for signing';
      const messageBytes = Buffer.from(message, 'utf8');
      
      const signature = await ed25519.sign(messageBytes, privateKey);
      const isValid = await ed25519.verify(signature, messageBytes, publicKey);
      
      expect(isValid).toBe(true);
    });

    test('should reject invalid signatures', async () => {
      const privateKey1 = ed25519.utils.randomPrivateKey();
      const privateKey2 = ed25519.utils.randomPrivateKey();
      const publicKey1 = await ed25519.getPublicKey(privateKey1);
      const publicKey2 = await ed25519.getPublicKey(privateKey2);
      
      const message = 'Test message';
      const messageBytes = Buffer.from(message, 'utf8');
      
      const signature = await ed25519.sign(messageBytes, privateKey1);
      const isValid = await ed25519.verify(signature, messageBytes, publicKey2);
      
      expect(isValid).toBe(false);
    });
  });

  describe('Security Bridge', () => {
    test('should encrypt and decrypt through bridge', async () => {
      const testData = 'Bridge test data';
      
      const encrypted = await securityBridge.encryptForCheqdStudio(testData);
      expect(encrypted).toBeDefined();
      
      const decrypted = await securityBridge.decryptFromCheqdStudio(encrypted);
      expect(decrypted).toBe(testData);
    });

    test('should handle sync operations when disabled', async () => {
      await expect(securityBridge.syncKeyWithCheqdStudio({
        operation: 'create',
        keyId: 'test-key',
        did: 'did:test:123',
        customerId: 'customer-456',
        metadata: {}
      })).resolves.not.toThrow();
    });
  });

  describe('Performance Tests', () => {
    test('should meet encryption performance requirements', async () => {
      const testData = 'Performance test data';
      const iterations = 50;
      
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = await envelopeService.encrypt(`${testData}-${i}`);
        const decrypted = await envelopeService.decrypt(encrypted);
        expect(decrypted).toBe(`${testData}-${i}`);
      }
      
      const endTime = Date.now();
      const avgTime = (endTime - startTime) / iterations;
      
      // Should be fast (less than 20ms per operation)
      expect(avgTime).toBeLessThan(20);
      
      console.log(`Encryption performance: ${avgTime.toFixed(2)}ms per operation`);
    });

    test('should handle concurrent operations', async () => {
      const concurrentOps = 20;
      const testData = 'Concurrent test data';
      
      const startTime = Date.now();
      
      const promises = [];
      for (let i = 0; i < concurrentOps; i++) {
        promises.push(envelopeService.encrypt(`${testData}-${i}`));
      }
      
      const results = await Promise.all(promises);
      const endTime = Date.now();
      
      expect(results).toHaveLength(concurrentOps);
      
      const avgTime = (endTime - startTime) / concurrentOps;
      expect(avgTime).toBeLessThan(25);
      
      console.log(`Concurrent encryption: ${avgTime.toFixed(2)}ms per operation`);
    });

    test('should handle signature performance', async () => {
      const privateKey = ed25519.utils.randomPrivateKey();
      const publicKey = await ed25519.getPublicKey(privateKey);
      const message = 'Performance test message';
      const messageBytes = Buffer.from(message, 'utf8');
      
      const iterations = 100;
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const signature = await ed25519.sign(messageBytes, privateKey);
        const isValid = await ed25519.verify(signature, messageBytes, publicKey);
        expect(isValid).toBe(true);
      }
      
      const endTime = Date.now();
      const avgTime = (endTime - startTime) / iterations;
      
      // Should be very fast (less than 1ms per operation)
      expect(avgTime).toBeLessThan(1);
      
      console.log(`Signature performance: ${avgTime.toFixed(3)}ms per operation`);
    });
  });

  describe('Integration Tests', () => {
    test('should work together for secure operations', async () => {
      const sensitiveData = 'Integration test data';
      
      // Encrypt data
      const encrypted = await envelopeService.encrypt(sensitiveData);
      
      // Register for memory protection
      const encryptedBuffer = Buffer.from(encrypted.encryptedData, 'hex');
      memoryService.registerSensitiveBuffer(encryptedBuffer);
      
      // Decrypt data
      const decrypted = await envelopeService.decrypt(encrypted);
      expect(decrypted).toBe(sensitiveData);
      
      // Clean up memory
      memoryService.performCleanup();
      expect(encryptedBuffer.toString()).toBe('\x00'.repeat(encryptedBuffer.length));
    });

    test('should handle error scenarios gracefully', async () => {
      // Test invalid encrypted data
      const invalidEncrypted = {
        encryptedData: 'invalid',
        encryptedDEK: 'invalid',
        keyId: 'invalid',
        iv: 'invalid',
        salt: 'invalid',
        authTag: 'invalid',
        algorithm: 'AES-256-GCM',
        version: 1
      };
      
      await expect(envelopeService.decrypt(invalidEncrypted)).rejects.toThrow();
    });
  });
});
