import { EnvelopeEncryptionService } from '../../security/envelope-encryption.service.js';
import { MemoryProtectionService } from '../../security/memory-protection.service.js';
import { SecurityBridgeService } from '../../shared/security-bridge.service.js';
import { KeyRotationService } from '../../security/key-rotation.service.js';
import * as ed25519 from '@noble/ed25519';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

// Mock the secure key storage to avoid circular dependencies
jest.mock('../../security/secure-key-storage.js', () => ({
  SecureKeyStorage: {
    getInstance: jest.fn().mockReturnValue({
      storeKey: jest.fn().mockResolvedValue(undefined),
      retrieveKey: jest.fn().mockImplementation(async (keyId: string, password: string) => {
        if (password === 'wrong-password') {
          return null;
        }
        return {
          privateKeyHex: 'a'.repeat(64),
          publicKeyHex: 'b'.repeat(64)
        };
      }),
      listKeys: jest.fn().mockResolvedValue([
        { keyId: 'test-key-1', did: 'did:test:123', isActive: true },
        { keyId: 'test-key-2', did: 'did:test:456', isActive: true }
      ]),
      deleteKey: jest.fn().mockResolvedValue(true)
    })
  }
}));

describe('Security Integration Tests', () => {
  let envelopeService: EnvelopeEncryptionService;
  let memoryService: MemoryProtectionService;
  let securityBridge: SecurityBridgeService;
  let keyRotationService: KeyRotationService;

  beforeEach(() => {
    envelopeService = EnvelopeEncryptionService.getInstance();
    memoryService = MemoryProtectionService.getInstance();
    securityBridge = SecurityBridgeService.getInstance({
      cheqdStudioEndpoint: 'https://test-studio.com',
      sharedSecretKey: 'test-secret',
      enableCrossRepoSync: false // Disable for testing
    });
    keyRotationService = KeyRotationService.getInstance();
    jest.clearAllMocks();
  });

  describe('End-to-End Security Workflow', () => {
    test('should handle complete secure message workflow', async () => {
      // Step 1: Prepare message data
      const messageData = {
        id: uuidv4(),
        type: 'secure-message',
        content: 'This is a secure message',
        timestamp: new Date().toISOString(),
        metadata: {
          priority: 'high',
          category: 'confidential'
        }
      };

      // Step 2: Encrypt message content
      const encryptedContent = await envelopeService.encrypt(JSON.stringify(messageData));
      expect(encryptedContent).toBeDefined();
      expect(encryptedContent.encryptedData).toBeDefined();

      // Step 3: Register sensitive data for memory protection
      const sensitiveBuffer = Buffer.from(encryptedContent.encryptedData, 'hex');
      memoryService.registerSensitiveBuffer(sensitiveBuffer);

      // Step 4: Create secure message structure
      const secureMessage = {
        id: messageData.id,
        type: messageData.type,
        from: 'did:test:sender',
        to: 'did:test:recipient',
        body: {
          encrypted: true,
          data: encryptedContent
        },
        signature: {
          message: 'signature-payload',
          signature: 'mock-signature',
          signer: 'did:test:sender',
          timestamp: messageData.timestamp,
          messageId: messageData.id,
          nonce: crypto.randomBytes(16).toString('hex'),
          keyId: 'test-key-id',
          algorithm: 'Ed25519',
          version: 1
        },
        encrypted: true,
        timestamp: messageData.timestamp
      };

      // Step 5: Verify message structure
      expect(secureMessage.id).toBe(messageData.id);
      expect(secureMessage.body.encrypted).toBe(true);
      expect(secureMessage.signature.algorithm).toBe('Ed25519');

      // Step 6: Decrypt message content
      const decryptedContent = await envelopeService.decrypt(secureMessage.body.data);
      const parsedContent = JSON.parse(decryptedContent);
      expect(parsedContent.content).toBe(messageData.content);

      // Step 7: Clean up sensitive memory
      memoryService.performCleanup();
      expect(sensitiveBuffer.toString()).toBe('\x00'.repeat(sensitiveBuffer.length));
    });

    test('should handle key rotation workflow', async () => {
      const did = 'did:test:rotation';
      const password = 'test-password';

      // Step 1: Create rotation plan
      const plan = await keyRotationService.createRotationPlan(did);
      expect(plan).toBeDefined();
      expect(plan.did).toBe(did);
      expect(plan.rotationType).toBe('manual');

      // Step 2: Execute key rotation
      const result = await keyRotationService.executeKeyRotation(plan, password);
      expect(result).toBeDefined();
      expect(result.rotationId).toBe(plan.rotationId);
      expect(result.success).toBe(true);

      // Step 3: Verify rotation completed
      expect(result.rotatedKeys.length).toBeGreaterThan(0);
      expect(result.failedKeys.length).toBe(0);
      expect(result.duration).toBeGreaterThan(0);
    });

    test('should handle security bridge integration', async () => {
      const testData = 'Data for cheqd-studio integration';
      
      // Step 1: Encrypt data through security bridge
      const encrypted = await securityBridge.encryptForCheqdStudio(testData);
      expect(encrypted).toBeDefined();

      // Step 2: Decrypt data through security bridge
      const decrypted = await securityBridge.decryptFromCheqdStudio(encrypted);
      expect(decrypted).toBe(testData);

      // Step 3: Test key sync operation (should not throw when disabled)
      await expect(securityBridge.syncKeyWithCheqdStudio({
        operation: 'create',
        keyId: 'test-key',
        did: 'did:test:123',
        customerId: 'customer-456',
        metadata: {}
      })).resolves.not.toThrow();

      // Step 4: Test key rotation coordination
      await expect(securityBridge.coordinateKeyRotation('did:test:123', 'customer-456'))
        .resolves.not.toThrow();
    });
  });

  describe('Cross-Service Security Operations', () => {
    test('should handle encryption with memory protection', async () => {
      const sensitiveData = 'Highly sensitive information';
      
      // Encrypt data
      const encrypted = await envelopeService.encrypt(sensitiveData);
      
      // Register encrypted data for memory protection
      const encryptedBuffer = Buffer.from(encrypted.encryptedData, 'hex');
      memoryService.registerSensitiveBuffer(encryptedBuffer);
      
      // Verify data can be decrypted
      const decrypted = await envelopeService.decrypt(encrypted);
      expect(decrypted).toBe(sensitiveData);
      
      // Clean up memory
      memoryService.performCleanup();
      
      // Verify buffer was zeroized
      expect(encryptedBuffer.toString()).toBe('\x00'.repeat(encryptedBuffer.length));
    });

    test('should handle key rotation with encryption continuity', async () => {
      const testData = 'Data that survives key rotation';
      
      // Encrypt with current key
      const encrypted1 = await envelopeService.encrypt(testData);
      const oldKeyId = encrypted1.keyId;
      
      // Rotate keys
      const rotatedKeyId = await envelopeService.rotateKeys();
      expect(rotatedKeyId).toBe(oldKeyId);
      
      // Encrypt with new key
      const encrypted2 = await envelopeService.encrypt(testData);
      expect(encrypted2.keyId).not.toBe(oldKeyId);
      
      // Both should be decryptable
      const decrypted1 = await envelopeService.decrypt(encrypted1);
      const decrypted2 = await envelopeService.decrypt(encrypted2);
      
      expect(decrypted1).toBe(testData);
      expect(decrypted2).toBe(testData);
    });

    test('should handle concurrent security operations', async () => {
      const operations = [];
      
      // Create multiple concurrent operations
      for (let i = 0; i < 5; i++) {
        operations.push(
          envelopeService.encrypt(`Concurrent data ${i}`)
        );
      }
      
      // Add memory protection operations
      for (let i = 0; i < 3; i++) {
        const buffer = Buffer.from(`Sensitive buffer ${i}`, 'utf8');
        memoryService.registerSensitiveBuffer(buffer);
        operations.push(Promise.resolve(buffer));
      }
      
      // Execute all operations
      const results = await Promise.all(operations);
      
      // Verify encryption results
      const encryptionResults = results.slice(0, 5);
      encryptionResults.forEach((result, index) => {
        expect(result.encryptedData).toBeDefined();
        expect(result.keyId).toBeDefined();
      });
      
      // Verify memory protection
      const buffers = results.slice(5);
      buffers.forEach(buffer => {
        expect(buffer.toString()).not.toBe('\x00'.repeat(buffer.length));
      });
      
      // Clean up
      memoryService.performCleanup();
      
      // Verify buffers were zeroized
      buffers.forEach(buffer => {
        expect(buffer.toString()).toBe('\x00'.repeat(buffer.length));
      });
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should handle encryption failures gracefully', async () => {
      // Test with invalid data
      const invalidData = null as any;
      
      try {
        await envelopeService.encrypt(invalidData);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    test('should handle decryption failures gracefully', async () => {
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
      
      try {
        await envelopeService.decrypt(invalidEncrypted);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    test('should handle memory protection errors gracefully', () => {
      // Test with invalid buffer
      const invalidBuffer = null as any;
      
      expect(() => memoryService.registerSensitiveBuffer(invalidBuffer)).not.toThrow();
      expect(() => memoryService.zeroizeBuffer(invalidBuffer)).not.toThrow();
    });

    test('should handle key rotation failures gracefully', async () => {
      const invalidDid = 'invalid-did';
      
      try {
        const plan = await keyRotationService.createRotationPlan(invalidDid);
        const result = await keyRotationService.executeKeyRotation(plan, 'password');
        
        // Should handle gracefully even with invalid DID
        expect(result).toBeDefined();
        expect(result.success).toBe(false);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle large-scale encryption operations', async () => {
      const largeData = 'x'.repeat(10000); // 10KB of data
      const iterations = 50;
      
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = await envelopeService.encrypt(`${largeData}-${i}`);
        const decrypted = await envelopeService.decrypt(encrypted);
        expect(decrypted).toBe(`${largeData}-${i}`);
      }
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const avgTime = totalTime / iterations;
      
      // Should handle large data efficiently
      expect(avgTime).toBeLessThan(50); // Less than 50ms per operation
      
      console.log(`Large data encryption: ${avgTime.toFixed(2)}ms per operation`);
    });

    test('should handle memory cleanup at scale', () => {
      const bufferCount = 1000;
      const buffers: Buffer[] = [];
      
      // Create many buffers
      for (let i = 0; i < bufferCount; i++) {
        const buffer = Buffer.from(`Large buffer ${i}`, 'utf8');
        buffers.push(buffer);
        memoryService.registerSensitiveBuffer(buffer);
      }
      
      const startTime = Date.now();
      memoryService.performCleanup();
      const endTime = Date.now();
      
      const cleanupTime = endTime - startTime;
      
      // Should clean up efficiently
      expect(cleanupTime).toBeLessThan(200); // Less than 200ms for 1000 buffers
      
      console.log(`Memory cleanup for ${bufferCount} buffers: ${cleanupTime}ms`);
    });

    test('should maintain performance under concurrent load', async () => {
      const concurrentOperations = 20;
      const operationsPerThread = 10;
      
      const startTime = Date.now();
      
      const promises = [];
      for (let i = 0; i < concurrentOperations; i++) {
        const threadPromises = [];
        for (let j = 0; j < operationsPerThread; j++) {
          threadPromises.push(envelopeService.encrypt(`Thread ${i} Operation ${j}`));
        }
        promises.push(Promise.all(threadPromises));
      }
      
      const results = await Promise.all(promises);
      const endTime = Date.now();
      
      const totalTime = endTime - startTime;
      const totalOperations = concurrentOperations * operationsPerThread;
      const avgTime = totalTime / totalOperations;
      
      // Should maintain good performance under load
      expect(avgTime).toBeLessThan(30); // Less than 30ms per operation
      
      console.log(`Concurrent load test: ${avgTime.toFixed(2)}ms per operation (${totalOperations} total)`);
    });
  });
});
