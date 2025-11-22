import { EnvelopeEncryptionService } from '../../security/envelope-encryption.service.js';
import { MemoryProtectionService } from '../../security/memory-protection.service.js';
import { SecurityBridgeService } from '../../shared/security-bridge.service.js';
import * as ed25519 from '@noble/ed25519';
import crypto from 'crypto';

describe('Security Performance Tests', () => {
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

  describe('Encryption Performance', () => {
    test('should meet encryption performance requirements', async () => {
      const testData = 'Performance test data';
      const iterations = 100;
      
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = await envelopeService.encrypt(`${testData}-${i}`);
        const decrypted = await envelopeService.decrypt(encrypted);
        expect(decrypted).toBe(`${testData}-${i}`);
      }
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const avgTime = totalTime / iterations;
      
      // Performance requirement: <20ms per operation
      expect(avgTime).toBeLessThan(20);
      
      console.log(`Encryption Performance: ${avgTime.toFixed(2)}ms per operation`);
    });

    test('should handle different data sizes efficiently', async () => {
      const dataSizes = [
        { size: 100, name: 'Small (100 bytes)' },
        { size: 1000, name: 'Medium (1KB)' },
        { size: 10000, name: 'Large (10KB)' },
        { size: 100000, name: 'Very Large (100KB)' }
      ];
      
      for (const { size, name } of dataSizes) {
        const testData = 'x'.repeat(size);
        
        const startTime = Date.now();
        const encrypted = await envelopeService.encrypt(testData);
        const decrypted = await envelopeService.decrypt(encrypted);
        const endTime = Date.now();
        
        const operationTime = endTime - startTime;
        
        expect(decrypted).toBe(testData);
        
        // Performance should scale reasonably with data size
        const expectedMaxTime = Math.max(10, size / 1000); // 1ms per KB minimum
        expect(operationTime).toBeLessThan(expectedMaxTime);
        
        console.log(`${name}: ${operationTime}ms`);
      }
    });

    test('should handle concurrent encryption operations', async () => {
      const concurrentOperations = 50;
      const testData = 'Concurrent test data';
      
      const startTime = Date.now();
      
      const promises = [];
      for (let i = 0; i < concurrentOperations; i++) {
        promises.push(envelopeService.encrypt(`${testData}-${i}`));
      }
      
      const results = await Promise.all(promises);
      const endTime = Date.now();
      
      const totalTime = endTime - startTime;
      const avgTime = totalTime / concurrentOperations;
      
      // Should handle concurrency efficiently
      expect(avgTime).toBeLessThan(25);
      expect(results).toHaveLength(concurrentOperations);
      
      console.log(`Concurrent Encryption: ${avgTime.toFixed(2)}ms per operation (${concurrentOperations} concurrent)`);
    });
  });

  describe('Memory Management Performance', () => {
    test('should handle memory cleanup efficiently', () => {
      const bufferCounts = [100, 500, 1000, 2000];
      
      for (const bufferCount of bufferCounts) {
        const buffers: Buffer[] = [];
        
        // Create buffers
        for (let i = 0; i < bufferCount; i++) {
          const buffer = Buffer.from(`Test buffer ${i}`, 'utf8');
          buffers.push(buffer);
          memoryService.registerSensitiveBuffer(buffer);
        }
        
        const startTime = Date.now();
        memoryService.performCleanup();
        const endTime = Date.now();
        
        const cleanupTime = endTime - startTime;
        
        // Should clean up efficiently
        const expectedMaxTime = bufferCount * 0.1; // 0.1ms per buffer
        expect(cleanupTime).toBeLessThan(expectedMaxTime);
        
        console.log(`Memory Cleanup (${bufferCount} buffers): ${cleanupTime}ms`);
      }
    });

    test('should handle large buffer cleanup', () => {
      const bufferSizes = [1024, 10240, 102400, 1048576]; // 1KB to 1MB
      
      for (const bufferSize of bufferSizes) {
        const buffer = Buffer.alloc(bufferSize, 'x');
        memoryService.registerSensitiveBuffer(buffer);
        
        const startTime = Date.now();
        memoryService.performCleanup();
        const endTime = Date.now();
        
        const cleanupTime = endTime - startTime;
        
        // Should handle large buffers efficiently
        const expectedMaxTime = bufferSize / 10000; // 0.1ms per 10KB
        expect(cleanupTime).toBeLessThan(expectedMaxTime);
        
        console.log(`Large Buffer Cleanup (${bufferSize} bytes): ${cleanupTime}ms`);
      }
    });
  });

  describe('Signature Performance', () => {
    test('should meet signature performance requirements', async () => {
      const privateKey = ed25519.utils.randomPrivateKey();
      const publicKey = await ed25519.getPublicKey(privateKey);
      const message = 'Performance test message';
      const messageBytes = Buffer.from(message, 'utf8');
      
      const iterations = 1000;
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const signature = await ed25519.sign(messageBytes, privateKey);
        const isValid = await ed25519.verify(signature, messageBytes, publicKey);
        expect(isValid).toBe(true);
      }
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const avgTime = totalTime / iterations;
      
      // Performance requirement: <1ms per signature operation
      expect(avgTime).toBeLessThan(1);
      
      console.log(`Signature Performance: ${avgTime.toFixed(3)}ms per operation`);
    });

    test('should handle different message sizes efficiently', async () => {
      const privateKey = ed25519.utils.randomPrivateKey();
      const publicKey = await ed25519.getPublicKey(privateKey);
      
      const messageSizes = [100, 1000, 10000, 100000];
      
      for (const size of messageSizes) {
        const message = 'x'.repeat(size);
        const messageBytes = Buffer.from(message, 'utf8');
        
        const startTime = Date.now();
        const signature = await ed25519.sign(messageBytes, privateKey);
        const isValid = await ed25519.verify(signature, messageBytes, publicKey);
        const endTime = Date.now();
        
        const operationTime = endTime - startTime;
        
        expect(isValid).toBe(true);
        
        // Signature performance should be relatively constant regardless of message size
        expect(operationTime).toBeLessThan(5);
        
        console.log(`Signature (${size} bytes): ${operationTime}ms`);
      }
    });
  });

  describe('Key Rotation Performance', () => {
    test('should handle key rotation efficiently', async () => {
      const iterations = 10;
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const oldKeyId = await envelopeService.rotateKeys();
        expect(oldKeyId).toBeDefined();
      }
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const avgTime = totalTime / iterations;
      
      // Key rotation should be reasonably fast
      expect(avgTime).toBeLessThan(100);
      
      console.log(`Key Rotation Performance: ${avgTime.toFixed(2)}ms per rotation`);
    });

    test('should maintain encryption performance after key rotation', async () => {
      const testData = 'Data before and after rotation';
      
      // Encrypt before rotation
      const encryptedBefore = await envelopeService.encrypt(testData);
      const beforeTime = Date.now();
      const decryptedBefore = await envelopeService.decrypt(encryptedBefore);
      const beforeDecryptTime = Date.now() - beforeTime;
      
      // Rotate keys
      await envelopeService.rotateKeys();
      
      // Encrypt after rotation
      const encryptedAfter = await envelopeService.encrypt(testData);
      const afterTime = Date.now();
      const decryptedAfter = await envelopeService.decrypt(encryptedAfter);
      const afterDecryptTime = Date.now() - afterTime;
      
      expect(decryptedBefore).toBe(testData);
      expect(decryptedAfter).toBe(testData);
      
      // Performance should be similar before and after rotation
      const performanceDiff = Math.abs(beforeDecryptTime - afterDecryptTime);
      expect(performanceDiff).toBeLessThan(10); // Less than 10ms difference
      
      console.log(`Performance after rotation: Before ${beforeDecryptTime}ms, After ${afterDecryptTime}ms`);
    });
  });

  describe('Security Bridge Performance', () => {
    test('should handle bridge operations efficiently', async () => {
      const testData = 'Bridge performance test data';
      const iterations = 50;
      
      const startTime = Date.now();
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = await securityBridge.encryptForCheqdStudio(`${testData}-${i}`);
        const decrypted = await securityBridge.decryptFromCheqdStudio(encrypted);
        expect(decrypted).toBe(`${testData}-${i}`);
      }
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const avgTime = totalTime / iterations;
      
      // Bridge operations should be efficient
      expect(avgTime).toBeLessThan(25);
      
      console.log(`Security Bridge Performance: ${avgTime.toFixed(2)}ms per operation`);
    });
  });

  describe('Load Testing', () => {
    test('should handle sustained load', async () => {
      const sustainedOperations = 1000;
      const testData = 'Sustained load test data';
      
      const startTime = Date.now();
      const results = [];
      
      for (let i = 0; i < sustainedOperations; i++) {
        const encrypted = await envelopeService.encrypt(`${testData}-${i}`);
        const decrypted = await envelopeService.decrypt(encrypted);
        results.push(decrypted);
      }
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const avgTime = totalTime / sustainedOperations;
      
      // Should maintain performance under sustained load
      expect(avgTime).toBeLessThan(30);
      expect(results).toHaveLength(sustainedOperations);
      
      console.log(`Sustained Load: ${avgTime.toFixed(2)}ms per operation (${sustainedOperations} operations)`);
    });

    test('should handle mixed workload efficiently', async () => {
      const workload = [
        { type: 'encrypt', count: 100 },
        { type: 'decrypt', count: 100 },
        { type: 'sign', count: 50 },
        { type: 'verify', count: 50 },
        { type: 'memory', count: 25 }
      ];
      
      const startTime = Date.now();
      
      // Execute mixed workload
      for (const { type, count } of workload) {
        for (let i = 0; i < count; i++) {
          switch (type) {
            case 'encrypt':
              await envelopeService.encrypt(`Mixed workload data ${i}`);
              break;
            case 'decrypt':
              const encrypted = await envelopeService.encrypt(`Decrypt test ${i}`);
              await envelopeService.decrypt(encrypted);
              break;
            case 'sign':
              const privateKey = ed25519.utils.randomPrivateKey();
              const message = Buffer.from(`Sign test ${i}`, 'utf8');
              await ed25519.sign(message, privateKey);
              break;
            case 'verify':
              const privKey = ed25519.utils.randomPrivateKey();
              const pubKey = await ed25519.getPublicKey(privKey);
              const msg = Buffer.from(`Verify test ${i}`, 'utf8');
              const sig = await ed25519.sign(msg, privKey);
              await ed25519.verify(sig, msg, pubKey);
              break;
            case 'memory':
              const buffer = Buffer.from(`Memory test ${i}`, 'utf8');
              memoryService.registerSensitiveBuffer(buffer);
              break;
          }
        }
      }
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      const totalOperations = workload.reduce((sum, w) => sum + w.count, 0);
      const avgTime = totalTime / totalOperations;
      
      // Should handle mixed workload efficiently
      expect(avgTime).toBeLessThan(35);
      
      console.log(`Mixed Workload: ${avgTime.toFixed(2)}ms per operation (${totalOperations} total operations)`);
    });
  });

  describe('Memory Usage', () => {
    test('should not leak memory during operations', async () => {
      const initialMemory = process.memoryUsage();
      
      // Perform many operations
      for (let i = 0; i < 1000; i++) {
        const encrypted = await envelopeService.encrypt(`Memory test ${i}`);
        await envelopeService.decrypt(encrypted);
        
        // Register and clean up buffers
        const buffer = Buffer.from(`Buffer ${i}`, 'utf8');
        memoryService.registerSensitiveBuffer(buffer);
        memoryService.performCleanup();
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Memory increase should be reasonable (less than 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
      
      console.log(`Memory Usage: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB increase`);
    });
  });
});
