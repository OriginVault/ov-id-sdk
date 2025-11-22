import { 
  EnvelopeEncryptionService,
  SecureKeyStorage,
  encryptWithPublicKeyAESRSA,
  decryptWithPrivateKeyAESRSA
} from '../../index.js';
import { 
  createTestEnvironment, 
  generateTestString, 
  PerformanceTimer,
  getMemoryUsage 
} from '../utils/test-helpers.js';
import crypto from 'crypto';

describe('Load Testing and Performance', () => {
  let testEnvironment: any;
  let envelopeService: EnvelopeEncryptionService;
  let secureStorage: SecureKeyStorage;
  let rsaKeyPair: { publicKey: string; privateKey: string };

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    envelopeService = EnvelopeEncryptionService.getInstance();
    secureStorage = SecureKeyStorage.getInstance();
    
    // Generate RSA key pair for AES-RSA tests
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    rsaKeyPair = keyPair;
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('Envelope Encryption Performance', () => {
    it('should handle high-volume encryption operations', async () => {
      const dataSizes = [100, 1000, 10000, 100000]; // 100B, 1KB, 10KB, 100KB
      const iterations = 100;
      
      for (const size of dataSizes) {
        const testData = generateTestString(size);
        const timer = new PerformanceTimer();
        
        timer.start();
        
        const operations = Array.from({ length: iterations }, () => 
          envelopeService.encrypt(testData)
        );
        
        await Promise.all(operations);
        
        const duration = timer.stop();
        const avgTimePerOperation = duration / iterations;
        const throughput = (size * iterations) / (duration / 1000); // bytes per second
        
        console.log(`Envelope Encryption - Size: ${size}B, Iterations: ${iterations}`);
        console.log(`  Total time: ${duration.toFixed(2)}ms`);
        console.log(`  Average time per operation: ${avgTimePerOperation.toFixed(2)}ms`);
        console.log(`  Throughput: ${(throughput / 1024).toFixed(2)} KB/s`);
        
        // Performance assertions
        expect(avgTimePerOperation).toBeLessThan(100); // Less than 100ms per operation
        expect(throughput).toBeGreaterThan(1000); // More than 1KB/s
      }
    });

    it('should handle concurrent encryption operations', async () => {
      const concurrentOperations = 50;
      const testData = generateTestString(1000);
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const operations = Array.from({ length: concurrentOperations }, () => 
        envelopeService.encrypt(testData)
      );
      
      const results = await Promise.all(operations);
      
      const duration = timer.stop();
      const avgTimePerOperation = duration / concurrentOperations;
      
      console.log(`Concurrent Envelope Encryption - Operations: ${concurrentOperations}`);
      console.log(`  Total time: ${duration.toFixed(2)}ms`);
      console.log(`  Average time per operation: ${avgTimePerOperation.toFixed(2)}ms`);
      
      expect(results).toHaveLength(concurrentOperations);
      expect(avgTimePerOperation).toBeLessThan(50); // Less than 50ms per operation
    });

    it('should maintain performance under memory pressure', async () => {
      const initialMemory = getMemoryUsage();
      const largeDataSize = 1000000; // 1MB
      const iterations = 10;
      
      const timer = new PerformanceTimer();
      timer.start();
      
      for (let i = 0; i < iterations; i++) {
        const largeData = generateTestString(largeDataSize);
        const encrypted = await envelopeService.encrypt(largeData);
        const decrypted = await envelopeService.decrypt(encrypted);
        
        expect(decrypted).toBe(largeData);
        
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
      }
      
      const duration = timer.stop();
      const finalMemory = getMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      console.log(`Memory Pressure Test - Data size: ${largeDataSize}B, Iterations: ${iterations}`);
      console.log(`  Total time: ${duration.toFixed(2)}ms`);
      console.log(`  Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)} MB`);
      
      expect(duration / iterations).toBeLessThan(1000); // Less than 1s per iteration
      expect(memoryIncrease / 1024 / 1024).toBeLessThan(100); // Less than 100MB increase
    });
  });

  describe('AES-RSA Encryption Performance', () => {
    it('should handle high-volume AES-RSA operations', async () => {
      const dataSizes = [100, 1000, 10000]; // RSA has size limitations
      const iterations = 50;
      
      for (const size of dataSizes) {
        const testData = generateTestString(size);
        const timer = new PerformanceTimer();
        
        timer.start();
        
        const operations = Array.from({ length: iterations }, async () => {
          const encrypted = await encryptWithPublicKeyAESRSA(testData, rsaKeyPair.publicKey);
          return decryptWithPrivateKeyAESRSA(encrypted, rsaKeyPair.privateKey);
        });
        
        const results = await Promise.all(operations);
        
        const duration = timer.stop();
        const avgTimePerOperation = duration / iterations;
        
        console.log(`AES-RSA Encryption - Size: ${size}B, Iterations: ${iterations}`);
        console.log(`  Total time: ${duration.toFixed(2)}ms`);
        console.log(`  Average time per operation: ${avgTimePerOperation.toFixed(2)}ms`);
        
        // Verify all results
        results.forEach(result => {
          expect(result).toBe(testData);
        });
        
        expect(avgTimePerOperation).toBeLessThan(200); // Less than 200ms per operation
      }
    });

    it('should handle large data with AES-RSA', async () => {
      const largeData = generateTestString(50000); // 50KB
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const encrypted = await encryptWithPublicKeyAESRSA(largeData, rsaKeyPair.publicKey);
      const decrypted = await decryptWithPrivateKeyAESRSA(encrypted, rsaKeyPair.privateKey);
      
      const duration = timer.stop();
      
      console.log(`AES-RSA Large Data - Size: ${largeData.length}B`);
      console.log(`  Total time: ${duration.toFixed(2)}ms`);
      console.log(`  Throughput: ${(largeData.length / (duration / 1000) / 1024).toFixed(2)} KB/s`);
      
      expect(decrypted).toBe(largeData);
      expect(duration).toBeLessThan(5000); // Less than 5 seconds
    });
  });

  describe('Secure Key Storage Performance', () => {
    it('should handle high-volume key operations', async () => {
      const keyCount = 100;
      const password = generateTestString(16);
      const timer = new PerformanceTimer();
      
      timer.start();
      
      // Store multiple keys
      const storeOperations = Array.from({ length: keyCount }, async (_, i) => {
        const keyId = `perf-test-key-${i}`;
        const did = `did:key:perf-test-${i}`;
        const privateKey = generateTestString(64);
        const publicKey = generateTestString(64);
        
        return secureStorage.storeKey(keyId, did, privateKey, publicKey, password);
      });
      
      await Promise.all(storeOperations);
      
      const storeDuration = timer.stop();
      
      // Retrieve all keys
      timer.start();
      
      const retrieveOperations = Array.from({ length: keyCount }, async (_, i) => {
        const keyId = `perf-test-key-${i}`;
        return secureStorage.retrieveKey(keyId, password);
      });
      
      const retrievedKeys = await Promise.all(retrieveOperations);
      
      const retrieveDuration = timer.stop();
      
      console.log(`Secure Key Storage Performance - Keys: ${keyCount}`);
      console.log(`  Store time: ${storeDuration.toFixed(2)}ms`);
      console.log(`  Retrieve time: ${retrieveDuration.toFixed(2)}ms`);
      console.log(`  Average store time per key: ${(storeDuration / keyCount).toFixed(2)}ms`);
      console.log(`  Average retrieve time per key: ${(retrieveDuration / keyCount).toFixed(2)}ms`);
      
      expect(retrievedKeys).toHaveLength(keyCount);
      retrievedKeys.forEach(key => {
        expect(key).toBeDefined();
        expect(key?.privateKeyHex).toBeDefined();
        expect(key?.publicKeyHex).toBeDefined();
      });
      
      expect(storeDuration / keyCount).toBeLessThan(100); // Less than 100ms per key
      expect(retrieveDuration / keyCount).toBeLessThan(50); // Less than 50ms per key
    });

    it('should handle concurrent key operations', async () => {
      const concurrentOperations = 20;
      const password = generateTestString(16);
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const operations = Array.from({ length: concurrentOperations }, async (_, i) => {
        const keyId = `concurrent-test-key-${i}`;
        const did = `did:key:concurrent-test-${i}`;
        const privateKey = generateTestString(64);
        const publicKey = generateTestString(64);
        
        await secureStorage.storeKey(keyId, did, privateKey, publicKey, password);
        return secureStorage.retrieveKey(keyId, password);
      });
      
      const results = await Promise.all(operations);
      
      const duration = timer.stop();
      const avgTimePerOperation = duration / concurrentOperations;
      
      console.log(`Concurrent Key Operations - Operations: ${concurrentOperations}`);
      console.log(`  Total time: ${duration.toFixed(2)}ms`);
      console.log(`  Average time per operation: ${avgTimePerOperation.toFixed(2)}ms`);
      
      expect(results).toHaveLength(concurrentOperations);
      expect(avgTimePerOperation).toBeLessThan(150); // Less than 150ms per operation
    });
  });

  describe('Memory Usage and Leak Detection', () => {
    it('should not leak memory during encryption operations', async () => {
      const initialMemory = getMemoryUsage();
      const iterations = 1000;
      const testData = generateTestString(1000);
      
      for (let i = 0; i < iterations; i++) {
        const encrypted = await envelopeService.encrypt(testData);
        const decrypted = await envelopeService.decrypt(encrypted);
        
        expect(decrypted).toBe(testData);
        
        // Force garbage collection every 100 iterations
        if (i % 100 === 0 && global.gc) {
          global.gc();
        }
      }
      
      const finalMemory = getMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      console.log(`Memory Leak Test - Iterations: ${iterations}`);
      console.log(`  Initial memory: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
      console.log(`  Final memory: ${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
      console.log(`  Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)} MB`);
      
      // Memory increase should be reasonable (less than 50MB for 1000 operations)
      expect(memoryIncrease / 1024 / 1024).toBeLessThan(50);
    });

    it('should handle memory pressure gracefully', async () => {
      const largeDataSize = 100000; // 100KB
      const iterations = 50;
      const initialMemory = getMemoryUsage();
      
      const timer = new PerformanceTimer();
      timer.start();
      
      for (let i = 0; i < iterations; i++) {
        const largeData = generateTestString(largeDataSize);
        const encrypted = await envelopeService.encrypt(largeData);
        const decrypted = await envelopeService.decrypt(encrypted);
        
        expect(decrypted).toBe(largeData);
      }
      
      const duration = timer.stop();
      const finalMemory = getMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      console.log(`Memory Pressure Test - Data size: ${largeDataSize}B, Iterations: ${iterations}`);
      console.log(`  Total time: ${duration.toFixed(2)}ms`);
      console.log(`  Memory increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)} MB`);
      
      expect(duration / iterations).toBeLessThan(500); // Less than 500ms per iteration
      expect(memoryIncrease / 1024 / 1024).toBeLessThan(200); // Less than 200MB increase
    });
  });

  describe('Stress Testing', () => {
    it('should handle stress test with mixed operations', async () => {
      const operations = 200;
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const mixedOperations = Array.from({ length: operations }, async (_, i) => {
        const operationType = i % 4;
        const testData = generateTestString(1000);
        
        switch (operationType) {
          case 0:
            // Envelope encryption
            return envelopeService.encrypt(testData);
          case 1:
            // AES-RSA encryption
            const encrypted = await encryptWithPublicKeyAESRSA(testData, rsaKeyPair.publicKey);
            return decryptWithPrivateKeyAESRSA(encrypted, rsaKeyPair.privateKey);
          case 2:
            // Key storage
            const keyId = `stress-test-key-${i}`;
            const did = `did:key:stress-test-${i}`;
            const privateKey = generateTestString(64);
            const publicKey = generateTestString(64);
            const password = generateTestString(16);
            
            await secureStorage.storeKey(keyId, did, privateKey, publicKey, password);
            return secureStorage.retrieveKey(keyId, password);
          case 3:
            // Mixed encryption
            const envelopeEncrypted = await envelopeService.encrypt(testData);
            const envelopeJson = JSON.stringify(envelopeEncrypted);
            const aesRsaEncrypted = await encryptWithPublicKeyAESRSA(envelopeJson, rsaKeyPair.publicKey);
            const decryptedEnvelopeJson = await decryptWithPrivateKeyAESRSA(aesRsaEncrypted, rsaKeyPair.privateKey);
            const decryptedEnvelope = JSON.parse(decryptedEnvelopeJson);
            return envelopeService.decrypt(decryptedEnvelope);
          default:
            return Promise.resolve();
        }
      });
      
      const results = await Promise.all(mixedOperations);
      
      const duration = timer.stop();
      const avgTimePerOperation = duration / operations;
      
      console.log(`Stress Test - Operations: ${operations}`);
      console.log(`  Total time: ${duration.toFixed(2)}ms`);
      console.log(`  Average time per operation: ${avgTimePerOperation.toFixed(2)}ms`);
      
      expect(results).toHaveLength(operations);
      expect(avgTimePerOperation).toBeLessThan(200); // Less than 200ms per operation
    });

    it('should maintain performance under sustained load', async () => {
      const sustainedOperations = 500;
      const testData = generateTestString(1000);
      const performanceResults: number[] = [];
      
      for (let i = 0; i < sustainedOperations; i++) {
        const timer = new PerformanceTimer();
        
        timer.start();
        const encrypted = await envelopeService.encrypt(testData);
        const decrypted = await envelopeService.decrypt(encrypted);
        const duration = timer.stop();
        
        expect(decrypted).toBe(testData);
        performanceResults.push(duration);
        
        // Log progress every 100 operations
        if (i % 100 === 0) {
          const avgTime = performanceResults.slice(-100).reduce((a, b) => a + b, 0) / Math.min(100, performanceResults.length);
          console.log(`Sustained Load Test - Operation ${i}, Average time: ${avgTime.toFixed(2)}ms`);
        }
      }
      
      const avgTime = performanceResults.reduce((a, b) => a + b, 0) / performanceResults.length;
      const maxTime = Math.max(...performanceResults);
      const minTime = Math.min(...performanceResults);
      
      console.log(`Sustained Load Test Results - Operations: ${sustainedOperations}`);
      console.log(`  Average time: ${avgTime.toFixed(2)}ms`);
      console.log(`  Max time: ${maxTime.toFixed(2)}ms`);
      console.log(`  Min time: ${minTime.toFixed(2)}ms`);
      
      expect(avgTime).toBeLessThan(100); // Average less than 100ms
      expect(maxTime).toBeLessThan(500); // Max less than 500ms
    });
  });
});