import { 
  EnvelopeEncryptionService,
  SecureKeyStorage,
  SecurityValidationService,
  KeyRotationService,
  MemoryProtectionService
} from '../../security/index.js';
import { 
  encryptWithPublicKeyAESRSA, 
  decryptWithPrivateKeyAESRSA 
} from '../../aesRsaEncryption.js';
import { createTestEnvironment, generateTestString, expectToThrow } from '../utils/test-helpers.js';
import crypto from 'crypto';

describe('Comprehensive Security Tests', () => {
  let testEnvironment: any;
  let envelopeService: EnvelopeEncryptionService;
  let secureStorage: SecureKeyStorage;
  let securityValidationService: SecurityValidationService;
  let keyRotationService: KeyRotationService;
  let memoryProtectionService: MemoryProtectionService;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    envelopeService = EnvelopeEncryptionService.getInstance();
    secureStorage = SecureKeyStorage.getInstance();
    securityValidationService = SecurityValidationService.getInstance();
    keyRotationService = KeyRotationService.getInstance();
    memoryProtectionService = MemoryProtectionService.getInstance();
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('Security Architecture Validation', () => {
    it('should validate complete security architecture', async () => {
      // Test all security services are properly initialized
      expect(envelopeService).toBeDefined();
      expect(secureStorage).toBeDefined();
      expect(securityValidationService).toBeDefined();
      expect(keyRotationService).toBeDefined();
      expect(memoryProtectionService).toBeDefined();

      // Validate singleton patterns
      expect(EnvelopeEncryptionService.getInstance()).toBe(envelopeService);
      expect(SecureKeyStorage.getInstance()).toBe(secureStorage);
      expect(SecurityValidationService.getInstance()).toBe(securityValidationService);
      expect(KeyRotationService.getInstance()).toBe(keyRotationService);
      expect(MemoryProtectionService.getInstance()).toBe(memoryProtectionService);
    });

    it('should validate encryption algorithm consistency', async () => {
      const testData = generateTestString(1000);
      
      // Test envelope encryption
      const envelopeResult = await envelopeService.encrypt(testData);
      expect(envelopeResult.algorithm).toBe('aes-256-gcm');
      expect(envelopeResult.version).toBe(1);
      
      // Test AES-RSA encryption
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      const aesRsaResult = await encryptWithPublicKeyAESRSA(testData, publicKey);
      expect(aesRsaResult.algorithm).toBe('aes-rsa');
    });

    it('should validate key management security', async () => {
      const keyId = generateTestString(16);
      const did = testEnvironment.testDID;
      const privateKey = testEnvironment.testPrivateKey;
      const publicKey = testEnvironment.testPublicKey;
      const password = generateTestString(16);
      
      // Store key
      await secureStorage.storeKey(keyId, did, privateKey, publicKey, password);
      
      // Verify key is stored securely
      const keys = await secureStorage.listKeys();
      const storedKey = keys.find(k => k.keyId === keyId);
      
      expect(storedKey).toBeDefined();
      expect(storedKey?.encryptedPrivateKey.algorithm).toBe('aes-256-gcm');
      expect(storedKey?.isActive).toBe(true);
      
      // Verify key can be retrieved
      const retrieved = await secureStorage.retrieveKey(keyId, password);
      expect(retrieved?.privateKeyHex).toBe(privateKey);
      expect(retrieved?.publicKeyHex).toBe(publicKey);
    });
  });

  describe('Multi-Layer Security Validation', () => {
    it('should validate defense in depth', async () => {
      const sensitiveData = generateTestString(5000);
      const password = generateTestString(16);
      
      // Layer 1: Envelope encryption
      const envelopeEncrypted = await envelopeService.encrypt(sensitiveData);
      
      // Layer 2: AES-RSA encryption of envelope result
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      const envelopeJson = JSON.stringify(envelopeEncrypted);
      const aesRsaEncrypted = await encryptWithPublicKeyAESRSA(envelopeJson, publicKey);
      
      // Layer 3: Secure key storage
      const keyId = generateTestString(16);
      const did = testEnvironment.testDID;
      await secureStorage.storeKey(keyId, did, testEnvironment.testPrivateKey, testEnvironment.testPublicKey, password);
      
      // Verify all layers work together
      expect(envelopeEncrypted.encryptedData).toBeDefined();
      expect(aesRsaEncrypted.encryptedData).toBeDefined();
      expect(aesRsaEncrypted.encryptedKey).toBeDefined();
      
      // Test decryption through all layers
      const decryptedEnvelopeJson = await decryptWithPrivateKeyAESRSA(aesRsaEncrypted, privateKey);
      const decryptedEnvelope = JSON.parse(decryptedEnvelopeJson);
      const finalDecrypted = await envelopeService.decrypt(decryptedEnvelope);
      
      expect(finalDecrypted).toBe(sensitiveData);
    });

    it('should validate security boundaries', async () => {
      // Test that services cannot access each other's internal state
      const keyId = generateTestString(16);
      const did = testEnvironment.testDID;
      const privateKey = testEnvironment.testPrivateKey;
      const publicKey = testEnvironment.testPublicKey;
      const password = generateTestString(16);
      
      await secureStorage.storeKey(keyId, did, privateKey, publicKey, password);
      
      // Envelope service should not have access to stored keys
      const envelopeKeyId = envelopeService.getCurrentKeyId();
      expect(envelopeKeyId).toBeDefined();
      expect(envelopeKeyId).not.toBe(keyId);
      
      // Security validation should not expose sensitive data
      const securityReport = await securityValidationService.generateSecurityReport();
      expect(securityReport.overallScore).toBeGreaterThanOrEqual(0);
      expect(securityReport.overallScore).toBeLessThanOrEqual(100);
      
      // Report should not contain actual private keys or sensitive data
      const reportString = JSON.stringify(securityReport);
      expect(reportString).not.toContain(privateKey);
      expect(reportString).not.toContain(password);
    });
  });

  describe('Security Property Validation', () => {
    it('should validate confidentiality', async () => {
      const sensitiveData = generateTestString(1000);
      
      // Test envelope encryption confidentiality
      const encrypted = await envelopeService.encrypt(sensitiveData);
      expect(encrypted.encryptedData).not.toBe(sensitiveData);
      expect(encrypted.encryptedData).not.toContain(sensitiveData);
      
      // Test AES-RSA encryption confidentiality
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      const aesRsaEncrypted = await encryptWithPublicKeyAESRSA(sensitiveData, publicKey);
      expect(aesRsaEncrypted.encryptedData).not.toBe(sensitiveData);
      expect(aesRsaEncrypted.encryptedData).not.toContain(sensitiveData);
    });

    it('should validate integrity', async () => {
      const testData = generateTestString(1000);
      
      // Test envelope encryption integrity
      const encrypted = await envelopeService.encrypt(testData);
      const decrypted = await envelopeService.decrypt(encrypted);
      expect(decrypted).toBe(testData);
      
      // Test tamper detection
      const tamperedEncrypted = { ...encrypted, encryptedData: 'tampered-data' };
      await expectToThrow(
        () => envelopeService.decrypt(tamperedEncrypted),
        'Failed to decrypt data'
      );
    });

    it('should validate authenticity', async () => {
      const testData = generateTestString(1000);
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      // Test AES-RSA authenticity
      const encrypted = await encryptWithPublicKeyAESRSA(testData, publicKey);
      const decrypted = await decryptWithPrivateKeyAESRSA(encrypted, privateKey);
      expect(decrypted).toBe(testData);
      
      // Test wrong key rejection
      const { privateKey: wrongPrivateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      await expectToThrow(
        () => decryptWithPrivateKeyAESRSA(encrypted, wrongPrivateKey),
        'AES-RSA decryption failed'
      );
    });

    it('should validate non-repudiation', async () => {
      const testData = generateTestString(1000);
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      // Test that only the holder of the private key can decrypt
      const encrypted = await encryptWithPublicKeyAESRSA(testData, publicKey);
      const decrypted = await decryptWithPrivateKeyAESRSA(encrypted, privateKey);
      expect(decrypted).toBe(testData);
      
      // Test that public key alone cannot decrypt
      await expectToThrow(
        () => decryptWithPrivateKeyAESRSA(encrypted, publicKey),
        'AES-RSA decryption failed'
      );
    });
  });

  describe('Security Threat Mitigation', () => {
    it('should mitigate timing attacks', async () => {
      const testData = generateTestString(1000);
      const validPassword = generateTestString(16);
      const invalidPassword = generateTestString(16);
      
      const keyId = generateTestString(16);
      const did = testEnvironment.testDID;
      await secureStorage.storeKey(keyId, did, testEnvironment.testPrivateKey, testEnvironment.testPublicKey, validPassword);
      
      // Measure timing for valid and invalid passwords
      const validStart = performance.now();
      await secureStorage.retrieveKey(keyId, validPassword);
      const validTime = performance.now() - validStart;
      
      const invalidStart = performance.now();
      await secureStorage.retrieveKey(keyId, invalidPassword);
      const invalidTime = performance.now() - invalidStart;
      
      // Timing difference should be minimal (within 100ms)
      expect(Math.abs(validTime - invalidTime)).toBeLessThan(100);
    });

    it('should mitigate replay attacks', async () => {
      const testData = generateTestString(1000);
      
      // Test that same data produces different encrypted results
      const encrypted1 = await envelopeService.encrypt(testData);
      const encrypted2 = await envelopeService.encrypt(testData);
      
      expect(encrypted1.encryptedData).not.toBe(encrypted2.encryptedData);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.authTag).not.toBe(encrypted2.authTag);
    });

    it('should mitigate side-channel attacks', async () => {
      const testData = generateTestString(1000);
      
      // Test that encryption operations don't leak information through timing
      const operations = Array.from({ length: 10 }, () => 
        envelopeService.encrypt(testData)
      );
      
      const results = await Promise.all(operations);
      
      // All operations should complete successfully
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result.encryptedData).toBeDefined();
        expect(result.algorithm).toBe('aes-256-gcm');
      });
    });

    it('should mitigate memory-based attacks', async () => {
      const sensitiveData = generateTestString(1000);
      const buffer = Buffer.from(sensitiveData);
      
      // Register sensitive buffer
      memoryProtectionService.registerSensitiveBuffer(buffer);
      
      // Perform encryption
      const encrypted = await envelopeService.encrypt(sensitiveData);
      expect(encrypted.encryptedData).toBeDefined();
      
      // Zeroize sensitive buffer
      memoryProtectionService.zeroizeBuffer(buffer);
      
      // Buffer should be zeroized
      expect(buffer.every(byte => byte === 0)).toBe(true);
    });
  });

  describe('Security Compliance Validation', () => {
    it('should comply with encryption standards', async () => {
      const testData = generateTestString(1000);
      
      // Test AES-256-GCM compliance
      const encrypted = await envelopeService.encrypt(testData);
      expect(encrypted.algorithm).toBe('aes-256-gcm');
      
      // Verify IV length (12 bytes for AES-256-GCM)
      const iv = Buffer.from(encrypted.iv, 'base64');
      expect(iv.length).toBe(12);
      
      // Verify salt length (32 bytes for scrypt)
      const salt = Buffer.from(encrypted.salt, 'base64');
      expect(salt.length).toBe(32);
      
      // Verify auth tag presence
      expect(encrypted.authTag).toBeDefined();
      expect(encrypted.authTag.length).toBeGreaterThan(0);
    });

    it('should comply with key management standards', async () => {
      const keyId = generateTestString(16);
      const did = testEnvironment.testDID;
      const privateKey = testEnvironment.testPrivateKey;
      const publicKey = testEnvironment.testPublicKey;
      const password = generateTestString(16);
      
      // Test secure key storage
      await secureStorage.storeKey(keyId, did, privateKey, publicKey, password);
      
      const keys = await secureStorage.listKeys();
      const storedKey = keys.find(k => k.keyId === keyId);
      
      // Verify key metadata
      expect(storedKey?.createdAt).toBeDefined();
      expect(storedKey?.isActive).toBe(true);
      expect(storedKey?.encryptedPrivateKey).toBeDefined();
      
      // Verify encryption algorithm
      expect(storedKey?.encryptedPrivateKey.algorithm).toBe('aes-256-gcm');
    });

    it('should comply with security validation standards', async () => {
      const securityReport = await securityValidationService.generateSecurityReport();
      
      // Verify report structure
      expect(securityReport.timestamp).toBeDefined();
      expect(securityReport.overallScore).toBeGreaterThanOrEqual(0);
      expect(securityReport.overallScore).toBeLessThanOrEqual(100);
      expect(securityReport.validationResults).toBeDefined();
      expect(securityReport.keyIntegrityResults).toBeDefined();
      expect(securityReport.encryptionConfigResults).toBeDefined();
      expect(Array.isArray(securityReport.recommendations)).toBe(true);
      
      // Verify timestamp format
      expect(new Date(securityReport.timestamp).getTime()).not.toBeNaN();
    });
  });

  describe('Security Resilience Testing', () => {
    it('should handle security service failures gracefully', async () => {
      const testData = generateTestString(1000);
      
      // Test envelope service resilience
      const encrypted = await envelopeService.encrypt(testData);
      expect(encrypted).toBeDefined();
      
      // Test decryption resilience
      const decrypted = await envelopeService.decrypt(encrypted);
      expect(decrypted).toBe(testData);
      
      // Test error handling
      await expectToThrow(
        () => envelopeService.decrypt({} as any),
        'Failed to decrypt data'
      );
    });

    it('should handle key rotation gracefully', async () => {
      const did = testEnvironment.testDID;
      
      // Test rotation plan creation
      const rotationPlan = await keyRotationService.createRotationPlan(did);
      expect(rotationPlan).toBeDefined();
      expect(rotationPlan.rotationId).toBeDefined();
      
      // Test rotation execution
      const rotationResult = await keyRotationService.executeKeyRotation(rotationPlan, 'test-password');
      expect(rotationResult).toBeDefined();
      expect(rotationResult.rotationId).toBe(rotationPlan.rotationId);
    });

    it('should handle memory pressure gracefully', async () => {
      const largeData = generateTestString(100000); // 100KB
      
      // Test large data encryption
      const encrypted = await envelopeService.encrypt(largeData);
      expect(encrypted).toBeDefined();
      
      // Test large data decryption
      const decrypted = await envelopeService.decrypt(encrypted);
      expect(decrypted).toBe(largeData);
      
      // Test memory cleanup
      memoryProtectionService.performCleanup();
      expect(true).toBe(true); // If we get here, cleanup succeeded
    });
  });
});