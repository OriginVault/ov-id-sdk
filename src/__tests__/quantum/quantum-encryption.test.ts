import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { generateKyberKeyPair, encryptWithKyber, decryptWithKyber, validateKyberKeyPair } from '../../quantum/quantumEncryption.js';
import { KeyEncryptionService } from '../../encryption.js';
import { EnhancedKeyStorage } from '../../storage/EnhancedKeyStorage.js';
import { QuantumKeyManager } from '../../identityManager.js';
import { QuantumMessenger } from '../../messanger.js';
import { KeyEntity } from '../../storage/entities/KeyEntity.js';
import { DataSource, Repository } from 'typeorm';

describe('Quantum Encryption Tests', () => {
  let dataSource: DataSource;
  let keyRepository: Repository<KeyEntity>;
  let encryptionKey: string;
  let enhancedKeyStorage: EnhancedKeyStorage;
  let quantumKeyManager: QuantumKeyManager;
  let quantumMessenger: QuantumMessenger;

  beforeEach(async () => {
    // Setup in-memory database for testing
    dataSource = new DataSource({
      type: 'sqlite',
      database: ':memory:',
      entities: [KeyEntity],
      synchronize: true,
    });

    await dataSource.initialize();
    keyRepository = dataSource.getRepository(KeyEntity);
    
    // Setup encryption key
    encryptionKey = 'test-encryption-key-12345';
    
    // Initialize services
    enhancedKeyStorage = new EnhancedKeyStorage(encryptionKey, keyRepository);
    quantumKeyManager = new QuantumKeyManager(encryptionKey, keyRepository);
    quantumMessenger = new QuantumMessenger(encryptionKey, keyRepository);
  });

  afterEach(async () => {
    if (dataSource) {
      await dataSource.destroy();
    }
  });

  describe('Kyber Key Generation', () => {
    it('should generate valid Kyber key pairs', async () => {
      const { publicKey, privateKey } = await generateKyberKeyPair();
      
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
      expect(publicKey).toMatch(/^[0-9a-fA-F]+$/);
      expect(privateKey).toMatch(/^[0-9a-fA-F]+$/);
      expect(publicKey.length).toBeGreaterThan(0);
      expect(privateKey.length).toBeGreaterThan(0);
    });

    it('should validate key pairs correctly', async () => {
      const { publicKey, privateKey } = await generateKyberKeyPair();
      
      expect(await validateKyberKeyPair(publicKey, privateKey)).toBe(true);
      expect(await validateKyberKeyPair(publicKey, 'invalid-key')).toBe(false);
    });
  });

  describe('Quantum Encryption/Decryption', () => {
    it('should encrypt and decrypt messages correctly', async () => {
      const { publicKey, privateKey } = await generateKyberKeyPair();
      const testMessage = 'Hello, quantum world!';
      
      const encrypted = await encryptWithKyber(testMessage, publicKey, privateKey);
      
      expect(encrypted).toBeDefined();
      expect(encrypted.algorithm).toBe('aes-kyber');
      expect(encrypted.kyberPublicKey).toBe(publicKey);
      expect(encrypted.encryptedData).toBeDefined();
      expect(encrypted.encryptedKey).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      
      const decrypted = await decryptWithKyber(encrypted, privateKey);
      expect(decrypted).toBe(testMessage);
    });

    it('should handle different message types', async () => {
      const { publicKey, privateKey } = await generateKyberKeyPair();
      
      const messages = [
        'Simple text',
        'Text with special characters: !@#$%^&*()',
        'Unicode: 🚀🌍🔐',
        JSON.stringify({ test: 'data', number: 123, boolean: true })
      ];
      
      for (const message of messages) {
        const encrypted = await encryptWithKyber(message, publicKey, privateKey);
        const decrypted = await decryptWithKyber(encrypted, privateKey);
        expect(decrypted).toBe(message);
      }
    });
  });

  describe('Key Encryption Service', () => {
    it('should encrypt and decrypt keys correctly', async () => {
      const service = new KeyEncryptionService(encryptionKey);
      const testKey = 'test-private-key-data';
      
      const encrypted = await service.encryptKey(testKey);
      expect(encrypted).toBeDefined();
      expect(encrypted.algorithm).toBe('aes-256-gcm');
      expect(encrypted.keyDerivation).toBe('scrypt');
      
      const decrypted = await service.decryptKey(encrypted);
      expect(decrypted).toBe(testKey);
    });
  });

  describe('Enhanced Key Storage', () => {
    it('should store and retrieve quantum keys', async () => {
      const did = 'did:test:123';
      const { publicKey, privateKey } = await generateKyberKeyPair();
      const keyId = 'kyber-test';
      
      const storedKey = {
        keyId,
        algorithm: 'Kyber768',
        keyType: 'quantum' as const,
        publicKeyHex: publicKey,
        encryptedPrivateKey: await enhancedKeyStorage.keyEncryptionService.encryptKey(privateKey),
        metadata: { test: true }
      };
      
      await enhancedKeyStorage.storeKey(did, storedKey);
      
      const retrievedKey = await enhancedKeyStorage.retrieveKey(did, keyId);
      expect(retrievedKey).toBeDefined();
      expect(retrievedKey?.publicKeyHex).toBe(publicKey);
      expect(retrievedKey?.algorithm).toBe('Kyber768');
      expect(retrievedKey?.keyType).toBe('quantum');
      
      const decryptedPrivateKey = await enhancedKeyStorage.getDecryptedPrivateKey(did, keyId);
      expect(decryptedPrivateKey).toBe(privateKey);
    });
  });

  describe('Quantum Key Manager', () => {
    it('should generate and manage quantum keys for DIDs', async () => {
      const did = 'did:test:456';
      
      const result = await quantumKeyManager.generateQuantumKeys(did);
      expect(result.publicKey).toBeDefined();
      expect(result.keyId).toBeDefined();
      
      const publicKey = await quantumKeyManager.getQuantumPublicKey(did);
      expect(publicKey).toBe(result.publicKey);
      
      const privateKey = await quantumKeyManager.getQuantumPrivateKey(did);
      expect(privateKey).toBeDefined();
      
      const quantumKeys = await quantumKeyManager.listQuantumKeys(did);
      expect(quantumKeys).toHaveLength(1);
      expect(quantumKeys[0].algorithm).toBe('Kyber768');
    });
  });

  describe('Quantum Messenger', () => {
    it('should send and receive quantum-encrypted messages', async () => {
      const senderDID = 'did:test:sender';
      const recipientDID = 'did:test:recipient';
      const message = 'Secret quantum message';
      
      // Generate quantum keys for both DIDs
      await quantumMessenger.generateQuantumKeys(senderDID);
      await quantumMessenger.generateQuantumKeys(recipientDID);
      
      // Send quantum-encrypted message
      const encryptedMessage = await quantumMessenger.sendQuantumEncryptedMessage(
        recipientDID,
        message,
        senderDID
      );
      
      expect(encryptedMessage).toBeDefined();
      expect(typeof encryptedMessage).toBe('string');
      
      // Decrypt the message
      const decryptedMessage = await quantumMessenger.decryptQuantumMessage(
        encryptedMessage,
        recipientDID
      );
      
      expect(decryptedMessage).toBe(message);
    });

    it('should handle missing quantum keys gracefully', async () => {
      const senderDID = 'did:test:sender2';
      const recipientDID = 'did:test:recipient2';
      const message = 'Test message';
      
      // Try to send message without quantum keys
      await expect(
        quantumMessenger.sendQuantumEncryptedMessage(recipientDID, message, senderDID)
      ).rejects.toThrow('does not have quantum keys');
    });
  });
});
