import { 
  encryptWithPublicKeyAESRSA, 
  decryptWithPrivateKeyAESRSA, 
  isAESRSAEncryptedMessage,
  AESRSAEncryptedMessage 
} from '../../aesRsaEncryption.js';
import crypto from 'crypto';

describe('AES-RSA Encryption Tests', () => {
  let publicKeyPem: string;
  let privateKeyPem: string;
  let keyPair: crypto.KeyPairKeyObjectResult;

  beforeAll(async () => {
    // Generate a test RSA key pair
    keyPair = crypto.generateKeyPairSync('rsa', {
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
    
    publicKeyPem = keyPair.publicKey;
    privateKeyPem = keyPair.privateKey;
  });

  describe('Basic Encryption/Decryption', () => {
    test('should encrypt and decrypt a simple message', () => {
      const message = 'Hello, World!';
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      expect(encrypted.algorithm).toBe('aes-rsa');
      expect(encrypted.encryptedData).toBeDefined();
      expect(encrypted.encryptedKey).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, privateKeyPem);
      expect(decrypted).toBe(message);
    });

    test('should encrypt and decrypt a large message', () => {
      const message = 'A'.repeat(10000); // 10KB message
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, privateKeyPem);
      
      expect(decrypted).toBe(message);
    });

    test('should encrypt and decrypt JSON data', () => {
      const message = JSON.stringify({
        type: 'test-message',
        data: { foo: 'bar', nested: { value: 123 } },
        timestamp: new Date().toISOString()
      });
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, privateKeyPem);
      
      expect(JSON.parse(decrypted)).toEqual(JSON.parse(message));
    });
  });

  describe('Environment Variable Key Handling', () => {
    test('should handle private key with literal \\n characters', () => {
      const message = 'Test message with literal newlines';
      
      // Simulate private key from environment variable with literal \n
      const privateKeyWithLiteralNewlines = privateKeyPem.replace(/\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, privateKeyWithLiteralNewlines);
      
      expect(decrypted).toBe(message);
    });

    test('should handle public key with literal \\n characters', () => {
      const message = 'Test message with literal newlines in public key';
      
      // Simulate public key from environment variable with literal \n
      const publicKeyWithLiteralNewlines = publicKeyPem.replace(/\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyWithLiteralNewlines);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, privateKeyPem);
      
      expect(decrypted).toBe(message);
    });

    test('should handle keys with mixed line endings', () => {
      const message = 'Test message with mixed line endings';
      
      // Simulate key with mixed line endings
      let mixedKey = privateKeyPem.replace(/\n/g, '\r\n');
      mixedKey = mixedKey.replace(/\r\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, mixedKey);
      
      expect(decrypted).toBe(message);
    });

    test('should handle keys with extra whitespace', () => {
      const message = 'Test message with extra whitespace';
      
      // Add extra whitespace and literal newlines
      const messyKey = '  \n  ' + privateKeyPem.replace(/\n/g, '\\n') + '  \n  ';
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, messyKey);
      
      expect(decrypted).toBe(message);
    });
  });

  describe('Error Handling', () => {
    test('should throw error for invalid public key', () => {
      const message = 'Test message';
      
      expect(() => {
        encryptWithPublicKeyAESRSA(message, 'invalid-key');
      }).toThrow('Invalid public key format');
    });

    test('should throw error for invalid private key', () => {
      const message = 'Test message';
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      
      expect(() => {
        decryptWithPrivateKeyAESRSA(encrypted, 'invalid-key');
      }).toThrow('Invalid private key format');
    });

    test('should throw error for wrong algorithm', () => {
      const message = 'Test message';
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      
      // Modify the algorithm
      const wrongAlgorithm = { ...encrypted, algorithm: 'wrong-algorithm' };
      
      expect(() => {
        decryptWithPrivateKeyAESRSA(wrongAlgorithm, privateKeyPem);
      }).toThrow('Unsupported algorithm');
    });

    test('should throw error for empty message', () => {
      expect(() => {
        encryptWithPublicKeyAESRSA('', publicKeyPem);
      }).toThrow();
    });

    test('should throw error for null/undefined keys', () => {
      const message = 'Test message';
      
      expect(() => {
        encryptWithPublicKeyAESRSA(message, '');
      }).toThrow('Invalid public key');
      
      expect(() => {
        encryptWithPublicKeyAESRSA(message, null as any);
      }).toThrow('Invalid public key');
    });
  });

  describe('Type Guards', () => {
    test('should correctly identify AES-RSA encrypted messages', () => {
      const message = 'Test message';
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      
      expect(isAESRSAEncryptedMessage(encrypted)).toBe(true);
    });

    test('should reject invalid objects', () => {
      expect(isAESRSAEncryptedMessage(null)).toBe(false);
      expect(isAESRSAEncryptedMessage(undefined)).toBe(false);
      expect(isAESRSAEncryptedMessage({})).toBe(false);
      expect(isAESRSAEncryptedMessage({ algorithm: 'aes-rsa' })).toBe(false);
      expect(isAESRSAEncryptedMessage({ 
        algorithm: 'aes-rsa', 
        encryptedData: 'test' 
      })).toBe(false);
    });
  });

  describe('Security Properties', () => {
    test('should produce different encrypted data for same message', () => {
      const message = 'Test message';
      
      const encrypted1 = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const encrypted2 = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      
      // Should be different due to random IV and AES key
      expect(encrypted1.encryptedData).not.toBe(encrypted2.encryptedData);
      expect(encrypted1.encryptedKey).not.toBe(encrypted2.encryptedKey);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      
      // But both should decrypt to the same message
      const decrypted1 = decryptWithPrivateKeyAESRSA(encrypted1, privateKeyPem);
      const decrypted2 = decryptWithPrivateKeyAESRSA(encrypted2, privateKeyPem);
      
      expect(decrypted1).toBe(message);
      expect(decrypted2).toBe(message);
    });

    test('should handle different key sizes', () => {
      const message = 'Test message for different key sizes';
      
      // Test with 1024-bit key
      const keyPair1024 = crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      const encrypted = encryptWithPublicKeyAESRSA(message, keyPair1024.publicKey);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, keyPair1024.privateKey);
      
      expect(decrypted).toBe(message);
    });
  });

  describe('Real-world Scenarios', () => {
    test('should handle DIDComm message encryption', () => {
      const didcommMessage = {
        id: 'test-message-id',
        type: 'https://didcomm.org/basicmessage/2.0/message',
        from: 'did:example:alice',
        to: 'did:example:bob',
        body: {
          content: 'Hello from Alice!',
          timestamp: new Date().toISOString()
        }
      };
      
      const messageString = JSON.stringify(didcommMessage);
      const encrypted = encryptWithPublicKeyAESRSA(messageString, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, privateKeyPem);
      
      expect(JSON.parse(decrypted)).toEqual(didcommMessage);
    });

    test('should handle encrypted message with metadata', () => {
      const encryptedMessage = {
        encrypted: true,
        encryptionType: 'aes-rsa',
        encryptedData: 'base64-encrypted-data',
        encryptedKey: 'base64-encrypted-key',
        iv: 'base64-iv',
        algorithm: 'aes-rsa',
        originalMessageId: 'original-id',
        from: 'did:example:sender',
        to: 'did:example:recipient',
        timestamp: new Date().toISOString()
      };
      
      const messageString = JSON.stringify(encryptedMessage);
      const encrypted = encryptWithPublicKeyAESRSA(messageString, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, privateKeyPem);
      
      expect(JSON.parse(decrypted)).toEqual(encryptedMessage);
    });
  });
});
