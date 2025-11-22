import { describe, it, expect } from '@jest/globals';
import { 
  generateMLKEMKeyPair, 
  encryptWithMLKEM, 
  decryptWithMLKEM, 
  validateMLKEMKeyPair 
} from '../../quantum/quantumEncryption.js';

describe('ML-KEM Quantum Encryption Tests (Simple)', () => {
  describe('ML-KEM Key Generation', () => {
    it('should generate valid ML-KEM key pairs', async () => {
      const { publicKey, privateKey } = await generateMLKEMKeyPair();
      
      expect(publicKey).toBeDefined();
      expect(privateKey).toBeDefined();
      expect(publicKey).toMatch(/^[0-9a-fA-F]+$/);
      expect(privateKey).toMatch(/^[0-9a-fA-F]+$/);
      expect(publicKey.length).toBeGreaterThan(0);
      expect(privateKey.length).toBeGreaterThan(0);
    });

    it('should validate ML-KEM key pairs correctly', async () => {
      const { publicKey, privateKey } = await generateMLKEMKeyPair();
      
      expect(await validateMLKEMKeyPair(publicKey, privateKey)).toBe(true);
      expect(await validateMLKEMKeyPair(publicKey, 'invalid-key')).toBe(false);
    });
  });

  describe('ML-KEM Encryption/Decryption', () => {
    it('should encrypt and decrypt messages correctly', async () => {
      const { publicKey, privateKey } = await generateMLKEMKeyPair();
      const testMessage = 'Hello, quantum world!';
      
      const encrypted = await encryptWithMLKEM(testMessage, publicKey, privateKey);
      
      expect(encrypted).toBeDefined();
      expect(encrypted.algorithm).toBe('aes-mlkem');
      expect(encrypted.mlkemPublicKey).toBe(publicKey);
      expect(encrypted.encryptedData).toBeDefined();
      expect(encrypted.encryptedKey).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      
      const decrypted = await decryptWithMLKEM(encrypted, privateKey);
      expect(decrypted).toBe(testMessage);
    });

    it('should handle different message types', async () => {
      const { publicKey, privateKey } = await generateMLKEMKeyPair();
      
      const messages = [
        'Simple text',
        'Text with special characters: !@#$%^&*()',
        'Unicode: 🚀🌍🔐',
        JSON.stringify({ test: 'data', number: 123, boolean: true })
      ];
      
      for (const message of messages) {
        const encrypted = await encryptWithMLKEM(message, publicKey, privateKey);
        const decrypted = await decryptWithMLKEM(encrypted, privateKey);
        expect(decrypted).toBe(message);
      }
    });

    it('should handle large messages', async () => {
      const { publicKey, privateKey } = await generateMLKEMKeyPair();
      const largeMessage = 'A'.repeat(10000); // 10KB message
      
      const encrypted = await encryptWithMLKEM(largeMessage, publicKey, privateKey);
      const decrypted = await decryptWithMLKEM(encrypted, privateKey);
      
      expect(decrypted).toBe(largeMessage);
    });
  });

  describe('FIPS 203 Compliance', () => {
    it('should use correct algorithm identifier', async () => {
      const { publicKey, privateKey } = await generateMLKEMKeyPair();
      const message = 'FIPS 203 compliance test';
      
      const encrypted = await encryptWithMLKEM(message, publicKey, privateKey);
      
      expect(encrypted.algorithm).toBe('aes-mlkem');
      expect(encrypted.mlkemPublicKey).toBeDefined();
    });

    it('should maintain backward compatibility with Kyber functions', async () => {
      // Test that the old function names still work
      const { generateKyberKeyPair, encryptWithKyber, decryptWithKyber } = await import('../../quantum/quantumEncryption.js');
      
      const { publicKey, privateKey } = await generateKyberKeyPair();
      const message = 'Backward compatibility test';
      
      const encrypted = await encryptWithKyber(message, publicKey, privateKey);
      const decrypted = await decryptWithKyber(encrypted, privateKey);
      
      expect(decrypted).toBe(message);
    });
  });
});
