import { 
  encryptWithPublicKeyAESRSA, 
  decryptWithPrivateKeyAESRSA 
} from '../../aesRsaEncryption.js';
import crypto from 'crypto';

describe('Environment Variable Key Handling Tests', () => {
  let publicKeyPem: string;
  let privateKeyPem: string;

  beforeAll(async () => {
    // Generate a test RSA key pair
    const keyPair = crypto.generateKeyPairSync('rsa', {
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

  describe('Literal \\n Character Handling', () => {
    test('should handle CHEQD_STUDIO_PRIVATE_KEY format with literal \\n', () => {
      const message = 'Test message for CHEQD_STUDIO_PRIVATE_KEY format';
      
      // Simulate the exact format from the environment variable
      // CHEQD_STUDIO_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nMII...
      const envPrivateKey = privateKeyPem.replace(/\n/g, '\\n');
      
      console.log('🔍 Testing with environment variable format:');
      console.log(`   Original key starts with: ${privateKeyPem.substring(0, 50)}...`);
      console.log(`   Env key starts with: ${envPrivateKey.substring(0, 50)}...`);
      console.log(`   Contains literal \\n: ${envPrivateKey.includes('\\n')}`);
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, envPrivateKey);
      
      expect(decrypted).toBe(message);
    });

    test('should handle real-world key format from generate-encryption-keys script', () => {
      const message = 'Test message with real-world key format';
      
      // Use the exact format from the generate-encryption-keys script
      // This simulates what you get when you copy the output from the script
      const realWorldPrivateKey = `-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCMwtnTsy9FF5aM\\n7v/6/w8VZZqt6mcyNc5rAk9Fi9QCBP8cOVKmwfcwrnzr7OUg4vScTC\\nOBFPo/6P3nCqjXRislhtlV6w\\n-----END PRIVATE KEY-----`;
      
      // Generate a matching public key for testing
      const testKeyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });
      
      console.log('🔍 Testing with real-world script format:');
      console.log(`   Key starts with: ${realWorldPrivateKey.substring(0, 50)}...`);
      console.log(`   Contains literal \\n: ${realWorldPrivateKey.includes('\\n')}`);
      
      const encrypted = encryptWithPublicKeyAESRSA(message, testKeyPair.publicKey);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, realWorldPrivateKey);
      
      expect(decrypted).toBe(message);
    });

    test('should handle keys with mixed literal and actual newlines', () => {
      const message = 'Test message with mixed newlines';
      
      // Create a key with both literal \n and actual newlines
      let mixedKey = privateKeyPem;
      // Replace some newlines with literal \n
      mixedKey = mixedKey.replace(/\n/g, (match, offset) => {
        return offset % 2 === 0 ? '\\n' : '\n';
      });
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, mixedKey);
      
      expect(decrypted).toBe(message);
    });

    test('should handle keys with Windows-style line endings in env vars', () => {
      const message = 'Test message with Windows line endings';
      
      // Simulate Windows environment variable with \r\n converted to literal \n
      const windowsKey = privateKeyPem.replace(/\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, windowsKey);
      
      expect(decrypted).toBe(message);
    });

    test('should handle keys with extra escaping', () => {
      const message = 'Test message with extra escaping';
      
      // Simulate double-escaped newlines
      const doubleEscapedKey = privateKeyPem.replace(/\n/g, '\\\\n');
      
      // This should fail with current implementation, but let's test it
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      
      expect(() => {
        decryptWithPrivateKeyAESRSA(encrypted, doubleEscapedKey);
      }).toThrow();
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty lines in PEM format', () => {
      const message = 'Test message with empty lines';
      
      // Add empty lines to the key
      const keyWithEmptyLines = privateKeyPem.replace(/\n/g, '\n\n');
      const envKeyWithEmptyLines = keyWithEmptyLines.replace(/\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, envKeyWithEmptyLines);
      
      expect(decrypted).toBe(message);
    });

    test('should handle keys with trailing whitespace', () => {
      const message = 'Test message with trailing whitespace';
      
      // Add trailing whitespace and convert to env format
      const keyWithWhitespace = privateKeyPem + '   \n  \t  ';
      const envKeyWithWhitespace = keyWithWhitespace.replace(/\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, envKeyWithWhitespace);
      
      expect(decrypted).toBe(message);
    });

    test('should handle keys with leading/trailing newlines', () => {
      const message = 'Test message with leading/trailing newlines';
      
      // Add leading and trailing newlines
      const keyWithNewlines = '\n\n' + privateKeyPem + '\n\n';
      const envKeyWithNewlines = keyWithNewlines.replace(/\n/g, '\\n');
      
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, envKeyWithNewlines);
      
      expect(decrypted).toBe(message);
    });
  });

  describe('Performance with Environment Variables', () => {
    test('should handle large messages with env format keys', () => {
      const message = 'A'.repeat(50000); // 50KB message
      
      const envPrivateKey = privateKeyPem.replace(/\n/g, '\\n');
      
      const startTime = Date.now();
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      const decrypted = decryptWithPrivateKeyAESRSA(encrypted, envPrivateKey);
      const endTime = Date.now();
      
      expect(decrypted).toBe(message);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
    });

    test('should handle multiple encryption/decryption cycles', () => {
      const message = 'Test message for multiple cycles';
      const envPrivateKey = privateKeyPem.replace(/\n/g, '\\n');
      
      const startTime = Date.now();
      
      for (let i = 0; i < 100; i++) {
        const encrypted = encryptWithPublicKeyAESRSA(message + i, publicKeyPem);
        const decrypted = decryptWithPrivateKeyAESRSA(encrypted, envPrivateKey);
        expect(decrypted).toBe(message + i);
      }
      
      const endTime = Date.now();
      expect(endTime - startTime).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });

  describe('Error Scenarios', () => {
    test('should provide clear error for malformed env key', () => {
      const message = 'Test message';
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      
      // Malformed key - missing parts
      const malformedKey = '-----BEGIN PRIVATE KEY-----\\nMII...';
      
      expect(() => {
        decryptWithPrivateKeyAESRSA(encrypted, malformedKey);
      }).toThrow();
    });

    test('should handle corrupted literal newlines', () => {
      const message = 'Test message';
      const encrypted = encryptWithPublicKeyAESRSA(message, publicKeyPem);
      
      // Corrupted literal newlines
      const corruptedKey = privateKeyPem.replace(/\n/g, '\\m'); // Wrong escape sequence
      
      expect(() => {
        decryptWithPrivateKeyAESRSA(encrypted, corruptedKey);
      }).toThrow();
    });
  });
});
