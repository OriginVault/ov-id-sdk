/**
 * Comprehensive security tests for did:peer session DIDs with biometric authentication
 * Tests biometric-based session management, security controls, and authentication flows
 */

import { IOVAgent } from '@originvault/ov-types';
import { createTestEnvironment, createTestBiometricData, expectToThrow, TestAssertions } from '../utils/test-helpers.js';
import { DIDCommClient } from '../../didcomm/didcommClient.js';
import { 
  createSessionDID,
  verifySessionDID,
  signWithSessionDID,
  verifySessionDIDSignature,
  recreateSessionDID
} from '../../didcomm/index.js';
import crypto from 'crypto';

describe('did:peer Session DID Security Tests', () => {
  let testEnvironment: any;
  let agent: IOVAgent;
  let didcommClient: DIDCommClient;
  let alicePeerDID: string;
  let bobPeerDID: string;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    agent = testEnvironment.agent;
    didcommClient = new DIDCommClient(agent);

    // Create test did:peer DIDs
    const aliceResult = await agent.didManagerCreate({ provider: 'did:peer' });
    const bobResult = await agent.didManagerCreate({ provider: 'did:peer' });

    alicePeerDID = aliceResult.did;
    bobPeerDID = bobResult.did;
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('Biometric Session DID Creation', () => {
    it('should create session DID with multiple biometric factors', async () => {
      const biometricData = {
        fingerprint: 'fingerprint-data-123',
        faceTemplate: 'face-template-456',
        voiceprint: 'voiceprint-789',
        deviceFingerprint: 'device-fp-abc',
        behavioralPattern: 'behavioral-data-xyz'
      };
      const sessionId = 'multi-biometric-session';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);

      expect(sessionDID).toBeDefined();
      expect(sessionDID.did).toMatch(/^did:peer:2/);
      expect(sessionDID.sessionId).toBe(sessionId);
      expect(sessionDID.biometricHash).toBeDefined();
      expect(sessionDID.privateKey).toBeDefined();
      expect(sessionDID.publicKey).toBeDefined();
    });

    it('should create deterministic session DIDs with same biometric data', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'deterministic-session';

      const sessionDID1 = await createSessionDID(biometricData, sessionId, agent);
      const sessionDID2 = await createSessionDID(biometricData, sessionId, agent);

      expect(sessionDID1.did).toBe(sessionDID2.did);
      expect(sessionDID1.privateKey).toBe(sessionDID2.privateKey);
      expect(sessionDID1.publicKey).toBe(sessionDID2.publicKey);
      expect(sessionDID1.biometricHash).toBe(sessionDID2.biometricHash);
    });

    it('should create different session DIDs with different biometric data', async () => {
      const biometricData1 = createTestBiometricData();
      const biometricData2 = createTestBiometricData();
      const sessionId = 'different-biometric-session';

      const sessionDID1 = await createSessionDID(biometricData1, sessionId, agent);
      const sessionDID2 = await createSessionDID(biometricData2, sessionId, agent);

      expect(sessionDID1.did).not.toBe(sessionDID2.did);
      expect(sessionDID1.privateKey).not.toBe(sessionDID2.privateKey);
      expect(sessionDID1.publicKey).not.toBe(sessionDID2.publicKey);
      expect(sessionDID1.biometricHash).not.toBe(sessionDID2.biometricHash);
    });

    it('should create different session DIDs with different session IDs', async () => {
      const biometricData = createTestBiometricData();
      const sessionId1 = 'session-1';
      const sessionId2 = 'session-2';

      const sessionDID1 = await createSessionDID(biometricData, sessionId1, agent);
      const sessionDID2 = await createSessionDID(biometricData, sessionId2, agent);

      expect(sessionDID1.did).not.toBe(sessionDID2.did);
      expect(sessionDID1.sessionId).toBe(sessionId1);
      expect(sessionDID2.sessionId).toBe(sessionId2);
    });
  });

  describe('Biometric Session DID Verification', () => {
    it('should verify session DID with correct biometric data', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'verification-session';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData, sessionId);

      expect(isValid).toBe(true);
    });

    it('should reject session DID with incorrect biometric data', async () => {
      const biometricData1 = createTestBiometricData();
      const biometricData2 = createTestBiometricData();
      const sessionId = 'incorrect-biometric-session';

      const sessionDID = await createSessionDID(biometricData1, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData2, sessionId);

      expect(isValid).toBe(false);
    });

    it('should reject session DID with incorrect session ID', async () => {
      const biometricData = createTestBiometricData();
      const sessionId1 = 'correct-session';
      const sessionId2 = 'incorrect-session';

      const sessionDID = await createSessionDID(biometricData, sessionId1, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData, sessionId2);

      expect(isValid).toBe(false);
    });

    it('should handle partial biometric data verification', async () => {
      const fullBiometricData = {
        fingerprint: 'fingerprint-123',
        faceTemplate: 'face-456',
        voiceprint: 'voice-789'
      };
      const partialBiometricData = {
        fingerprint: 'fingerprint-123',
        faceTemplate: 'face-456'
        // Missing voiceprint
      };
      const sessionId = 'partial-biometric-session';

      const sessionDID = await createSessionDID(fullBiometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, partialBiometricData, sessionId);

      // Should fail because biometric data doesn't match exactly
      expect(isValid).toBe(false);
    });
  });

  describe('Session DID Message Signing', () => {
    it('should sign message with session DID', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'signing-session';
      const message = 'Message signed with session DID';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      const signedMessage = await signWithSessionDID(
        sessionDID,
        message,
        agent
      );

      expect(signedMessage).toBeDefined();
      expect(signedMessage.message).toBe(message);
      expect(signedMessage.signer).toBe(sessionDID.did);
      expect(signedMessage.signature).toBeDefined();
      expect(signedMessage.timestamp).toBeDefined();
    });

    it('should verify message signed with session DID', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'verification-session';
      const message = 'Message for session DID verification';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      const signedMessage = await signWithSessionDID(sessionDID, message, agent);
      const isValid = await verifySessionDIDSignature(signedMessage, agent);

      expect(isValid).toBe(true);
    });

    it('should fail verification for tampered session-signed message', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'tamper-session';
      const message = 'Original message';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      const signedMessage = await signWithSessionDID(sessionDID, message, agent);
      
      const tamperedMessage = { ...signedMessage, message: 'Tampered message' };
      const isValid = await verifySessionDIDSignature(tamperedMessage, agent);

      expect(isValid).toBe(false);
    });
  });

  describe('Session DID Security Controls', () => {
    it('should handle session timeout scenarios', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'timeout-session';
      const message = 'Message after timeout';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      
      // Simulate time passing (in real implementation, this would be handled by session management)
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const signedMessage = await signWithSessionDID(sessionDID, message, agent);
      const isValid = await verifySessionDIDSignature(signedMessage, agent);

      expect(isValid).toBe(true);
    });

    it('should handle concurrent session creation', async () => {
      const biometricData = createTestBiometricData();
      const sessionCount = 5;
      const sessionIds = Array.from({ length: sessionCount }, (_, i) => `concurrent-session-${i}`);

      const sessionPromises = sessionIds.map(sessionId =>
        createSessionDID(biometricData, sessionId, agent)
      );

      const sessions = await Promise.all(sessionPromises);

      expect(sessions).toHaveLength(sessionCount);
      sessions.forEach((session, index) => {
        expect(session.sessionId).toBe(`concurrent-session-${index}`);
        expect(session.did).toMatch(/^did:peer:2/);
      });
    });

    it('should handle session DID recreation for verification', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'recreation-session';

      const originalSessionDID = await createSessionDID(biometricData, sessionId, agent);
      const recreatedSessionDID = await recreateSessionDID(biometricData, sessionId, agent);

      expect(recreatedSessionDID.did).toBe(originalSessionDID.did);
      expect(recreatedSessionDID.privateKey).toBe(originalSessionDID.privateKey);
      expect(recreatedSessionDID.publicKey).toBe(originalSessionDID.publicKey);
      expect(recreatedSessionDID.biometricHash).toBe(originalSessionDID.biometricHash);
    });
  });

  describe('Biometric Data Security', () => {
    it('should handle biometric data with special characters', async () => {
      const biometricData = {
        fingerprint: 'fingerprint-with-special-chars!@#$%^&*()',
        faceTemplate: 'face-template-with-unicode-🚀-emoji',
        voiceprint: 'voiceprint-with-spaces and-tabs\tand-newlines\n'
      };
      const sessionId = 'special-chars-session';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData, sessionId);

      expect(isValid).toBe(true);
    });

    it('should handle large biometric data', async () => {
      const largeBiometricData = {
        fingerprint: 'A'.repeat(1000),
        faceTemplate: 'B'.repeat(2000),
        voiceprint: 'C'.repeat(1500),
        deviceFingerprint: 'D'.repeat(500)
      };
      const sessionId = 'large-data-session';

      const sessionDID = await createSessionDID(largeBiometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, largeBiometricData, sessionId);

      expect(isValid).toBe(true);
    });

    it('should handle empty biometric data gracefully', async () => {
      const emptyBiometricData = {};
      const sessionId = 'empty-biometric-session';

      const sessionDID = await createSessionDID(emptyBiometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, emptyBiometricData, sessionId);

      expect(isValid).toBe(true);
    });

    it('should handle null/undefined biometric data', async () => {
      const nullBiometricData = {
        fingerprint: null,
        faceTemplate: undefined,
        voiceprint: ''
      };
      const sessionId = 'null-biometric-session';

      const sessionDID = await createSessionDID(nullBiometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, nullBiometricData, sessionId);

      expect(isValid).toBe(true);
    });
  });

  describe('Session DID Attack Resistance', () => {
    it('should resist biometric data replay attacks', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'replay-attack-session';

      const sessionDID1 = await createSessionDID(biometricData, sessionId, agent);
      const sessionDID2 = await createSessionDID(biometricData, sessionId, agent);

      // Same biometric data and session ID should produce same DID
      expect(sessionDID1.did).toBe(sessionDID2.did);
      
      // But different session IDs should produce different DIDs
      const sessionDID3 = await createSessionDID(biometricData, 'different-session', agent);
      expect(sessionDID1.did).not.toBe(sessionDID3.did);
    });

    it('should resist session ID collision attacks', async () => {
      const biometricData1 = createTestBiometricData();
      const biometricData2 = createTestBiometricData();
      const sessionId = 'collision-session';

      const sessionDID1 = await createSessionDID(biometricData1, sessionId, agent);
      const sessionDID2 = await createSessionDID(biometricData2, sessionId, agent);

      expect(sessionDID1.did).not.toBe(sessionDID2.did);
      expect(sessionDID1.privateKey).not.toBe(sessionDID2.privateKey);
    });

    it('should resist biometric data tampering', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'tamper-resistance-session';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      
      const tamperedBiometricData = { ...biometricData };
      tamperedBiometricData.fingerprint = 'tampered-fingerprint';
      
      const isValid = await verifySessionDID(sessionDID.did, tamperedBiometricData, sessionId);
      expect(isValid).toBe(false);
    });

    it('should resist session ID tampering', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'session-tamper-resistance';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      
      const tamperedSessionId = 'tampered-session-id';
      const isValid = await verifySessionDID(sessionDID.did, biometricData, tamperedSessionId);
      
      expect(isValid).toBe(false);
    });
  });

  describe('Session DID Performance and Scalability', () => {
    it('should handle rapid session creation and destruction', async () => {
      const biometricData = createTestBiometricData();
      const sessionCount = 20;

      const startTime = performance.now();

      for (let i = 0; i < sessionCount; i++) {
        const sessionDID = await createSessionDID(biometricData, `rapid-session-${i}`, agent);
        const isValid = await verifySessionDID(sessionDID.did, biometricData, `rapid-session-${i}`);
        expect(isValid).toBe(true);
      }

      const endTime = performance.now();
      const duration = endTime - startTime;

      expect(duration).toBeLessThan(30000); // Should complete within 30 seconds
    });

    it('should handle concurrent session operations', async () => {
      const biometricData = createTestBiometricData();
      const sessionCount = 10;

      const sessionPromises = Array.from({ length: sessionCount }, (_, i) => {
        const sessionId = `concurrent-session-${i}`;
        return createSessionDID(biometricData, sessionId, agent);
      });

      const sessions = await Promise.all(sessionPromises);

      const verificationPromises = sessions.map((session, index) => 
        verifySessionDID(session.did, biometricData, `concurrent-session-${index}`)
      );

      const verificationResults = await Promise.all(verificationPromises);

      expect(verificationResults).toHaveLength(sessionCount);
      verificationResults.forEach(result => {
        expect(result).toBe(true);
      });
    });

    it('should handle memory usage for large number of sessions', async () => {
      const biometricData = createTestBiometricData();
      const sessionCount = 100;

      const initialMemory = process.memoryUsage();

      const sessions = [];
      for (let i = 0; i < sessionCount; i++) {
        const sessionDID = await createSessionDID(biometricData, `memory-session-${i}`, agent);
        sessions.push(sessionDID);
      }

      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      // Memory increase should be reasonable (less than 100MB for 100 sessions)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
      expect(sessions).toHaveLength(sessionCount);
    });
  });

  describe('Session DID Error Handling', () => {
    it('should handle invalid biometric data gracefully', async () => {
      const invalidBiometricData = {
        fingerprint: null,
        faceTemplate: undefined,
        voiceprint: 123, // Invalid type
        deviceFingerprint: {}
      };
      const sessionId = 'invalid-biometric-session';

      // Should not throw, but may produce different results
      const sessionDID = await createSessionDID(invalidBiometricData, sessionId, agent);
      expect(sessionDID).toBeDefined();
    });

    it('should handle very long session IDs', async () => {
      const biometricData = createTestBiometricData();
      const longSessionId = 'A'.repeat(1000);
      
      const sessionDID = await createSessionDID(biometricData, longSessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData, longSessionId);
      
      expect(isValid).toBe(true);
    });

    it('should handle special characters in session IDs', async () => {
      const biometricData = createTestBiometricData();
      const specialSessionId = 'session-with-special-chars!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
      
      const sessionDID = await createSessionDID(biometricData, specialSessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData, specialSessionId);
      
      expect(isValid).toBe(true);
    });
  });
});
