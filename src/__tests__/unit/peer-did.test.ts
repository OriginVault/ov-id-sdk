/**
 * Comprehensive tests for did:peer functionality
 * Tests DID creation, resolution, key management, and basic operations
 */

import { IOVAgent } from '@originvault/ov-types';
import { createTestEnvironment, createMockCredentials, expectToThrow, TestAssertions } from '../utils/test-helpers.js';
import { DIDCommClient } from '../../didcomm/didcommClient.js';
import { signMessage, verifyMessageSignature, createSessionDID, verifySessionDID } from '../../didcomm/index.js';

describe('did:peer Tests', () => {
  let testEnvironment: any;
  let agent: IOVAgent;
  let didcommClient: DIDCommClient;
  let peerDID1: string;
  let peerDID2: string;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    agent = testEnvironment.agent;
    didcommClient = new DIDCommClient(agent);
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('did:peer DID Creation', () => {
    it('should create a did:peer DID successfully', async () => {
      const result = await agent.didManagerCreate({
        provider: 'did:peer'
      });

      expect(result).toBeDefined();
      expect(result.did).toMatch(/^did:peer:2/);
      expect(result.controllerKeyId).toBeDefined();
      expect(result.keys).toBeDefined();
      expect(result.keys.length).toBeGreaterThan(0);

      peerDID1 = result.did;
    });

    it('should create multiple did:peer DIDs with different keys', async () => {
      const result1 = await agent.didManagerCreate({
        provider: 'did:peer'
      });
      const result2 = await agent.didManagerCreate({
        provider: 'did:peer'
      });

      expect(result1.did).not.toBe(result2.did);
      expect(result1.controllerKeyId).not.toBe(result2.controllerKeyId);
      expect(result1.keys[0].publicKeyHex).not.toBe(result2.keys[0].publicKeyHex);

      peerDID2 = result2.did;
    });

    it('should create did:peer DID with specific alias', async () => {
      const alias = 'test-peer-did';
      const result = await agent.didManagerCreate({
        provider: 'did:peer',
        alias
      });

      expect(result.alias).toBe(alias);
      expect(result.did).toMatch(/^did:peer:2/);
    });

    it('should handle did:peer creation with key options', async () => {
      const result = await agent.didManagerCreate({
        provider: 'did:peer',
        options: {
          keyType: 'Ed25519'
        }
      });

      expect(result).toBeDefined();
      expect(result.did).toMatch(/^did:peer:2/);
      expect(result.keys[0].type).toBe('Ed25519');
    });
  });

  describe('did:peer DID Resolution', () => {
    it('should resolve a did:peer DID successfully', async () => {
      const resolution = await agent.resolveDid({ didUrl: peerDID1 });

      expect(resolution).toBeDefined();
      expect(resolution.didDocument).toBeDefined();
      expect(resolution.didDocument.id).toBe(peerDID1);
      expect(resolution.didDocument.verificationMethod).toBeDefined();
      expect(resolution.didDocument.verificationMethod.length).toBeGreaterThan(0);
    });

    it('should resolve did:peer DID with proper verification methods', async () => {
      const resolution = await agent.resolveDid({ didUrl: peerDID1 });
      const didDoc = resolution.didDocument;

      expect(didDoc.verificationMethod).toBeDefined();
      expect(didDoc.verificationMethod.length).toBeGreaterThan(0);

      const vm = didDoc.verificationMethod[0];
      expect(vm.id).toBeDefined();
      expect(vm.type).toBeDefined();
      expect(vm.controller).toBe(peerDID1);
      expect(vm.publicKeyMultibase).toBeDefined();
    });

    it('should resolve did:peer DID with key agreement methods', async () => {
      const resolution = await agent.resolveDid({ didUrl: peerDID1 });
      const didDoc = resolution.didDocument;

      expect(didDoc.keyAgreement).toBeDefined();
      expect(didDoc.keyAgreement.length).toBeGreaterThan(0);
    });

    it('should handle resolution of non-existent did:peer DID', async () => {
      const fakeDID = 'did:peer:2.Ez6LSj8F8nfaXQ6u2yF5uJQXpUpRv7Q6mZvK6a2Y9wR8nQ3Jz.Ez6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V';
      
      await expectToThrow(
        () => agent.resolveDid({ didUrl: fakeDID }),
        'Error resolving DID'
      );
    });
  });

  describe('did:peer Key Management', () => {
    it('should list keys for did:peer DID', async () => {
      const keys = await agent.keyManagerList();

      const peerKeys = keys.filter(key => 
        key.meta?.algorithms?.includes('Ed25519') && 
        key.kid.includes('did:peer')
      );

      expect(peerKeys.length).toBeGreaterThan(0);
    });

    it('should get specific key for did:peer DID', async () => {
      const keys = await agent.keyManagerList();
      const peerKey = keys.find(key => key.kid.includes(peerDID1));

      expect(peerKey).toBeDefined();
      expect(peerKey.kid).toBeDefined();
      expect(peerKey.type).toBe('Ed25519');
      expect(peerKey.publicKeyHex).toBeDefined();
    });

    it('should create additional keys for did:peer DID', async () => {
      const newKey = await agent.keyManagerCreate({
        type: 'Ed25519',
        meta: {
          algorithms: ['Ed25519']
        }
      });

      expect(newKey).toBeDefined();
      expect(newKey.kid).toBeDefined();
      expect(newKey.type).toBe('Ed25519');
      expect(newKey.publicKeyHex).toBeDefined();
    });
  });

  describe('did:peer Message Signing', () => {
    it('should sign a message with did:peer DID', async () => {
      const message = 'Test message for did:peer signing';
      
      const signedMessage = await signMessage(agent, message, {
        signer: peerDID1
      });

      expect(signedMessage).toBeDefined();
      expect(signedMessage.message).toBe(message);
      expect(signedMessage.signer).toBe(peerDID1);
      expect(signedMessage.signature).toBeDefined();
      expect(signedMessage.timestamp).toBeDefined();
      expect(signedMessage.messageId).toBeDefined();
    });

    it('should verify a message signed with did:peer DID', async () => {
      const message = 'Verification test message';
      
      const signedMessage = await signMessage(agent, message, {
        signer: peerDID1
      });

      const isValid = await verifyMessageSignature(agent, signedMessage);
      expect(isValid).toBe(true);
    });

    it('should fail verification for tampered did:peer signed message', async () => {
      const message = 'Original message';
      
      const signedMessage = await signMessage(agent, message, {
        signer: peerDID1
      });

      const tamperedMessage = { ...signedMessage, message: 'Tampered message' };
      const isValid = await verifyMessageSignature(agent, tamperedMessage);
      
      expect(isValid).toBe(false);
    });

    it('should sign message with nonce for replay protection', async () => {
      const message = 'Message with nonce';
      
      const signedMessage = await signMessage(agent, message, {
        signer: peerDID1,
        includeNonce: true
      });

      expect(signedMessage.nonce).toBeDefined();
      expect(typeof signedMessage.nonce).toBe('string');
      
      const isValid = await verifyMessageSignature(agent, signedMessage);
      expect(isValid).toBe(true);
    });
  });

  describe('did:peer DIDComm Messaging', () => {
    it('should send signed message between did:peer DIDs', async () => {
      const message = 'Test message between peer DIDs';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: peerDID2,
        message: message,
        signer: peerDID1,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage).toBeDefined();
      expect(result.signedMessage).toBeDefined();
      expect(result.didcommMessage.to).toBe(peerDID2);
      expect(result.didcommMessage.from).toBe(peerDID1);
    });

    it('should send encrypted signed message between did:peer DIDs', async () => {
      const message = 'Encrypted message between peer DIDs';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: peerDID2,
        message: message,
        signer: peerDID1,
        encrypt: true,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.encryptedMessage).toBeDefined();
      expect(result.sender).toBe(peerDID1);
      expect(result.recipient).toBe(peerDID2);
    });

    it('should verify received signed message from did:peer DID', async () => {
      const message = 'Message to verify';
      
      const sentResult = await didcommClient.sendSignedMessage({
        recipient: peerDID2,
        message: message,
        signer: peerDID1,
        encrypt: false,
        storeMessage: false
      });

      const verificationResult = await didcommClient.verifyReceivedMessage(
        sentResult.didcommMessage
      );

      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.signedMessage).toBeDefined();
      expect(verificationResult.signer).toBe(peerDID1);
    });
  });

  describe('did:peer Session DIDs', () => {
    it('should create session DID from biometric data using did:peer', async () => {
      const biometricData = {
        fingerprint: 'test-fingerprint-123',
        faceTemplate: 'test-face-template-456',
        deviceFingerprint: 'test-device-789'
      };
      const sessionId = 'test-session-peer';

      const sessionDID = await createSessionDID(
        biometricData,
        sessionId,
        agent
      );

      expect(sessionDID).toBeDefined();
      expect(sessionDID.did).toMatch(/^did:peer:2/);
      expect(sessionDID.sessionId).toBe(sessionId);
      expect(sessionDID.biometricHash).toBeDefined();
      expect(sessionDID.privateKey).toBeDefined();
      expect(sessionDID.publicKey).toBeDefined();
    });

    it('should create deterministic session DIDs with did:peer', async () => {
      const biometricData = {
        fingerprint: 'deterministic-fingerprint',
        faceTemplate: 'deterministic-face'
      };
      const sessionId = 'deterministic-session-peer';

      const sessionDID1 = await createSessionDID(biometricData, sessionId, agent);
      const sessionDID2 = await createSessionDID(biometricData, sessionId, agent);

      expect(sessionDID1.did).toBe(sessionDID2.did);
      expect(sessionDID1.privateKey).toBe(sessionDID2.privateKey);
      expect(sessionDID1.publicKey).toBe(sessionDID2.publicKey);
      expect(sessionDID1.biometricHash).toBe(sessionDID2.biometricHash);
    });

    it('should verify session DID origin with did:peer', async () => {
      const biometricData = {
        fingerprint: 'verification-fingerprint',
        faceTemplate: 'verification-face'
      };
      const sessionId = 'verification-session-peer';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData, sessionId);

      expect(isValid).toBe(true);
    });

    it('should reject session DID with wrong biometric data', async () => {
      const biometricData1 = {
        fingerprint: 'correct-fingerprint',
        faceTemplate: 'correct-face'
      };
      const biometricData2 = {
        fingerprint: 'wrong-fingerprint',
        faceTemplate: 'wrong-face'
      };
      const sessionId = 'wrong-biometric-session';

      const sessionDID = await createSessionDID(biometricData1, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData2, sessionId);

      expect(isValid).toBe(false);
    });
  });

  describe('did:peer Cross-Method Communication', () => {
    let keyDID: string;

    beforeAll(async () => {
      // Create a did:key DID for cross-method testing
      const keyResult = await agent.didManagerCreate({
        provider: 'did:key'
      });
      keyDID = keyResult.did;
    });

    it('should send message from did:peer to did:key', async () => {
      const message = 'Cross-method message from peer to key';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: keyDID,
        message: message,
        signer: peerDID1,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage.to).toBe(keyDID);
      expect(result.didcommMessage.from).toBe(peerDID1);
    });

    it('should send message from did:key to did:peer', async () => {
      const message = 'Cross-method message from key to peer';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: peerDID1,
        message: message,
        signer: keyDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage.to).toBe(peerDID1);
      expect(result.didcommMessage.from).toBe(keyDID);
    });
  });

  describe('did:peer Error Handling', () => {
    it('should handle invalid did:peer DID format', async () => {
      const invalidDID = 'did:peer:invalid-format';
      
      await expectToThrow(
        () => agent.resolveDid({ didUrl: invalidDID }),
        'Error resolving DID'
      );
    });

    it('should handle signing with non-existent did:peer DID', async () => {
      const fakeDID = 'did:peer:2.Ez6LSj8F8nfaXQ6u2yF5uJQXpUpRv7Q6mZvK6a2Y9wR8nQ3Jz.Ez6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V';
      
      await expectToThrow(
        () => signMessage(agent, 'Test message', { signer: fakeDID }),
        'Error signing message'
      );
    });

    it('should handle empty message signing', async () => {
      await expectToThrow(
        () => signMessage(agent, '', { signer: peerDID1 }),
        'Error signing message'
      );
    });
  });

  describe('did:peer Performance Tests', () => {
    it('should handle multiple concurrent did:peer DID creations', async () => {
      const creationPromises = Array.from({ length: 5 }, () =>
        agent.didManagerCreate({ provider: 'did:peer' })
      );

      const results = await Promise.all(creationPromises);

      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result.did).toMatch(/^did:peer:2/);
        expect(result.controllerKeyId).toBeDefined();
      });
    });

    it('should handle multiple concurrent message signings with did:peer', async () => {
      const messages = Array.from({ length: 10 }, (_, i) => `Message ${i}`);
      
      const signingPromises = messages.map(message =>
        signMessage(agent, message, { signer: peerDID1 })
      );

      const signedMessages = await Promise.all(signingPromises);

      expect(signedMessages).toHaveLength(10);
      signedMessages.forEach((signedMessage, index) => {
        expect(signedMessage.message).toBe(`Message ${index}`);
        expect(signedMessage.signer).toBe(peerDID1);
      });
    });

    it('should handle multiple concurrent verifications', async () => {
      const message = 'Concurrent verification test';
      const signedMessage = await signMessage(agent, message, { signer: peerDID1 });

      const verificationPromises = Array.from({ length: 10 }, () =>
        verifyMessageSignature(agent, signedMessage)
      );

      const results = await Promise.all(verificationPromises);

      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result).toBe(true);
      });
    });
  });

  describe('did:peer Validation Tests', () => {
    it('should validate did:peer DID format', () => {
      expect(TestAssertions.isValidDID(peerDID1)).toBe(true);
      expect(peerDID1).toMatch(/^did:peer:2/);
    });

    it('should validate did:peer signature format', async () => {
      const message = 'Signature format test';
      const signedMessage = await signMessage(agent, message, { signer: peerDID1 });

      expect(signedMessage.signature).toBeDefined();
      expect(typeof signedMessage.signature).toBe('string');
      expect(signedMessage.signature.length).toBeGreaterThan(0);
    });

    it('should validate did:peer timestamp format', async () => {
      const message = 'Timestamp format test';
      const signedMessage = await signMessage(agent, message, { signer: peerDID1 });

      expect(TestAssertions.isValidTimestamp(signedMessage.timestamp)).toBe(true);
    });

    it('should validate did:peer message ID format', async () => {
      const message = 'Message ID format test';
      const signedMessage = await signMessage(agent, message, { signer: peerDID1 });

      expect(signedMessage.messageId).toBeDefined();
      expect(typeof signedMessage.messageId).toBe('string');
      expect(signedMessage.messageId.length).toBeGreaterThan(0);
    });
  });
});
