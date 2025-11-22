import { DIDCommClient } from '../../didcomm/didcommClient.js';
import { 
  signMessage, 
  verifyMessageSignature,
  createSessionDID,
  verifySessionDID
} from '../../didcomm/index.js';
import { createTestEnvironment, createTestBiometricData, expectToThrow } from '../utils/test-helpers.js';

describe('DIDComm Integration Tests', () => {
  let testEnvironment: any;
  let didcommClient: DIDCommClient;
  let senderDID: string;
  let recipientDID: string;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    didcommClient = new DIDCommClient(testEnvironment.agent);
    
    // Create test DIDs
    const senderResult = await testEnvironment.agent.didManagerCreate({
      provider: 'did:key'
    });
    const recipientResult = await testEnvironment.agent.didManagerCreate({
      provider: 'did:key'
    });
    
    senderDID = senderResult.did;
    recipientDID = recipientResult.did;
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('Message Signing and Verification', () => {
    it('should sign and verify a message successfully', async () => {
      const message = 'Test message for signing';
      
      // Sign the message
      const signedMessage = await signMessage(testEnvironment.agent, message, {
        signer: senderDID
      });
      
      expect(signedMessage).toBeDefined();
      expect(signedMessage.message).toBe(message);
      expect(signedMessage.signature).toBeDefined();
      expect(signedMessage.signer).toBe(senderDID);
      expect(signedMessage.timestamp).toBeDefined();
      expect(signedMessage.messageId).toBeDefined();
      
      // Verify the signature
      const isValid = await verifyMessageSignature(testEnvironment.agent, signedMessage);
      expect(isValid).toBe(true);
    });

    it('should fail verification for tampered message', async () => {
      const message = 'Original message';
      
      const signedMessage = await signMessage(testEnvironment.agent, message, {
        signer: senderDID
      });
      
      // Tamper with the message
      const tamperedMessage = { ...signedMessage, message: 'Tampered message' };
      
      const isValid = await verifyMessageSignature(testEnvironment.agent, tamperedMessage);
      expect(isValid).toBe(false);
    });

    it('should handle messages with nonce for replay protection', async () => {
      const message = 'Message with nonce';
      
      const signedMessage = await signMessage(testEnvironment.agent, message, {
        signer: senderDID,
        includeNonce: true
      });
      
      expect(signedMessage.nonce).toBeDefined();
      expect(typeof signedMessage.nonce).toBe('string');
      
      const isValid = await verifyMessageSignature(testEnvironment.agent, signedMessage);
      expect(isValid).toBe(true);
    });
  });

  describe('DIDComm Client - Signed Messages', () => {
    it('should send a signed message successfully', async () => {
      const message = 'Test signed message';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: recipientDID,
        message: message,
        signer: senderDID,
        encrypt: false,
        storeMessage: false
      });
      
      expect(result).toBeDefined();
      expect(result.didcommMessage).toBeDefined();
      expect(result.signedMessage).toBeDefined();
      expect(result.encrypted).toBe(false);
      
      // Verify the message structure
      expect(result.didcommMessage.id).toBeDefined();
      expect(result.didcommMessage.type).toBe('https://didcomm.org/basicmessage/2.0/message');
      expect(result.didcommMessage.to).toBe(recipientDID);
      expect(result.didcommMessage.from).toBe(senderDID);
      expect(result.didcommMessage.body.content).toBe(message);
      
      // Verify signature attachment
      expect(result.didcommMessage.attachments).toBeDefined();
      expect(result.didcommMessage.attachments.length).toBe(1);
      expect(result.didcommMessage.attachments[0].id).toBe('message-signature');
    });

    it('should send an encrypted signed message', async () => {
      const message = 'Test encrypted signed message';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: recipientDID,
        message: message,
        signer: senderDID,
        encrypt: true,
        storeMessage: false
      });
      
      expect(result).toBeDefined();
      // For encrypted messages, we get the result from sendMessage
      expect(result.id).toBeDefined();
      expect(result.encryptedMessage).toBeDefined();
      expect(result.sender).toBe(senderDID);
      expect(result.recipient).toBe(recipientDID);
    });

    it('should verify a received signed message', async () => {
      const message = 'Message to verify';
      
      // Send a signed message
      const sentResult = await didcommClient.sendSignedMessage({
        recipient: recipientDID,
        message: message,
        signer: senderDID,
        encrypt: false,
        storeMessage: false
      });
      
      // Verify the received message
      const verificationResult = await didcommClient.verifyReceivedMessage(
        sentResult.didcommMessage
      );
      
      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.signedMessage).toBeDefined();
      expect(verificationResult.message).toBeDefined();
      expect(verificationResult.signer).toBe(senderDID);
    });

    it('should handle unsigned messages gracefully', async () => {
      const unsignedMessage = {
        id: 'test-message-id',
        type: 'https://didcomm.org/basicmessage/2.0/message',
        to: recipientDID,
        from: senderDID,
        body: {
          content: 'Unsigned message'
        }
      };
      
      const verificationResult = await didcommClient.verifyReceivedMessage(unsignedMessage);
      
      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.signedMessage).toBeUndefined();
      expect(verificationResult.message).toBeDefined();
      expect(verificationResult.signer).toBe(senderDID);
    });
  });

  describe('Session DID Functionality', () => {
    it('should create a session DID from biometric data', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'test-session-123';
      
      const sessionDID = await createSessionDID(
        biometricData,
        sessionId,
        testEnvironment.agent
      );
      
      expect(sessionDID).toBeDefined();
      expect(sessionDID.did).toBeDefined();
      expect(sessionDID.privateKey).toBeDefined();
      expect(sessionDID.publicKey).toBeDefined();
      expect(sessionDID.keyId).toBeDefined();
      expect(sessionDID.sessionId).toBe(sessionId);
      expect(sessionDID.biometricHash).toBeDefined();
    });

    it('should create deterministic session DIDs', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'deterministic-session';
      
      const sessionDID1 = await createSessionDID(biometricData, sessionId);
      const sessionDID2 = await createSessionDID(biometricData, sessionId);
      
      expect(sessionDID1.did).toBe(sessionDID2.did);
      expect(sessionDID1.privateKey).toBe(sessionDID2.privateKey);
      expect(sessionDID1.publicKey).toBe(sessionDID2.publicKey);
      expect(sessionDID1.biometricHash).toBe(sessionDID2.biometricHash);
    });

    it('should verify session DID origin', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'verification-session';
      
      const sessionDID = await createSessionDID(biometricData, sessionId);
      
      const isValid = await verifySessionDID(
        sessionDID.did,
        biometricData,
        sessionId
      );
      
      expect(isValid).toBe(true);
    });

    it('should reject session DID with wrong biometric data', async () => {
      const biometricData1 = createTestBiometricData();
      const biometricData2 = createTestBiometricData();
      const sessionId = 'wrong-biometric-session';
      
      const sessionDID = await createSessionDID(biometricData1, sessionId);
      
      const isValid = await verifySessionDID(
        sessionDID.did,
        biometricData2,
        sessionId
      );
      
      expect(isValid).toBe(false);
    });

    it('should reject session DID with wrong session ID', async () => {
      const biometricData = createTestBiometricData();
      const sessionId1 = 'session-1';
      const sessionId2 = 'session-2';
      
      const sessionDID = await createSessionDID(biometricData, sessionId1);
      
      const isValid = await verifySessionDID(
        sessionDID.did,
        biometricData,
        sessionId2
      );
      
      expect(isValid).toBe(false);
    });
  });

  describe('DIDComm Client - Session Signed Messages', () => {
    it('should send a session-signed message', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'session-signed-message';
      const message = 'Session signed message';
      
      const result = await didcommClient.sendSessionSignedMessage({
        recipient: recipientDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });
      
      expect(result).toBeDefined();
      expect(result.sessionDID).toBeDefined();
      expect(result.sessionDID.did).toBeDefined();
      expect(result.sessionDID.sessionId).toBe(sessionId);
      expect(result.sessionDID.keyId).toBeDefined();
    });

    it('should recreate session DID for verification', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'recreate-session';
      
      const originalSessionDID = await createSessionDID(biometricData, sessionId);
      
      const recreatedSessionDID = await didcommClient.recreateSessionDIDForVerification(
        biometricData,
        sessionId
      );
      
      expect(recreatedSessionDID.did).toBe(originalSessionDID.did);
      expect(recreatedSessionDID.privateKey).toBe(originalSessionDID.privateKey);
      expect(recreatedSessionDID.publicKey).toBe(originalSessionDID.publicKey);
    });
  });

  describe('Raw Message Operations', () => {
    it('should sign a raw message', async () => {
      const message = 'Raw message to sign';
      
      const signedMessage = await didcommClient.signRawMessage(
        message,
        senderDID,
        { messageType: 'test-message', includeNonce: true }
      );
      
      expect(signedMessage).toBeDefined();
      expect(signedMessage.message).toBe(message);
      expect(signedMessage.signer).toBe(senderDID);
      expect(signedMessage.nonce).toBeDefined();
    });

    it('should verify a raw signed message', async () => {
      const message = 'Raw message for verification';
      
      const signedMessage = await didcommClient.signRawMessage(message, senderDID);
      const isValid = await didcommClient.verifyRawMessage(signedMessage);
      
      expect(isValid).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid signer DID', async () => {
      await expectToThrow(
        () => didcommClient.sendSignedMessage({
          recipient: recipientDID,
          message: 'Test message',
          signer: 'invalid-did',
          encrypt: false
        }),
        'Error sending signed message'
      );
    });

    it('should handle invalid recipient DID', async () => {
      await expectToThrow(
        () => didcommClient.sendSignedMessage({
          recipient: 'invalid-recipient',
          message: 'Test message',
          signer: senderDID,
          encrypt: false
        }),
        'Error sending signed message'
      );
    });

    it('should handle empty message', async () => {
      await expectToThrow(
        () => didcommClient.sendSignedMessage({
          recipient: recipientDID,
          message: '',
          signer: senderDID,
          encrypt: false
        }),
        'Error sending signed message'
      );
    });
  });

  describe('Performance Tests', () => {
    it('should handle multiple concurrent message signings', async () => {
      const messages = Array.from({ length: 10 }, (_, i) => `Message ${i}`);
      
      const signingPromises = messages.map(message =>
        signMessage(testEnvironment.agent, message, { signer: senderDID })
      );
      
      const signedMessages = await Promise.all(signingPromises);
      
      expect(signedMessages).toHaveLength(10);
      signedMessages.forEach((signedMessage, index) => {
        expect(signedMessage.message).toBe(`Message ${index}`);
        expect(signedMessage.signer).toBe(senderDID);
      });
    });

    it('should handle multiple concurrent verifications', async () => {
      const message = 'Concurrent verification test';
      const signedMessage = await signMessage(testEnvironment.agent, message, {
        signer: senderDID
      });
      
      const verificationPromises = Array.from({ length: 10 }, () =>
        verifyMessageSignature(testEnvironment.agent, signedMessage)
      );
      
      const results = await Promise.all(verificationPromises);
      
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result).toBe(true);
      });
    });
  });
});