import { 
  DIDCommClient,
  signMessage,
  verifyMessageSignature,
  createSessionDID,
  verifySessionDID
} from '../../didcomm/index.js';
import { createTestEnvironment, createTestBiometricData, expectToThrow } from '../utils/test-helpers.js';

describe('DIDComm Security Tests', () => {
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

  describe('Message Signing Security', () => {
    it('should prevent message tampering', async () => {
      const originalMessage = 'Original secure message';
      
      // Sign the message
      const signedMessage = await signMessage(testEnvironment.agent, originalMessage, {
        signer: senderDID
      });
      
      // Tamper with the message
      const tamperedMessage = { ...signedMessage, message: 'Tampered message' };
      
      // Verification should fail
      const isValid = await verifyMessageSignature(testEnvironment.agent, tamperedMessage);
      expect(isValid).toBe(false);
    });

    it('should prevent signature forgery', async () => {
      const message = 'Message to forge';
      
      // Create legitimate signature
      const legitimateSignature = await signMessage(testEnvironment.agent, message, {
        signer: senderDID
      });
      
      // Create forged signature with different signer
      const forgedSignature = { ...legitimateSignature, signer: recipientDID };
      
      // Verification should fail
      const isValid = await verifyMessageSignature(testEnvironment.agent, forgedSignature);
      expect(isValid).toBe(false);
    });

    it('should prevent replay attacks with nonce', async () => {
      const message = 'Message with nonce protection';
      
      // Sign message with nonce
      const signedMessage1 = await signMessage(testEnvironment.agent, message, {
        signer: senderDID,
        includeNonce: true
      });
      
      const signedMessage2 = await signMessage(testEnvironment.agent, message, {
        signer: senderDID,
        includeNonce: true
      });
      
      // Nonces should be different
      expect(signedMessage1.nonce).not.toBe(signedMessage2.nonce);
      
      // Both should be valid
      const isValid1 = await verifyMessageSignature(testEnvironment.agent, signedMessage1);
      const isValid2 = await verifyMessageSignature(testEnvironment.agent, signedMessage2);
      
      expect(isValid1).toBe(true);
      expect(isValid2).toBe(true);
    });

    it('should validate message integrity', async () => {
      const message = 'Message integrity test';
      
      const signedMessage = await signMessage(testEnvironment.agent, message, {
        signer: senderDID
      });
      
      // Verify original message
      const isValidOriginal = await verifyMessageSignature(testEnvironment.agent, signedMessage);
      expect(isValidOriginal).toBe(true);
      
      // Corrupt signature
      const corruptedSignature = { ...signedMessage, signature: 'corrupted-signature' };
      const isValidCorrupted = await verifyMessageSignature(testEnvironment.agent, corruptedSignature);
      expect(isValidCorrupted).toBe(false);
    });

    it('should validate timestamp integrity', async () => {
      const message = 'Timestamp integrity test';
      
      const signedMessage = await signMessage(testEnvironment.agent, message, {
        signer: senderDID
      });
      
      // Verify original timestamp
      const isValidOriginal = await verifyMessageSignature(testEnvironment.agent, signedMessage);
      expect(isValidOriginal).toBe(true);
      
      // Corrupt timestamp
      const corruptedTimestamp = { ...signedMessage, timestamp: 'invalid-timestamp' };
      const isValidCorrupted = await verifyMessageSignature(testEnvironment.agent, corruptedTimestamp);
      expect(isValidCorrupted).toBe(false);
    });
  });

  describe('DIDComm Message Security', () => {
    it('should secure message attachments', async () => {
      const message = 'Message with secure attachment';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: recipientDID,
        message: message,
        signer: senderDID,
        encrypt: false,
        storeMessage: false
      });
      
      // Verify message structure
      expect(result.didcommMessage.attachments).toBeDefined();
      expect(result.didcommMessage.attachments.length).toBe(1);
      
      const attachment = result.didcommMessage.attachments[0];
      expect(attachment.id).toBe('message-signature');
      expect(attachment.data.json).toBeDefined();
      expect(attachment.data.json.signature).toBeDefined();
    });

    it('should prevent unauthorized message access', async () => {
      const message = 'Unauthorized access test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: recipientDID,
        message: message,
        signer: senderDID,
        encrypt: true,
        storeMessage: false
      });
      
      // Encrypted message should not contain plain text
      expect(result.encryptedMessage).toBeDefined();
      expect(result.encryptedMessage).not.toContain(message);
    });

    it('should validate message routing', async () => {
      const message = 'Routing validation test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: recipientDID,
        message: message,
        signer: senderDID,
        encrypt: false,
        storeMessage: false
      });
      
      // Verify routing information
      expect(result.didcommMessage.to).toBe(recipientDID);
      expect(result.didcommMessage.from).toBe(senderDID);
      expect(result.didcommMessage.id).toBeDefined();
      expect(result.didcommMessage.type).toBe('https://didcomm.org/basicmessage/2.0/message');
    });

    it('should handle message verification securely', async () => {
      const message = 'Secure verification test';
      
      // Send signed message
      const sentResult = await didcommClient.sendSignedMessage({
        recipient: recipientDID,
        message: message,
        signer: senderDID,
        encrypt: false,
        storeMessage: false
      });
      
      // Verify received message
      const verificationResult = await didcommClient.verifyReceivedMessage(
        sentResult.didcommMessage
      );
      
      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.signer).toBe(senderDID);
      expect(verificationResult.message).toBeDefined();
    });
  });

  describe('Session DID Security', () => {
    it('should create deterministic session DIDs', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'deterministic-security-test';
      
      const sessionDID1 = await createSessionDID(biometricData, sessionId);
      const sessionDID2 = await createSessionDID(biometricData, sessionId);
      
      // Should be identical
      expect(sessionDID1.did).toBe(sessionDID2.did);
      expect(sessionDID1.privateKey).toBe(sessionDID2.privateKey);
      expect(sessionDID1.publicKey).toBe(sessionDID2.publicKey);
      expect(sessionDID1.biometricHash).toBe(sessionDID2.biometricHash);
    });

    it('should prevent session DID forgery', async () => {
      const biometricData1 = createTestBiometricData();
      const biometricData2 = createTestBiometricData();
      const sessionId = 'forgery-test-session';
      
      const legitimateSessionDID = await createSessionDID(biometricData1, sessionId);
      
      // Try to verify with different biometric data
      const isValid = await verifySessionDID(
        legitimateSessionDID.did,
        biometricData2,
        sessionId
      );
      
      expect(isValid).toBe(false);
    });

    it('should prevent session ID manipulation', async () => {
      const biometricData = createTestBiometricData();
      const sessionId1 = 'session-1';
      const sessionId2 = 'session-2';
      
      const sessionDID = await createSessionDID(biometricData, sessionId1);
      
      // Try to verify with different session ID
      const isValid = await verifySessionDID(
        sessionDID.did,
        biometricData,
        sessionId2
      );
      
      expect(isValid).toBe(false);
    });

    it('should secure biometric data handling', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'biometric-security-test';
      
      const sessionDID = await createSessionDID(biometricData, sessionId);
      
      // Biometric hash should be present but not the raw data
      expect(sessionDID.biometricHash).toBeDefined();
      expect(sessionDID.biometricHash).not.toBe(biometricData.fingerprint);
      expect(sessionDID.biometricHash).not.toBe(biometricData.faceTemplate);
      
      // Session DID should be verifiable
      const isValid = await verifySessionDID(
        sessionDID.did,
        biometricData,
        sessionId
      );
      
      expect(isValid).toBe(true);
    });

    it('should handle session DID key isolation', async () => {
      const biometricData1 = createTestBiometricData();
      const biometricData2 = createTestBiometricData();
      const sessionId = 'key-isolation-test';
      
      const sessionDID1 = await createSessionDID(biometricData1, sessionId);
      const sessionDID2 = await createSessionDID(biometricData2, sessionId);
      
      // Keys should be different
      expect(sessionDID1.privateKey).not.toBe(sessionDID2.privateKey);
      expect(sessionDID1.publicKey).not.toBe(sessionDID2.publicKey);
      expect(sessionDID1.did).not.toBe(sessionDID2.did);
    });
  });

  describe('Session Signed Message Security', () => {
    it('should secure session-signed messages', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'session-signed-security-test';
      const message = 'Session signed message';
      
      const result = await didcommClient.sendSessionSignedMessage({
        recipient: recipientDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });
      
      // Verify session information
      expect(result.sessionDID).toBeDefined();
      expect(result.sessionDID.did).toBeDefined();
      expect(result.sessionDID.sessionId).toBe(sessionId);
      expect(result.sessionDID.keyId).toBeDefined();
    });

    it('should prevent session replay attacks', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'replay-attack-test';
      const message = 'Replay attack test message';
      
      // Send first message
      const result1 = await didcommClient.sendSessionSignedMessage({
        recipient: recipientDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });
      
      // Send second message with same session
      const result2 = await didcommClient.sendSessionSignedMessage({
        recipient: recipientDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });
      
      // Session DIDs should be identical (deterministic)
      expect(result1.sessionDID.did).toBe(result2.sessionDID.did);
      
      // But message IDs should be different
      expect(result1.didcommMessage.id).not.toBe(result2.didcommMessage.id);
    });

    it('should validate session DID recreation', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'recreation-test';
      
      const originalSessionDID = await createSessionDID(biometricData, sessionId);
      
      const recreatedSessionDID = await didcommClient.recreateSessionDIDForVerification(
        biometricData,
        sessionId
      );
      
      // Should be identical
      expect(recreatedSessionDID.did).toBe(originalSessionDID.did);
      expect(recreatedSessionDID.privateKey).toBe(originalSessionDID.privateKey);
      expect(recreatedSessionDID.publicKey).toBe(originalSessionDID.publicKey);
    });
  });

  describe('Raw Message Security', () => {
    it('should secure raw message signing', async () => {
      const message = 'Raw message security test';
      
      const signedMessage = await didcommClient.signRawMessage(
        message,
        senderDID,
        { messageType: 'security-test', includeNonce: true }
      );
      
      expect(signedMessage.message).toBe(message);
      expect(signedMessage.signer).toBe(senderDID);
      expect(signedMessage.nonce).toBeDefined();
      expect(signedMessage.signature).toBeDefined();
    });

    it('should validate raw message verification', async () => {
      const message = 'Raw message verification test';
      
      const signedMessage = await didcommClient.signRawMessage(message, senderDID);
      const isValid = await didcommClient.verifyRawMessage(signedMessage);
      
      expect(isValid).toBe(true);
    });

    it('should prevent raw message tampering', async () => {
      const message = 'Raw message tampering test';
      
      const signedMessage = await didcommClient.signRawMessage(message, senderDID);
      
      // Tamper with the message
      const tamperedMessage = { ...signedMessage, message: 'Tampered message' };
      
      const isValid = await didcommClient.verifyRawMessage(tamperedMessage);
      expect(isValid).toBe(false);
    });
  });

  describe('Security Error Handling', () => {
    it('should handle invalid signer gracefully', async () => {
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

    it('should handle invalid recipient gracefully', async () => {
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

    it('should handle empty message gracefully', async () => {
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

    it('should handle invalid biometric data gracefully', async () => {
      await expectToThrow(
        () => didcommClient.sendSessionSignedMessage({
          recipient: recipientDID,
          message: 'Test message',
          biometricData: {} as any,
          sessionId: 'test-session',
          encrypt: false
        }),
        'Error sending session-signed message'
      );
    });

    it('should handle invalid session ID gracefully', async () => {
      const biometricData = createTestBiometricData();
      
      await expectToThrow(
        () => didcommClient.sendSessionSignedMessage({
          recipient: recipientDID,
          message: 'Test message',
          biometricData: biometricData,
          sessionId: '',
          encrypt: false
        }),
        'Error sending session-signed message'
      );
    });
  });

  describe('Security Performance', () => {
    it('should handle concurrent security operations', async () => {
      const messages = Array.from({ length: 10 }, (_, i) => `Security test message ${i}`);
      
      const signingPromises = messages.map(message =>
        signMessage(testEnvironment.agent, message, { signer: senderDID })
      );
      
      const signedMessages = await Promise.all(signingPromises);
      
      const verificationPromises = signedMessages.map(signedMessage =>
        verifyMessageSignature(testEnvironment.agent, signedMessage)
      );
      
      const verificationResults = await Promise.all(verificationPromises);
      
      expect(signedMessages).toHaveLength(10);
      expect(verificationResults).toHaveLength(10);
      verificationResults.forEach(result => {
        expect(result).toBe(true);
      });
    });

    it('should handle concurrent session DID operations', async () => {
      const biometricData = createTestBiometricData();
      const sessionIds = Array.from({ length: 10 }, (_, i) => `concurrent-session-${i}`);
      
      const sessionDIDPromises = sessionIds.map(sessionId =>
        createSessionDID(biometricData, sessionId)
      );
      
      const sessionDIDs = await Promise.all(sessionDIDPromises);
      
      const verificationPromises = sessionDIDs.map((sessionDID, index) =>
        verifySessionDID(sessionDID.did, biometricData, sessionIds[index])
      );
      
      const verificationResults = await Promise.all(verificationPromises);
      
      expect(sessionDIDs).toHaveLength(10);
      expect(verificationResults).toHaveLength(10);
      verificationResults.forEach(result => {
        expect(result).toBe(true);
      });
    });
  });
});