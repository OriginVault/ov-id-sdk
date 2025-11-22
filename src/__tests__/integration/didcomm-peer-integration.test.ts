/**
 * Comprehensive DIDComm integration tests for did:peer DIDs
 * Tests advanced messaging scenarios, encryption, and session management
 */

import { IOVAgent } from '@originvault/ov-types';
import { createTestEnvironment, createTestBiometricData, expectToThrow, TestAssertions } from '../utils/test-helpers.js';
import { DIDCommClient } from '../../didcomm/didcommClient.js';
import { 
  signMessage, 
  verifyMessageSignature,
  createSessionDID,
  verifySessionDID,
  signWithSessionDID,
  verifySessionDIDSignature
} from '../../didcomm/index.js';

describe('DIDComm did:peer Integration Tests', () => {
  let testEnvironment: any;
  let agent: IOVAgent;
  let didcommClient: DIDCommClient;
  let alicePeerDID: string;
  let bobPeerDID: string;
  let charliePeerDID: string;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    agent = testEnvironment.agent;
    didcommClient = new DIDCommClient(agent);

    // Create test did:peer DIDs
    const aliceResult = await agent.didManagerCreate({ provider: 'did:peer' });
    const bobResult = await agent.didManagerCreate({ provider: 'did:peer' });
    const charlieResult = await agent.didManagerCreate({ provider: 'did:peer' });

    alicePeerDID = aliceResult.did;
    bobPeerDID = bobResult.did;
    charliePeerDID = charlieResult.did;
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('did:peer Basic DIDComm Messaging', () => {
    it('should send and receive basic message between did:peer DIDs', async () => {
      const message = 'Hello from Alice to Bob via did:peer';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage).toBeDefined();
      expect(result.didcommMessage.to).toBe(bobPeerDID);
      expect(result.didcommMessage.from).toBe(alicePeerDID);
      expect(result.didcommMessage.body.content).toBe(message);
      expect(result.signedMessage).toBeDefined();
    });

    it('should send encrypted message between did:peer DIDs', async () => {
      const message = 'Secret message from Alice to Bob';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: true,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.encryptedMessage).toBeDefined();
      expect(result.sender).toBe(alicePeerDID);
      expect(result.recipient).toBe(bobPeerDID);
    });

    it('should handle message verification between did:peer DIDs', async () => {
      const message = 'Message for verification';
      
      const sentResult = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      const verificationResult = await didcommClient.verifyReceivedMessage(
        sentResult.didcommMessage
      );

      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.signedMessage).toBeDefined();
      expect(verificationResult.signer).toBe(alicePeerDID);
      expect(verificationResult.message.body.content).toBe(message);
    });
  });

  describe('did:peer Multi-Party Communication', () => {
    it('should send message from Alice to Bob and Charlie', async () => {
      const message = 'Broadcast message to multiple recipients';
      
      const aliceToBob = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      const aliceToCharlie = await didcommClient.sendSignedMessage({
        recipient: charliePeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(aliceToBob.didcommMessage.to).toBe(bobPeerDID);
      expect(aliceToCharlie.didcommMessage.to).toBe(charliePeerDID);
      expect(aliceToBob.didcommMessage.from).toBe(alicePeerDID);
      expect(aliceToCharlie.didcommMessage.from).toBe(alicePeerDID);
    });

    it('should handle group conversation with did:peer DIDs', async () => {
      const conversation = [
        { from: alicePeerDID, to: bobPeerDID, message: 'Hi Bob!' },
        { from: bobPeerDID, to: alicePeerDID, message: 'Hi Alice!' },
        { from: alicePeerDID, to: charliePeerDID, message: 'Hi Charlie!' },
        { from: charliePeerDID, to: alicePeerDID, message: 'Hello Alice!' }
      ];

      const results = [];
      for (const msg of conversation) {
        const result = await didcommClient.sendSignedMessage({
          recipient: msg.to,
          message: msg.message,
          signer: msg.from,
          encrypt: false,
          storeMessage: false
        });
        results.push(result);
      }

      expect(results).toHaveLength(4);
      results.forEach((result, index) => {
        expect(result.didcommMessage.from).toBe(conversation[index].from);
        expect(result.didcommMessage.to).toBe(conversation[index].to);
        expect(result.didcommMessage.body.content).toBe(conversation[index].message);
      });
    });
  });

  describe('did:peer Session-Based Messaging', () => {
    it('should create session DID and send session-signed message', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'alice-session-1';
      const message = 'Session-signed message from Alice';

      const result = await didcommClient.sendSessionSignedMessage({
        recipient: bobPeerDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.sessionDID).toBeDefined();
      expect(result.sessionDID.did).toMatch(/^did:peer:2/);
      expect(result.sessionDID.sessionId).toBe(sessionId);
      expect(result.didcommMessage).toBeDefined();
      expect(result.didcommMessage.body.content).toBe(message);
    });

    it('should verify session DID origin for received message', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'bob-session-1';
      const message = 'Session message for verification';

      const result = await didcommClient.sendSessionSignedMessage({
        recipient: alicePeerDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });

      const isValid = await didcommClient.verifySessionDIDOrigin(
        result.sessionDID.did,
        biometricData,
        sessionId
      );

      expect(isValid).toBe(true);
    });

    it('should recreate session DID for message verification', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'recreate-session';

      const originalSessionDID = await createSessionDID(biometricData, sessionId, agent);
      const recreatedSessionDID = await didcommClient.recreateSessionDIDForVerification(
        biometricData,
        sessionId
      );

      expect(recreatedSessionDID.did).toBe(originalSessionDID.did);
      expect(recreatedSessionDID.privateKey).toBe(originalSessionDID.privateKey);
      expect(recreatedSessionDID.publicKey).toBe(originalSessionDID.publicKey);
    });
  });

  describe('did:peer Advanced Message Types', () => {
    it('should send different message types with did:peer DIDs', async () => {
      const messageTypes = [
        'https://didcomm.org/basicmessage/2.0/message',
        'https://didcomm.org/signedmessage/1.0/message',
        'https://didcomm.org/sessionmessage/1.0/message'
      ];

      for (const messageType of messageTypes) {
        const result = await didcommClient.sendSignedMessage({
          recipient: bobPeerDID,
          message: `Message of type ${messageType}`,
          signer: alicePeerDID,
          encrypt: false,
          storeMessage: false,
          messageType: messageType
        });

        expect(result.didcommMessage.type).toBe(messageType);
      }
    });

    it('should handle message with attachments using did:peer DIDs', async () => {
      const message = 'Message with attachment';
      const attachment = {
        id: 'attachment-1',
        description: 'Test attachment',
        data: { json: { test: 'data' } }
      };

      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result.didcommMessage.attachments).toBeDefined();
      expect(result.didcommMessage.attachments.length).toBeGreaterThan(0);
      expect(result.didcommMessage.attachments[0].id).toBe('message-signature');
    });
  });

  describe('did:peer Message Routing', () => {
    it('should handle message routing through intermediate did:peer DIDs', async () => {
      // Create intermediate DID
      const intermediateResult = await agent.didManagerCreate({ provider: 'did:peer' });
      const intermediateDID = intermediateResult.did;

      const message = 'Message routed through intermediate DID';
      
      // Send from Alice to Bob via intermediate
      const aliceToIntermediate = await didcommClient.sendSignedMessage({
        recipient: intermediateDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      const intermediateToBob = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: intermediateDID,
        encrypt: false,
        storeMessage: false
      });

      expect(aliceToIntermediate.didcommMessage.to).toBe(intermediateDID);
      expect(intermediateToBob.didcommMessage.to).toBe(bobPeerDID);
      expect(intermediateToBob.didcommMessage.from).toBe(intermediateDID);
    });
  });

  describe('did:peer Error Handling and Edge Cases', () => {
    it('should handle invalid recipient did:peer DID', async () => {
      const invalidDID = 'did:peer:2.Ez6LSj8F8nfaXQ6u2yF5uJQXpUpRv7Q6mZvK6a2Y9wR8nQ3Jz.Ez6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V';
      
      await expectToThrow(
        () => didcommClient.sendSignedMessage({
          recipient: invalidDID,
          message: 'Test message',
          signer: alicePeerDID,
          encrypt: false
        }),
        'Error sending signed message'
      );
    });

    it('should handle empty message content', async () => {
      await expectToThrow(
        () => didcommClient.sendSignedMessage({
          recipient: bobPeerDID,
          message: '',
          signer: alicePeerDID,
          encrypt: false
        }),
        'Error sending signed message'
      );
    });

    it('should handle very long message content', async () => {
      const longMessage = 'A'.repeat(10000); // 10KB message
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: longMessage,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result.didcommMessage.body.content).toBe(longMessage);
    });

    it('should handle special characters in message content', async () => {
      const specialMessage = 'Message with special chars: !@#$%^&*()_+-=[]{}|;:,.<>?/~`';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: specialMessage,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result.didcommMessage.body.content).toBe(specialMessage);
    });
  });

  describe('did:peer Performance and Scalability', () => {
    it('should handle multiple concurrent messages between did:peer DIDs', async () => {
      const messageCount = 20;
      const messages = Array.from({ length: messageCount }, (_, i) => 
        `Concurrent message ${i}`
      );

      const sendPromises = messages.map((message, index) => {
        const sender = index % 2 === 0 ? alicePeerDID : bobPeerDID;
        const recipient = index % 2 === 0 ? bobPeerDID : alicePeerDID;
        
        return didcommClient.sendSignedMessage({
          recipient: recipient,
          message: message,
          signer: sender,
          encrypt: false,
          storeMessage: false
        });
      });

      const results = await Promise.all(sendPromises);

      expect(results).toHaveLength(messageCount);
      results.forEach((result, index) => {
        expect(result.didcommMessage.body.content).toBe(`Concurrent message ${index}`);
      });
    });

    it('should handle rapid session DID creation and messaging', async () => {
      const sessionCount = 10;
      const biometricData = createTestBiometricData();

      const sessionPromises = Array.from({ length: sessionCount }, (_, i) => 
        createSessionDID(biometricData, `rapid-session-${i}`, agent)
      );

      const sessions = await Promise.all(sessionPromises);

      expect(sessions).toHaveLength(sessionCount);
      sessions.forEach((session, index) => {
        expect(session.sessionId).toBe(`rapid-session-${index}`);
        expect(session.did).toMatch(/^did:peer:2/);
      });
    });

    it('should handle message signing performance with did:peer DIDs', async () => {
      const messageCount = 50;
      const messages = Array.from({ length: messageCount }, (_, i) => 
        `Performance test message ${i}`
      );

      const startTime = performance.now();

      const signingPromises = messages.map(message =>
        signMessage(agent, message, { signer: alicePeerDID })
      );

      const signedMessages = await Promise.all(signingPromises);

      const endTime = performance.now();
      const duration = endTime - startTime;

      expect(signedMessages).toHaveLength(messageCount);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });

  describe('did:peer Security and Validation', () => {
    it('should validate did:peer DID format in messages', async () => {
      const message = 'DID format validation test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(TestAssertions.isValidDID(result.didcommMessage.from)).toBe(true);
      expect(TestAssertions.isValidDID(result.didcommMessage.to)).toBe(true);
      expect(result.didcommMessage.from).toMatch(/^did:peer:2/);
      expect(result.didcommMessage.to).toMatch(/^did:peer:2/);
    });

    it('should validate signature integrity for did:peer messages', async () => {
      const message = 'Signature integrity test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      const verificationResult = await didcommClient.verifyReceivedMessage(
        result.didcommMessage
      );

      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.signedMessage).toBeDefined();
      expect(verificationResult.signedMessage.signature).toBeDefined();
    });

    it('should handle signature tampering detection', async () => {
      const message = 'Tampering detection test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      // Tamper with the signature
      const tamperedMessage = { ...result.didcommMessage };
      tamperedMessage.attachments[0].data.json.signature = 'tampered-signature';

      const verificationResult = await didcommClient.verifyReceivedMessage(
        tamperedMessage
      );

      expect(verificationResult.isValid).toBe(false);
    });

    it('should validate timestamp freshness for did:peer messages', async () => {
      const message = 'Timestamp validation test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: false
      });

      const timestamp = result.signedMessage.timestamp;
      expect(TestAssertions.isValidTimestamp(timestamp)).toBe(true);
      
      const messageTime = new Date(timestamp).getTime();
      const now = Date.now();
      const timeDiff = now - messageTime;
      
      expect(timeDiff).toBeLessThan(60000); // Message should be less than 1 minute old
    });
  });

  describe('did:peer Message Persistence and Storage', () => {
    it('should handle message storage with did:peer DIDs', async () => {
      const message = 'Stored message test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: true
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage).toBeDefined();
      // Note: Actual storage verification would depend on the storage implementation
    });

    it('should handle message retrieval and verification', async () => {
      const message = 'Retrieval test message';
      
      const sentResult = await didcommClient.sendSignedMessage({
        recipient: bobPeerDID,
        message: message,
        signer: alicePeerDID,
        encrypt: false,
        storeMessage: true
      });

      // Simulate message retrieval and verification
      const verificationResult = await didcommClient.verifyReceivedMessage(
        sentResult.didcommMessage
      );

      expect(verificationResult.isValid).toBe(true);
      expect(verificationResult.message.body.content).toBe(message);
    });
  });
});
