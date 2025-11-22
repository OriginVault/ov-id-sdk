/**
 * Integration tests for did:peer with other DID methods
 * Tests cross-method communication, interoperability, and mixed DID scenarios
 */

import { IOVAgent } from '@originvault/ov-types';
import { createTestEnvironment, createTestBiometricData, expectToThrow, TestAssertions } from '../utils/test-helpers.js';
import { DIDCommClient } from '../../didcomm/didcommClient.js';
import { 
  signMessage, 
  verifyMessageSignature,
  createSessionDID,
  verifySessionDID
} from '../../didcomm/index.js';

describe('did:peer Cross-Method Integration Tests', () => {
  let testEnvironment: any;
  let agent: IOVAgent;
  let didcommClient: DIDCommClient;
  let peerDID: string;
  let keyDID: string;
  let cheqdTestnetDID: string;
  let cheqdMainnetDID: string;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    agent = testEnvironment.agent;
    didcommClient = new DIDCommClient(agent);

    // Create DIDs of different methods
    const peerResult = await agent.didManagerCreate({ provider: 'did:peer' });
    const keyResult = await agent.didManagerCreate({ provider: 'did:key' });
    
    peerDID = peerResult.did;
    keyDID = keyResult.did;

    // Create Cheqd DIDs if possible (may fail in test environment)
    try {
      const cheqdTestnetResult = await agent.didManagerCreate({ 
        provider: 'did:cheqd:testnet' 
      });
      cheqdTestnetDID = cheqdTestnetResult.did;
    } catch (error) {
      console.log('⚠️ Cheqd testnet DID creation failed, skipping Cheqd tests');
      cheqdTestnetDID = null;
    }

    try {
      const cheqdMainnetResult = await agent.didManagerCreate({ 
        provider: 'did:cheqd:mainnet' 
      });
      cheqdMainnetDID = cheqdMainnetResult.did;
    } catch (error) {
      console.log('⚠️ Cheqd mainnet DID creation failed, skipping Cheqd tests');
      cheqdMainnetDID = null;
    }
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('did:peer ↔ did:key Communication', () => {
    it('should send message from did:peer to did:key', async () => {
      const message = 'Message from peer to key DID';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: keyDID,
        message: message,
        signer: peerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage.to).toBe(keyDID);
      expect(result.didcommMessage.from).toBe(peerDID);
      expect(result.didcommMessage.body.content).toBe(message);
    });

    it('should send message from did:key to did:peer', async () => {
      const message = 'Message from key to peer DID';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: peerDID,
        message: message,
        signer: keyDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage.to).toBe(peerDID);
      expect(result.didcommMessage.from).toBe(keyDID);
      expect(result.didcommMessage.body.content).toBe(message);
    });

    it('should verify cross-method message signatures', async () => {
      const message = 'Cross-method signature verification';
      
      // Sign with did:peer
      const peerSignedMessage = await signMessage(agent, message, { signer: peerDID });
      const peerVerification = await verifyMessageSignature(agent, peerSignedMessage);
      expect(peerVerification).toBe(true);

      // Sign with did:key
      const keySignedMessage = await signMessage(agent, message, { signer: keyDID });
      const keyVerification = await verifyMessageSignature(agent, keySignedMessage);
      expect(keyVerification).toBe(true);
    });

    it('should handle encrypted cross-method communication', async () => {
      const message = 'Encrypted cross-method message';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: keyDID,
        message: message,
        signer: peerDID,
        encrypt: true,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.encryptedMessage).toBeDefined();
      expect(result.sender).toBe(peerDID);
      expect(result.recipient).toBe(keyDID);
    });
  });

  describe('did:peer ↔ Cheqd Communication', () => {
    it('should send message from did:peer to did:cheqd:testnet', async () => {
      if (!cheqdTestnetDID) {
        console.log('⏭️ Skipping Cheqd testnet test - DID not available');
        return;
      }

      const message = 'Message from peer to Cheqd testnet';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: cheqdTestnetDID,
        message: message,
        signer: peerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage.to).toBe(cheqdTestnetDID);
      expect(result.didcommMessage.from).toBe(peerDID);
      expect(result.didcommMessage.body.content).toBe(message);
    });

    it('should send message from did:cheqd:testnet to did:peer', async () => {
      if (!cheqdTestnetDID) {
        console.log('⏭️ Skipping Cheqd testnet test - DID not available');
        return;
      }

      const message = 'Message from Cheqd testnet to peer';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: peerDID,
        message: message,
        signer: cheqdTestnetDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.didcommMessage.to).toBe(peerDID);
      expect(result.didcommMessage.from).toBe(cheqdTestnetDID);
      expect(result.didcommMessage.body.content).toBe(message);
    });

    it('should handle encrypted communication with Cheqd DIDs', async () => {
      if (!cheqdTestnetDID) {
        console.log('⏭️ Skipping Cheqd encrypted test - DID not available');
        return;
      }

      const message = 'Encrypted message with Cheqd';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: cheqdTestnetDID,
        message: message,
        signer: peerDID,
        encrypt: true,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.encryptedMessage).toBeDefined();
      expect(result.sender).toBe(peerDID);
      expect(result.recipient).toBe(cheqdTestnetDID);
    });
  });

  describe('Multi-Method Group Communication', () => {
    it('should handle group conversation with mixed DID methods', async () => {
      const participants = [
        { did: peerDID, name: 'Alice (peer)' },
        { did: keyDID, name: 'Bob (key)' }
      ];

      if (cheqdTestnetDID) {
        participants.push({ did: cheqdTestnetDID, name: 'Charlie (cheqd)' });
      }

      const conversation = [
        { from: participants[0].did, to: participants[1].did, message: 'Hi Bob!' },
        { from: participants[1].did, to: participants[0].did, message: 'Hi Alice!' }
      ];

      if (participants.length > 2) {
        conversation.push(
          { from: participants[0].did, to: participants[2].did, message: 'Hi Charlie!' },
          { from: participants[2].did, to: participants[0].did, message: 'Hello Alice!' }
        );
      }

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

      expect(results).toHaveLength(conversation.length);
      results.forEach((result, index) => {
        expect(result.didcommMessage.from).toBe(conversation[index].from);
        expect(result.didcommMessage.to).toBe(conversation[index].to);
        expect(result.didcommMessage.body.content).toBe(conversation[index].message);
      });
    });

    it('should handle broadcast messages to multiple DID methods', async () => {
      const recipients = [keyDID];
      if (cheqdTestnetDID) {
        recipients.push(cheqdTestnetDID);
      }

      const message = 'Broadcast message to multiple DID methods';
      const results = [];

      for (const recipient of recipients) {
        const result = await didcommClient.sendSignedMessage({
          recipient: recipient,
          message: message,
          signer: peerDID,
          encrypt: false,
          storeMessage: false
        });
        results.push(result);
      }

      expect(results).toHaveLength(recipients.length);
      results.forEach(result => {
        expect(result.didcommMessage.from).toBe(peerDID);
        expect(result.didcommMessage.body.content).toBe(message);
        expect(recipients).toContain(result.didcommMessage.to);
      });
    });
  });

  describe('Cross-Method Session DIDs', () => {
    it('should create session DID and communicate with different DID methods', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'cross-method-session';
      const message = 'Session message to different DID method';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      
      const result = await didcommClient.sendSessionSignedMessage({
        recipient: keyDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.sessionDID.did).toMatch(/^did:peer:2/);
      expect(result.didcommMessage.to).toBe(keyDID);
      expect(result.didcommMessage.body.content).toBe(message);
    });

    it('should verify session DID across different DID methods', async () => {
      const biometricData = createTestBiometricData();
      const sessionId = 'cross-verification-session';

      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      const isValid = await verifySessionDID(sessionDID.did, biometricData, sessionId);

      expect(isValid).toBe(true);
      expect(sessionDID.did).toMatch(/^did:peer:2/);
    });

    it('should handle session DID communication with Cheqd DIDs', async () => {
      if (!cheqdTestnetDID) {
        console.log('⏭️ Skipping Cheqd session test - DID not available');
        return;
      }

      const biometricData = createTestBiometricData();
      const sessionId = 'cheqd-session';
      const message = 'Session message to Cheqd DID';

      const result = await didcommClient.sendSessionSignedMessage({
        recipient: cheqdTestnetDID,
        message: message,
        biometricData: biometricData,
        sessionId: sessionId,
        encrypt: false,
        storeMessage: false
      });

      expect(result).toBeDefined();
      expect(result.sessionDID.did).toMatch(/^did:peer:2/);
      expect(result.didcommMessage.to).toBe(cheqdTestnetDID);
    });
  });

  describe('Cross-Method DID Resolution', () => {
    it('should resolve did:peer DID from other DID methods', async () => {
      const resolution = await agent.resolveDid({ didUrl: peerDID });

      expect(resolution).toBeDefined();
      expect(resolution.didDocument).toBeDefined();
      expect(resolution.didDocument.id).toBe(peerDID);
      expect(resolution.didDocument.verificationMethod).toBeDefined();
    });

    it('should resolve did:key DID from did:peer context', async () => {
      const resolution = await agent.resolveDid({ didUrl: keyDID });

      expect(resolution).toBeDefined();
      expect(resolution.didDocument).toBeDefined();
      expect(resolution.didDocument.id).toBe(keyDID);
    });

    it('should resolve Cheqd DIDs from did:peer context', async () => {
      if (!cheqdTestnetDID) {
        console.log('⏭️ Skipping Cheqd resolution test - DID not available');
        return;
      }

      const resolution = await agent.resolveDid({ didUrl: cheqdTestnetDID });

      expect(resolution).toBeDefined();
      expect(resolution.didDocument).toBeDefined();
      expect(resolution.didDocument.id).toBe(cheqdTestnetDID);
    });
  });

  describe('Cross-Method Key Management', () => {
    it('should list keys from different DID methods', async () => {
      const keys = await agent.keyManagerList();

      const peerKeys = keys.filter(key => key.kid.includes('did:peer'));
      const keyKeys = keys.filter(key => key.kid.includes('did:key'));
      const cheqdKeys = keys.filter(key => key.kid.includes('did:cheqd'));

      expect(peerKeys.length).toBeGreaterThan(0);
      expect(keyKeys.length).toBeGreaterThan(0);
      
      if (cheqdTestnetDID) {
        expect(cheqdKeys.length).toBeGreaterThan(0);
      }
    });

    it('should create keys for different DID methods', async () => {
      const keyTypes = ['Ed25519', 'Secp256k1'];
      
      for (const keyType of keyTypes) {
        const key = await agent.keyManagerCreate({
          type: keyType,
          meta: {
            algorithms: [keyType]
          }
        });

        expect(key).toBeDefined();
        expect(key.type).toBe(keyType);
        expect(key.publicKeyHex).toBeDefined();
      }
    });
  });

  describe('Cross-Method Error Handling', () => {
    it('should handle invalid cross-method recipient', async () => {
      const invalidDID = 'did:invalid:test';
      
      await expectToThrow(
        () => didcommClient.sendSignedMessage({
          recipient: invalidDID,
          message: 'Test message',
          signer: peerDID,
          encrypt: false
        }),
        'Error sending signed message'
      );
    });

    it('should handle resolution failure for invalid DIDs', async () => {
      const invalidDID = 'did:invalid:test';
      
      await expectToThrow(
        () => agent.resolveDid({ didUrl: invalidDID }),
        'Error resolving DID'
      );
    });

    it('should handle cross-method signature verification failure', async () => {
      const message = 'Cross-method verification test';
      
      const signedMessage = await signMessage(agent, message, { signer: peerDID });
      
      // Tamper with the signature
      const tamperedMessage = { ...signedMessage, signature: 'tampered-signature' };
      
      const isValid = await verifyMessageSignature(agent, tamperedMessage);
      expect(isValid).toBe(false);
    });
  });

  describe('Cross-Method Performance', () => {
    it('should handle concurrent cross-method messaging', async () => {
      const messageCount = 10;
      const messages = Array.from({ length: messageCount }, (_, i) => 
        `Cross-method message ${i}`
      );

      const sendPromises = messages.map((message, index) => {
        const sender = index % 2 === 0 ? peerDID : keyDID;
        const recipient = index % 2 === 0 ? keyDID : peerDID;
        
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
        expect(result.didcommMessage.body.content).toBe(`Cross-method message ${index}`);
      });
    });

    it('should handle mixed DID method session creation', async () => {
      const biometricData = createTestBiometricData();
      const sessionCount = 5;

      const sessionPromises = Array.from({ length: sessionCount }, (_, i) => 
        createSessionDID(biometricData, `mixed-session-${i}`, agent)
      );

      const sessions = await Promise.all(sessionPromises);

      expect(sessions).toHaveLength(sessionCount);
      sessions.forEach(session => {
        expect(session.did).toMatch(/^did:peer:2/);
        expect(session.biometricHash).toBeDefined();
      });
    });
  });

  describe('Cross-Method Validation', () => {
    it('should validate DID formats across methods', () => {
      expect(TestAssertions.isValidDID(peerDID)).toBe(true);
      expect(TestAssertions.isValidDID(keyDID)).toBe(true);
      
      if (cheqdTestnetDID) {
        expect(TestAssertions.isValidDID(cheqdTestnetDID)).toBe(true);
      }
    });

    it('should validate cross-method message signatures', async () => {
      const message = 'Cross-method signature validation';
      
      const peerSigned = await signMessage(agent, message, { signer: peerDID });
      const keySigned = await signMessage(agent, message, { signer: keyDID });

      const peerValid = await verifyMessageSignature(agent, peerSigned);
      const keyValid = await verifyMessageSignature(agent, keySigned);

      expect(peerValid).toBe(true);
      expect(keyValid).toBe(true);
    });

    it('should validate cross-method message routing', async () => {
      const message = 'Routing validation test';
      
      const result = await didcommClient.sendSignedMessage({
        recipient: keyDID,
        message: message,
        signer: peerDID,
        encrypt: false,
        storeMessage: false
      });

      expect(result.didcommMessage.from).toBe(peerDID);
      expect(result.didcommMessage.to).toBe(keyDID);
      expect(result.didcommMessage.body.content).toBe(message);
    });
  });
});
