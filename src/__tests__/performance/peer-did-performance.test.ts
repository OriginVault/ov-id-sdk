/**
 * Comprehensive performance tests for did:peer operations and DIDComm messaging
 * Tests scalability, throughput, memory usage, and performance benchmarks
 */

import { IOVAgent } from '@originvault/ov-types';
import { createTestEnvironment, createTestBiometricData, PerformanceTimer, getMemoryUsage } from '../utils/test-helpers.js';
import { DIDCommClient } from '../../didcomm/didcommClient.js';
import { 
  signMessage, 
  verifyMessageSignature,
  createSessionDID,
  verifySessionDID,
  signWithSessionDID,
  verifySessionDIDSignature
} from '../../didcomm/index.js';

describe('did:peer Performance Tests', () => {
  let testEnvironment: any;
  let agent: IOVAgent;
  let didcommClient: DIDCommClient;
  let testPeerDIDs: string[] = [];

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

  describe('did:peer DID Creation Performance', () => {
    it('should create multiple did:peer DIDs efficiently', async () => {
      const didCount = 50;
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const didPromises = Array.from({ length: didCount }, () =>
        agent.didManagerCreate({ provider: 'did:peer' })
      );
      
      const results = await Promise.all(didPromises);
      
      const duration = timer.stop();
      
      expect(results).toHaveLength(didCount);
      results.forEach(result => {
        expect(result.did).toMatch(/^did:peer:2/);
        expect(result.controllerKeyId).toBeDefined();
      });
      
      // Should create 50 DIDs in less than 30 seconds
      expect(duration).toBeLessThan(30000);
      console.log(`✅ Created ${didCount} did:peer DIDs in ${duration.toFixed(2)}ms`);
      
      // Store DIDs for later tests
      testPeerDIDs = results.map(r => r.did);
    });

    it('should handle concurrent did:peer DID creation', async () => {
      const concurrentCount = 20;
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const creationPromises = Array.from({ length: concurrentCount }, (_, i) =>
        agent.didManagerCreate({ 
          provider: 'did:peer',
          alias: `concurrent-peer-${i}`
        })
      );
      
      const results = await Promise.all(creationPromises);
      
      const duration = timer.stop();
      
      expect(results).toHaveLength(concurrentCount);
      expect(duration).toBeLessThan(15000); // Should complete within 15 seconds
      console.log(`✅ Created ${concurrentCount} concurrent did:peer DIDs in ${duration.toFixed(2)}ms`);
    });

    it('should measure memory usage during DID creation', async () => {
      const initialMemory = getMemoryUsage();
      const didCount = 100;
      
      const results = [];
      for (let i = 0; i < didCount; i++) {
        const result = await agent.didManagerCreate({ provider: 'did:peer' });
        results.push(result);
        
        // Check memory every 20 DIDs
        if (i % 20 === 0) {
          const currentMemory = getMemoryUsage();
          const memoryIncrease = currentMemory.heapUsed - initialMemory.heapUsed;
          console.log(`📊 Memory after ${i + 1} DIDs: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
        }
      }
      
      const finalMemory = getMemoryUsage();
      const totalMemoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      expect(results).toHaveLength(didCount);
      expect(totalMemoryIncrease).toBeLessThan(200 * 1024 * 1024); // Less than 200MB
      console.log(`✅ Total memory increase for ${didCount} DIDs: ${(totalMemoryIncrease / 1024 / 1024).toFixed(2)}MB`);
    });
  });

  describe('did:peer Message Signing Performance', () => {
    it('should handle high-volume message signing', async () => {
      const messageCount = 200;
      const senderDID = testPeerDIDs[0];
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const signingPromises = Array.from({ length: messageCount }, (_, i) =>
        signMessage(agent, `Performance test message ${i}`, { signer: senderDID })
      );
      
      const signedMessages = await Promise.all(signingPromises);
      
      const duration = timer.stop();
      
      expect(signedMessages).toHaveLength(messageCount);
      expect(duration).toBeLessThan(30000); // Should complete within 30 seconds
      console.log(`✅ Signed ${messageCount} messages in ${duration.toFixed(2)}ms (${(messageCount / duration * 1000).toFixed(2)} msg/sec)`);
    });

    it('should handle concurrent message signing', async () => {
      const concurrentCount = 50;
      const senderDID = testPeerDIDs[0];
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const signingPromises = Array.from({ length: concurrentCount }, (_, i) =>
        signMessage(agent, `Concurrent message ${i}`, { signer: senderDID })
      );
      
      const signedMessages = await Promise.all(signingPromises);
      
      const duration = timer.stop();
      
      expect(signedMessages).toHaveLength(concurrentCount);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
      console.log(`✅ Signed ${concurrentCount} concurrent messages in ${duration.toFixed(2)}ms`);
    });

    it('should handle large message signing', async () => {
      const largeMessage = 'A'.repeat(10000); // 10KB message
      const senderDID = testPeerDIDs[0];
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const signedMessage = await signMessage(agent, largeMessage, { signer: senderDID });
      
      const duration = timer.stop();
      
      expect(signedMessage.message).toBe(largeMessage);
      expect(signedMessage.signature).toBeDefined();
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      console.log(`✅ Signed 10KB message in ${duration.toFixed(2)}ms`);
    });
  });

  describe('did:peer Message Verification Performance', () => {
    it('should handle high-volume message verification', async () => {
      const messageCount = 100;
      const senderDID = testPeerDIDs[0];
      
      // First, create signed messages
      const signedMessages = [];
      for (let i = 0; i < messageCount; i++) {
        const signedMessage = await signMessage(agent, `Verification test message ${i}`, { signer: senderDID });
        signedMessages.push(signedMessage);
      }
      
      const timer = new PerformanceTimer();
      timer.start();
      
      const verificationPromises = signedMessages.map(signedMessage =>
        verifyMessageSignature(agent, signedMessage)
      );
      
      const verificationResults = await Promise.all(verificationPromises);
      
      const duration = timer.stop();
      
      expect(verificationResults).toHaveLength(messageCount);
      verificationResults.forEach(result => expect(result).toBe(true));
      expect(duration).toBeLessThan(20000); // Should complete within 20 seconds
      console.log(`✅ Verified ${messageCount} messages in ${duration.toFixed(2)}ms (${(messageCount / duration * 1000).toFixed(2)} ver/sec)`);
    });

    it('should handle concurrent message verification', async () => {
      const concurrentCount = 30;
      const senderDID = testPeerDIDs[0];
      
      // Create a single signed message
      const signedMessage = await signMessage(agent, 'Concurrent verification test', { signer: senderDID });
      
      const timer = new PerformanceTimer();
      timer.start();
      
      const verificationPromises = Array.from({ length: concurrentCount }, () =>
        verifyMessageSignature(agent, signedMessage)
      );
      
      const verificationResults = await Promise.all(verificationPromises);
      
      const duration = timer.stop();
      
      expect(verificationResults).toHaveLength(concurrentCount);
      verificationResults.forEach(result => expect(result).toBe(true));
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      console.log(`✅ Performed ${concurrentCount} concurrent verifications in ${duration.toFixed(2)}ms`);
    });
  });

  describe('did:peer DIDComm Messaging Performance', () => {
    it('should handle high-throughput DIDComm messaging', async () => {
      const messageCount = 50;
      const senderDID = testPeerDIDs[0];
      const recipientDID = testPeerDIDs[1];
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const messagingPromises = Array.from({ length: messageCount }, (_, i) =>
        didcommClient.sendSignedMessage({
          recipient: recipientDID,
          message: `DIDComm performance test message ${i}`,
          signer: senderDID,
          encrypt: false,
          storeMessage: false
        })
      );
      
      const results = await Promise.all(messagingPromises);
      
      const duration = timer.stop();
      
      expect(results).toHaveLength(messageCount);
      expect(duration).toBeLessThan(30000); // Should complete within 30 seconds
      console.log(`✅ Sent ${messageCount} DIDComm messages in ${duration.toFixed(2)}ms (${(messageCount / duration * 1000).toFixed(2)} msg/sec)`);
    });

    it('should handle encrypted DIDComm messaging performance', async () => {
      const messageCount = 20;
      const senderDID = testPeerDIDs[0];
      const recipientDID = testPeerDIDs[1];
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const messagingPromises = Array.from({ length: messageCount }, (_, i) =>
        didcommClient.sendSignedMessage({
          recipient: recipientDID,
          message: `Encrypted DIDComm message ${i}`,
          signer: senderDID,
          encrypt: true,
          storeMessage: false
        })
      );
      
      const results = await Promise.all(messagingPromises);
      
      const duration = timer.stop();
      
      expect(results).toHaveLength(messageCount);
      expect(duration).toBeLessThan(60000); // Should complete within 60 seconds
      console.log(`✅ Sent ${messageCount} encrypted DIDComm messages in ${duration.toFixed(2)}ms`);
    });

    it('should handle message verification performance', async () => {
      const messageCount = 30;
      const senderDID = testPeerDIDs[0];
      const recipientDID = testPeerDIDs[1];
      
      // First, create messages
      const messages = [];
      for (let i = 0; i < messageCount; i++) {
        const result = await didcommClient.sendSignedMessage({
          recipient: recipientDID,
          message: `Verification test message ${i}`,
          signer: senderDID,
          encrypt: false,
          storeMessage: false
        });
        messages.push(result.didcommMessage);
      }
      
      const timer = new PerformanceTimer();
      timer.start();
      
      const verificationPromises = messages.map(message =>
        didcommClient.verifyReceivedMessage(message)
      );
      
      const verificationResults = await Promise.all(verificationPromises);
      
      const duration = timer.stop();
      
      expect(verificationResults).toHaveLength(messageCount);
      verificationResults.forEach(result => expect(result.isValid).toBe(true));
      expect(duration).toBeLessThan(20000); // Should complete within 20 seconds
      console.log(`✅ Verified ${messageCount} DIDComm messages in ${duration.toFixed(2)}ms`);
    });
  });

  describe('did:peer Session DID Performance', () => {
    it('should handle high-volume session DID creation', async () => {
      const sessionCount = 100;
      const biometricData = createTestBiometricData();
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const sessionPromises = Array.from({ length: sessionCount }, (_, i) =>
        createSessionDID(biometricData, `performance-session-${i}`, agent)
      );
      
      const sessions = await Promise.all(sessionPromises);
      
      const duration = timer.stop();
      
      expect(sessions).toHaveLength(sessionCount);
      sessions.forEach(session => {
        expect(session.did).toMatch(/^did:peer:2/);
        expect(session.biometricHash).toBeDefined();
      });
      expect(duration).toBeLessThan(45000); // Should complete within 45 seconds
      console.log(`✅ Created ${sessionCount} session DIDs in ${duration.toFixed(2)}ms (${(sessionCount / duration * 1000).toFixed(2)} sessions/sec)`);
    });

    it('should handle session DID verification performance', async () => {
      const sessionCount = 50;
      const biometricData = createTestBiometricData();
      
      // First, create sessions
      const sessions = [];
      for (let i = 0; i < sessionCount; i++) {
        const session = await createSessionDID(biometricData, `verification-session-${i}`, agent);
        sessions.push(session);
      }
      
      const timer = new PerformanceTimer();
      timer.start();
      
      const verificationPromises = sessions.map((session, index) =>
        verifySessionDID(session.did, biometricData, `verification-session-${index}`)
      );
      
      const verificationResults = await Promise.all(verificationPromises);
      
      const duration = timer.stop();
      
      expect(verificationResults).toHaveLength(sessionCount);
      verificationResults.forEach(result => expect(result).toBe(true));
      expect(duration).toBeLessThan(30000); // Should complete within 30 seconds
      console.log(`✅ Verified ${sessionCount} session DIDs in ${duration.toFixed(2)}ms`);
    });

    it('should handle session-signed message performance', async () => {
      const messageCount = 25;
      const biometricData = createTestBiometricData();
      const sessionId = 'performance-session';
      const recipientDID = testPeerDIDs[1];
      
      const sessionDID = await createSessionDID(biometricData, sessionId, agent);
      
      const timer = new PerformanceTimer();
      timer.start();
      
      const messagingPromises = Array.from({ length: messageCount }, (_, i) =>
        didcommClient.sendSessionSignedMessage({
          recipient: recipientDID,
          message: `Session-signed message ${i}`,
          biometricData: biometricData,
          sessionId: sessionId,
          encrypt: false,
          storeMessage: false
        })
      );
      
      const results = await Promise.all(messagingPromises);
      
      const duration = timer.stop();
      
      expect(results).toHaveLength(messageCount);
      expect(duration).toBeLessThan(40000); // Should complete within 40 seconds
      console.log(`✅ Sent ${messageCount} session-signed messages in ${duration.toFixed(2)}ms`);
    });
  });

  describe('did:peer Memory and Resource Management', () => {
    it('should handle memory cleanup after large operations', async () => {
      const initialMemory = getMemoryUsage();
      const operationCount = 200;
      
      // Perform many operations
      for (let i = 0; i < operationCount; i++) {
        const senderDID = testPeerDIDs[i % testPeerDIDs.length];
        const recipientDID = testPeerDIDs[(i + 1) % testPeerDIDs.length];
        
        await didcommClient.sendSignedMessage({
          recipient: recipientDID,
          message: `Memory test message ${i}`,
          signer: senderDID,
          encrypt: false,
          storeMessage: false
        });
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = getMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Memory increase should be reasonable (less than 100MB for 200 operations)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
      console.log(`✅ Memory increase for ${operationCount} operations: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
    });

    it('should handle resource cleanup for session DIDs', async () => {
      const initialMemory = getMemoryUsage();
      const sessionCount = 100;
      const biometricData = createTestBiometricData();
      
      // Create many sessions
      const sessions = [];
      for (let i = 0; i < sessionCount; i++) {
        const session = await createSessionDID(biometricData, `cleanup-session-${i}`, agent);
        sessions.push(session);
      }
      
      // Perform operations with sessions
      for (const session of sessions) {
        await signWithSessionDID(session, 'Test message', agent);
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = getMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      expect(memoryIncrease).toBeLessThan(150 * 1024 * 1024); // Less than 150MB
      console.log(`✅ Memory increase for ${sessionCount} sessions: ${(memoryIncrease / 1024 / 1024).toFixed(2)}MB`);
    });
  });

  describe('did:peer Stress Testing', () => {
    it('should handle stress test with mixed operations', async () => {
      const operationCount = 100;
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const operations = [];
      for (let i = 0; i < operationCount; i++) {
        const operationType = i % 4;
        const senderDID = testPeerDIDs[i % testPeerDIDs.length];
        const recipientDID = testPeerDIDs[(i + 1) % testPeerDIDs.length];
        
        switch (operationType) {
          case 0:
            // Message signing
            operations.push(signMessage(agent, `Stress test message ${i}`, { signer: senderDID }));
            break;
          case 1:
            // DIDComm messaging
            operations.push(didcommClient.sendSignedMessage({
              recipient: recipientDID,
              message: `Stress test DIDComm ${i}`,
              signer: senderDID,
              encrypt: false,
              storeMessage: false
            }));
            break;
          case 2:
            // Session DID creation
            operations.push(createSessionDID(createTestBiometricData(), `stress-session-${i}`, agent));
            break;
          case 3:
            // DID resolution
            operations.push(agent.resolveDid({ didUrl: senderDID }));
            break;
        }
      }
      
      const results = await Promise.all(operations);
      
      const duration = timer.stop();
      
      expect(results).toHaveLength(operationCount);
      expect(duration).toBeLessThan(120000); // Should complete within 2 minutes
      console.log(`✅ Completed ${operationCount} mixed operations in ${duration.toFixed(2)}ms`);
    });

    it('should handle concurrent stress test', async () => {
      const concurrentCount = 20;
      const timer = new PerformanceTimer();
      
      timer.start();
      
      const stressPromises = Array.from({ length: concurrentCount }, (_, i) => {
        const senderDID = testPeerDIDs[i % testPeerDIDs.length];
        const recipientDID = testPeerDIDs[(i + 1) % testPeerDIDs.length];
        
        return Promise.all([
          signMessage(agent, `Concurrent stress ${i}`, { signer: senderDID }),
          didcommClient.sendSignedMessage({
            recipient: recipientDID,
            message: `Concurrent DIDComm ${i}`,
            signer: senderDID,
            encrypt: false,
            storeMessage: false
          }),
          createSessionDID(createTestBiometricData(), `concurrent-stress-${i}`, agent)
        ]);
      });
      
      const results = await Promise.all(stressPromises);
      
      const duration = timer.stop();
      
      expect(results).toHaveLength(concurrentCount);
      expect(duration).toBeLessThan(60000); // Should complete within 1 minute
      console.log(`✅ Completed ${concurrentCount} concurrent stress operations in ${duration.toFixed(2)}ms`);
    });
  });

  describe('did:peer Benchmarking', () => {
    it('should benchmark DID creation performance', async () => {
      const benchmarkCount = 10;
      const times = [];
      
      for (let i = 0; i < benchmarkCount; i++) {
        const timer = new PerformanceTimer();
        timer.start();
        
        await agent.didManagerCreate({ provider: 'did:peer' });
        
        const duration = timer.stop();
        times.push(duration);
      }
      
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);
      
      console.log(`📊 DID Creation Benchmark:`);
      console.log(`   Average: ${avgTime.toFixed(2)}ms`);
      console.log(`   Min: ${minTime.toFixed(2)}ms`);
      console.log(`   Max: ${maxTime.toFixed(2)}ms`);
      
      expect(avgTime).toBeLessThan(5000); // Average should be less than 5 seconds
    });

    it('should benchmark message signing performance', async () => {
      const benchmarkCount = 50;
      const senderDID = testPeerDIDs[0];
      const times = [];
      
      for (let i = 0; i < benchmarkCount; i++) {
        const timer = new PerformanceTimer();
        timer.start();
        
        await signMessage(agent, `Benchmark message ${i}`, { signer: senderDID });
        
        const duration = timer.stop();
        times.push(duration);
      }
      
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);
      
      console.log(`📊 Message Signing Benchmark:`);
      console.log(`   Average: ${avgTime.toFixed(2)}ms`);
      console.log(`   Min: ${minTime.toFixed(2)}ms`);
      console.log(`   Max: ${maxTime.toFixed(2)}ms`);
      
      expect(avgTime).toBeLessThan(1000); // Average should be less than 1 second
    });

    it('should benchmark DIDComm messaging performance', async () => {
      const benchmarkCount = 20;
      const senderDID = testPeerDIDs[0];
      const recipientDID = testPeerDIDs[1];
      const times = [];
      
      for (let i = 0; i < benchmarkCount; i++) {
        const timer = new PerformanceTimer();
        timer.start();
        
        await didcommClient.sendSignedMessage({
          recipient: recipientDID,
          message: `Benchmark DIDComm ${i}`,
          signer: senderDID,
          encrypt: false,
          storeMessage: false
        });
        
        const duration = timer.stop();
        times.push(duration);
      }
      
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const minTime = Math.min(...times);
      const maxTime = Math.max(...times);
      
      console.log(`📊 DIDComm Messaging Benchmark:`);
      console.log(`   Average: ${avgTime.toFixed(2)}ms`);
      console.log(`   Min: ${minTime.toFixed(2)}ms`);
      console.log(`   Max: ${maxTime.toFixed(2)}ms`);
      
      expect(avgTime).toBeLessThan(2000); // Average should be less than 2 seconds
    });
  });
});
