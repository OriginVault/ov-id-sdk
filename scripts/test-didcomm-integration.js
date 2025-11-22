import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.js';
import { createDID } from '../src/identityManager.js';
import { DIDCommClient } from '../src/didcomm/didcommClient.js';

dotenv.config();

(async () => {
  console.log('🧪 Testing Complete DIDComm Integration...');
  console.log('   📋 Testing: UI → Server → Recipient message flow with signatures');
  
  const { agent } = await packageStore.initialize();
  
  try {
    // Simulate the three-party architecture
    console.log('🔄 Setting up test scenario...');
    
    // 1. Create UI Session DID (simulating biometric authentication)
    const mockBiometricData = {
      fingerprint: 'user_fingerprint_abc123',
      faceTemplate: 'face_embedding_xyz789',
      deviceFingerprint: navigator?.userAgent || 'test_device_fingerprint',
      timestamp: Date.now()
    };
    
    const sessionId = `ui_session_${Date.now()}`;
    
    // 2. Create Server DID (main/chosen DID)
    const serverDID = await createDID({
      method: 'key',
      agent,
      alias: 'server_main_did'
    });
    
    // 3. Create Recipient DID
    const recipientDID = await createDID({
      method: 'key',
      agent,
      alias: 'recipient_user_did'
    });
    
    console.log('✅ Test setup complete:');
    console.log(`   📱 Session ID: ${sessionId}`);
    console.log(`   🖥️  Server DID: ${serverDID.did.did}`);
    console.log(`   👤 Recipient DID: ${recipientDID.did.did}`);
    
    // Initialize DIDComm client
    const didcommClient = new DIDCommClient(agent);
    
    // === STEP 1: UI → Server (Session DID signs message) ===
    console.log('\n🔄 STEP 1: UI → Server (Session DID signature)');
    
    const uiMessage = {
      type: 'user_message',
      content: 'Hello, please send this message to the recipient',
      recipient: recipientDID.did.did,
      metadata: {
        userAgent: 'OV-Public-Utility-Tool/1.0',
        timestamp: new Date().toISOString()
      }
    };
    
    // UI sends message signed with session DID
    const uiToServerMessage = await didcommClient.sendSessionSignedMessage({
      recipient: serverDID.did.did,
      message: JSON.stringify(uiMessage),
      biometricData: mockBiometricData,
      sessionId: sessionId,
      encrypt: false,
      messageType: 'ui-to-server-request'
    });
    
    console.log('✅ UI → Server message created:');
    console.log(`   🆔 Session DID: ${uiToServerMessage.sessionDID.did}`);
    console.log(`   📝 Message type: ui-to-server-request`);
    
    // === STEP 2: Server verifies UI message ===
    console.log('\n🔄 STEP 2: Server verifies UI message');
    
    const uiMessageVerification = await didcommClient.verifyReceivedMessage(
      uiToServerMessage.didcommMessage
    );
    
    console.log('✅ UI message verification:');
    console.log(`   🔍 Is Valid: ${uiMessageVerification.isValid ? 'YES ✓' : 'NO ✗'}`);
    console.log(`   🆔 Signer: ${uiMessageVerification.signer}`);
    console.log(`   ⏰ Timestamp: ${uiMessageVerification.signedMessage?.timestamp}`);
    
    if (!uiMessageVerification.isValid) {
      console.error('❌ UI message verification failed!');
      process.exit(1);
    }
    
    // Server verifies the session DID was created from biometrics
    const sessionDIDVerification = await didcommClient.verifySessionDIDOrigin(
      uiMessageVerification.signer!,
      mockBiometricData,
      sessionId
    );
    
    console.log(`   🔒 Session DID biometric verification: ${sessionDIDVerification ? 'VALID ✓' : 'INVALID ✗'}`);
    
    if (!sessionDIDVerification) {
      console.error('❌ Session DID biometric verification failed!');
      process.exit(1);
    }
    
    // === STEP 3: Server → Recipient (Server DID signs message) ===
    console.log('\n🔄 STEP 3: Server → Recipient (Server DID signature)');
    
    // Parse the original UI message
    const parsedUIMessage = JSON.parse(uiMessageVerification.signedMessage!.message);
    const originalContent = JSON.parse(parsedUIMessage).content;
    
    // Server forwards the message, signed with its own DID
    const serverToRecipientMessage = await didcommClient.sendSignedMessage({
      recipient: recipientDID.did.did,
      message: originalContent,
      signer: serverDID.did.did,
      encrypt: false,
      messageType: 'server-forwarded-message'
    });
    
    console.log('✅ Server → Recipient message created:');
    console.log(`   🆔 Server DID: ${serverDID.did.did}`);
    console.log(`   👤 Recipient: ${recipientDID.did.did}`);
    console.log(`   📝 Message: ${originalContent.substring(0, 50)}...`);
    
    // === STEP 4: Recipient verifies server message ===
    console.log('\n🔄 STEP 4: Recipient verifies server message');
    
    const serverMessageVerification = await didcommClient.verifyReceivedMessage(
      serverToRecipientMessage.didcommMessage
    );
    
    console.log('✅ Server message verification:');
    console.log(`   🔍 Is Valid: ${serverMessageVerification.isValid ? 'YES ✓' : 'NO ✗'}`);
    console.log(`   🆔 Signer: ${serverMessageVerification.signer}`);
    console.log(`   ⏰ Timestamp: ${serverMessageVerification.signedMessage?.timestamp}`);
    
    if (!serverMessageVerification.isValid) {
      console.error('❌ Server message verification failed!');
      process.exit(1);
    }
    
    // === STEP 5: End-to-end verification ===
    console.log('\n🔄 STEP 5: End-to-end chain of trust verification');
    
    // Verify the complete chain: UI Session DID → Server DID → Recipient
    const chainOfTrust = {
      uiSessionDID: uiMessageVerification.signer,
      serverDID: serverMessageVerification.signer,
      recipientDID: recipientDID.did.did,
      originalMessage: originalContent,
      deliveredMessage: serverMessageVerification.signedMessage?.message,
      uiTimestamp: uiMessageVerification.signedMessage?.timestamp,
      serverTimestamp: serverMessageVerification.signedMessage?.timestamp
    };
    
    const messageIntegrity = chainOfTrust.originalMessage === chainOfTrust.deliveredMessage;
    
    console.log('✅ Chain of Trust Analysis:');
    console.log(`   📱 UI Session DID: ${chainOfTrust.uiSessionDID?.substring(0, 20)}...`);
    console.log(`   🖥️  Server DID: ${chainOfTrust.serverDID?.substring(0, 20)}...`);
    console.log(`   👤 Recipient DID: ${chainOfTrust.recipientDID.substring(0, 20)}...`);
    console.log(`   🔗 Message Integrity: ${messageIntegrity ? 'PRESERVED ✓' : 'COMPROMISED ✗'}`);
    console.log(`   ⏰ UI Timestamp: ${chainOfTrust.uiTimestamp}`);
    console.log(`   ⏰ Server Timestamp: ${chainOfTrust.serverTimestamp}`);
    
    if (!messageIntegrity) {
      console.error('❌ Message integrity check failed!');
      process.exit(1);
    }
    
    // === STEP 6: Test replay attack protection ===
    console.log('\n🔄 STEP 6: Testing replay attack protection');
    
    // Try to replay the UI message
    console.log('   🔄 Attempting to replay UI message...');
    const replayVerification = await didcommClient.verifyReceivedMessage(
      uiToServerMessage.didcommMessage
    );
    
    // In a full implementation, you'd check timestamps and nonces
    console.log(`   🔍 Replay message verification: ${replayVerification.isValid ? 'VALID (check timestamps!)' : 'INVALID'}`);
    console.log('   ℹ️ Note: Timestamp-based replay protection would be implemented in production');
    
    // === FINAL RESULTS ===
    console.log('\n🎉 COMPLETE DIDComm INTEGRATION TEST RESULTS:');
    console.log('   ✅ UI Session DID creation from biometrics: PASSED');
    console.log('   ✅ UI → Server message signing: PASSED');
    console.log('   ✅ Server verification of UI signature: PASSED');
    console.log('   ✅ Server biometric verification of session DID: PASSED');
    console.log('   ✅ Server → Recipient message signing: PASSED');
    console.log('   ✅ Recipient verification of server signature: PASSED');
    console.log('   ✅ End-to-end message integrity: PASSED');
    console.log('   ✅ Chain of trust establishment: PASSED');
    
    console.log('\n📋 ARCHITECTURE VERIFICATION:');
    console.log('   🏗️  UI (Session DID) → Server (Main DID) → Recipient (User DID)');
    console.log('   🔒 Biometric + Session → Deterministic DID: WORKING');
    console.log('   ✍️  Message Signing Chain: WORKING');
    console.log('   🔍 Signature Verification: WORKING');
    console.log('   🛡️  Trust Chain: ESTABLISHED');
    
    console.log('\n🚀 Ready for integration into ov-public-utility-tool and ov-vault-agent!');
    
  } catch (error) {
    console.error('❌ Error in DIDComm integration test:', error);
    process.exit(1);
  }
})();
