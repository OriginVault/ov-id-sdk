import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.js';
import { createSessionDID, recreateSessionDID, verifySessionDID } from '../src/didcomm/sessionDID.js';
import { DIDCommClient } from '../src/didcomm/didcommClient.js';

dotenv.config();

(async () => {
  console.log('🧪 Testing Session DID Creation from Biometric Data...');
  
  const { agent } = await packageStore.initialize();
  
  try {
    // Mock biometric data (in real implementation, this would come from actual biometric sensors)
    const mockBiometricData = {
      fingerprint: 'mock_fingerprint_template_12345',
      faceTemplate: 'mock_face_embedding_vector_67890',
      deviceFingerprint: 'mock_device_id_abcdef',
      webauthnCredential: 'mock_webauthn_credential_xyz789'
    };
    
    const sessionId = 'session_' + Date.now();
    
    console.log('🔄 Creating session DID from biometric data...');
    console.log(`   📱 Session ID: ${sessionId}`);
    console.log(`   🔒 Biometric data keys: ${Object.keys(mockBiometricData).join(', ')}`);
    
    // Create session DID
    const sessionDID1 = await createSessionDID(mockBiometricData, sessionId, agent);
    
    console.log('✅ Session DID created successfully:');
    console.log(`   🆔 DID: ${sessionDID1.did}`);
    console.log(`   🔑 Key ID: ${sessionDID1.keyId}`);
    console.log(`   📱 Session ID: ${sessionDID1.sessionId}`);
    console.log(`   🔒 Biometric Hash: ${sessionDID1.biometricHash.substring(0, 16)}...`);
    
    console.log('🔄 Testing deterministic recreation...');
    
    // Recreate the same session DID - should be identical
    const sessionDID2 = await recreateSessionDID(mockBiometricData, sessionId, agent);
    
    console.log('✅ Session DID recreated:');
    console.log(`   🆔 DID: ${sessionDID2.did}`);
    
    // Verify they are identical
    const areIdentical = (
      sessionDID1.did === sessionDID2.did &&
      sessionDID1.privateKey === sessionDID2.privateKey &&
      sessionDID1.publicKey === sessionDID2.publicKey &&
      sessionDID1.biometricHash === sessionDID2.biometricHash
    );
    
    console.log(`✅ Deterministic recreation: ${areIdentical ? 'IDENTICAL ✓' : 'DIFFERENT ✗'}`);
    
    if (!areIdentical) {
      console.error('❌ Session DIDs should be identical when created from same biometric data!');
      console.log('   Original DID:', sessionDID1.did);
      console.log('   Recreated DID:', sessionDID2.did);
      process.exit(1);
    }
    
    console.log('🔄 Testing session DID verification...');
    
    // Verify the session DID
    const isValidSession = await verifySessionDID(
      sessionDID1.did,
      mockBiometricData,
      sessionId
    );
    
    console.log(`✅ Session DID verification: ${isValidSession ? 'VALID ✓' : 'INVALID ✗'}`);
    
    if (!isValidSession) {
      console.error('❌ Session DID verification failed!');
      process.exit(1);
    }
    
    console.log('🔄 Testing with different biometric data...');
    
    // Test with different biometric data - should fail
    const differentBiometricData = {
      ...mockBiometricData,
      fingerprint: 'different_fingerprint_template_99999'
    };
    
    const isValidWithDifferentBiometrics = await verifySessionDID(
      sessionDID1.did,
      differentBiometricData,
      sessionId
    );
    
    console.log(`✅ Different biometric verification: ${isValidWithDifferentBiometrics ? 'VALID ✓ (UNEXPECTED!)' : 'INVALID ✗ (EXPECTED)'}`);
    
    if (isValidWithDifferentBiometrics) {
      console.error('❌ Session DID should not be valid with different biometric data!');
      process.exit(1);
    }
    
    console.log('🔄 Testing DIDComm client with session DID...');
    
    // Test the DIDComm client with session DID
    const didcommClient = new DIDCommClient(agent);
    
    // Create a recipient DID for testing
    const { createDID } = await import('../src/identityManager.js');
    const recipientDID = await createDID({
      method: 'key',
      agent,
    });
    
    console.log(`✅ Created recipient DID: ${recipientDID.did.did}`);
    
    // Send a session-signed message
    const testMessage = 'Hello from session DID! This message is signed with biometric-derived credentials.';
    
    const messageResult = await didcommClient.sendSessionSignedMessage({
      recipient: recipientDID.did.did,
      message: testMessage,
      biometricData: mockBiometricData,
      sessionId: sessionId,
      encrypt: false, // Keep unencrypted for testing
      messageType: 'test-session-message'
    });
    
    console.log('✅ Session-signed message sent successfully:');
    console.log(`   📝 Message: ${testMessage.substring(0, 50)}...`);
    console.log(`   🆔 Session DID: ${messageResult.sessionDID.did}`);
    console.log(`   🔑 Key ID: ${messageResult.sessionDID.keyId}`);
    
    console.log('🎉 All session DID tests passed!');
    
  } catch (error) {
    console.error('❌ Error in session DID test:', error);
    process.exit(1);
  }
})();
