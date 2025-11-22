import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.js';
import { createDID } from '../src/identityManager.js';
import { signMessage, verifyMessageSignature } from '../src/didcomm/messageSigning.js';

dotenv.config();

(async () => {
  console.log('🧪 Testing Message Signing with DID...');
  
  const { agent } = await packageStore.initialize();
  
  try {
    // Create a test DID
    const testDID = await createDID({
      method: 'key',
      agent,
    });
    
    console.log(`✅ Created test DID: ${testDID.did.did}`);
    
    // Test message to sign
    const message = "Hello, this is a test message for signing";
    
    console.log('🔄 Signing message with DID...');
    
    // Sign the message using our new signMessage function
    const signedMessage = await signMessage(agent, message, {
      signer: testDID.did.did,
      messageType: 'test-message',
      includeNonce: true
    });
    
    console.log('✅ Message signed successfully:');
    console.log(`   📝 Message: ${signedMessage.message}`);
    console.log(`   ✍️  Signature: ${signedMessage.signature.substring(0, 32)}...`);
    console.log(`   🆔 Signer DID: ${signedMessage.signer}`);
    console.log(`   ⏰ Timestamp: ${signedMessage.timestamp}`);
    console.log(`   🔢 Message ID: ${signedMessage.messageId}`);
    console.log(`   🎲 Nonce: ${signedMessage.nonce}`);
    
    console.log('🔄 Verifying message signature...');
    
    // Verify the signature
    const isValid = await verifyMessageSignature(agent, signedMessage);
    
    console.log(`✅ Signature verification: ${isValid ? 'VALID ✓' : 'INVALID ✗'}`);
    
    if (!isValid) {
      console.error('❌ Signature verification failed!');
      process.exit(1);
    }
    
    // Test with tampered message
    console.log('🔄 Testing with tampered message...');
    const tamperedMessage = {
      ...signedMessage,
      message: "This message has been tampered with"
    };
    
    const isTamperedValid = await verifyMessageSignature(agent, tamperedMessage);
    console.log(`✅ Tampered message verification: ${isTamperedValid ? 'VALID ✓ (UNEXPECTED!)' : 'INVALID ✗ (EXPECTED)'}`);
    
    if (isTamperedValid) {
      console.error('❌ Tampered message should not be valid!');
      process.exit(1);
    }
    
    console.log('🎉 All message signing tests passed!');
    
  } catch (error) {
    console.error('❌ Error in message signing test:', error);
    process.exit(1);
  }
})();
