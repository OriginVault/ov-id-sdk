/**
 * Cheqd Studio Integration Example
 * 
 * This example demonstrates how to use the enhanced OV-ID-SDK
 * with cheqd-studio integration for enterprise-grade security.
 */

import { 
  SecurityBridgeService, 
  EnvelopeEncryptionService, 
  SecureKeyStorage, 
  KeyRotationService,
  SecurityValidationService,
  SecureDIDCommClient 
} from '@originvault/ov-id-sdk';
import { IOVAgent } from '@originvault/ov-types';

// =============================================================================
// SETUP AND INITIALIZATION
// =============================================================================

async function initializeSecurityServices() {
  console.log('🔐 Initializing OV-ID-SDK Security Services...');
  
  // Initialize security bridge for cheqd-studio integration
  const securityBridge = SecurityBridgeService.getInstance({
    cheqdStudioEndpoint: process.env.OV_CHEQD_STUDIO_ENDPOINT || 'https://your-cheqd-studio.com',
    sharedSecretKey: process.env.OV_CHEQD_STUDIO_SECRET || 'your-shared-secret',
    enableCrossRepoSync: true
  });
  
  // Initialize other security services
  const envelopeService = EnvelopeEncryptionService.getInstance();
  const keyStorage = SecureKeyStorage.getInstance();
  const rotationService = KeyRotationService.getInstance();
  const validationService = SecurityValidationService.getInstance();
  
  console.log('✅ Security services initialized');
  
  return {
    securityBridge,
    envelopeService,
    keyStorage,
    rotationService,
    validationService
  };
}

// =============================================================================
// EXAMPLE 1: SECURE KEY MANAGEMENT WITH CHEQD STUDIO SYNC
// =============================================================================

async function exampleSecureKeyManagement() {
  console.log('\n📋 Example 1: Secure Key Management with Cheqd Studio Sync');
  
  const { securityBridge, keyStorage } = await initializeSecurityServices();
  
  // Create a new DID and store the key securely
  const keyId = 'example-key-123';
  const did = 'did:cheqd:mainnet:example123';
  const privateKeyHex = 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456';
  const publicKeyHex = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
  const password = 'secure-password-123';
  
  try {
    // Store key securely in OV-ID-SDK
    await keyStorage.storeKey(keyId, did, privateKeyHex, publicKeyHex, password);
    console.log('✅ Key stored securely in OV-ID-SDK');
    
    // Sync key creation with cheqd-studio
    await securityBridge.syncKeyWithCheqdStudio({
      operation: 'create',
      keyId,
      did,
      customerId: 'customer-456',
      metadata: {
        keyType: 'Ed25519',
        purpose: 'authentication',
        algorithm: 'Ed25519',
        createdBy: 'ov-id-sdk'
      }
    });
    console.log('✅ Key creation synced with cheqd-studio');
    
    // Retrieve key securely
    const retrievedKey = await keyStorage.retrieveKey(keyId, password);
    if (retrievedKey) {
      console.log('✅ Key retrieved successfully');
      console.log(`   Public Key: ${retrievedKey.publicKeyHex.substring(0, 16)}...`);
    }
    
  } catch (error) {
    console.error('❌ Error in secure key management:', error);
  }
}

// =============================================================================
// EXAMPLE 2: ENCRYPTED DATA SHARING WITH CHEQD STUDIO
// =============================================================================

async function exampleEncryptedDataSharing() {
  console.log('\n📋 Example 2: Encrypted Data Sharing with Cheqd Studio');
  
  const { securityBridge, envelopeService } = await initializeSecurityServices();
  
  const sensitiveData = {
    customerId: 'customer-789',
    personalInfo: {
      name: 'John Doe',
      email: 'john.doe@example.com',
      ssn: '123-45-6789'
    },
    preferences: {
      notifications: true,
      theme: 'dark'
    }
  };
  
  try {
    // Encrypt data for cheqd-studio
    const encryptedData = await securityBridge.encryptForCheqdStudio(JSON.stringify(sensitiveData));
    console.log('✅ Data encrypted for cheqd-studio');
    console.log(`   Encryption Key ID: ${encryptedData.keyId}`);
    
    // Simulate sending to cheqd-studio
    const response = await fetch(`${process.env.OV_CHEQD_STUDIO_ENDPOINT}/api/secure-data`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-OV-SDK-Secret': process.env.OV_CHEQD_STUDIO_SECRET || 'your-shared-secret'
      },
      body: JSON.stringify({ 
        encryptedData,
        metadata: {
          dataType: 'customer-profile',
          source: 'ov-id-sdk',
          timestamp: new Date().toISOString()
        }
      })
    });
    
    if (response.ok) {
      console.log('✅ Encrypted data sent to cheqd-studio successfully');
      
      // Simulate receiving encrypted response
      const responseData = await response.json();
      if (responseData.encryptedResponse) {
        const decryptedResponse = await securityBridge.decryptFromCheqdStudio(responseData.encryptedResponse);
        console.log('✅ Response decrypted successfully');
        console.log('   Response:', JSON.parse(decryptedResponse));
      }
    } else {
      console.error('❌ Failed to send data to cheqd-studio:', response.statusText);
    }
    
  } catch (error) {
    console.error('❌ Error in encrypted data sharing:', error);
  }
}

// =============================================================================
// EXAMPLE 3: CROSS-REPOSITORY KEY ROTATION
// =============================================================================

async function exampleKeyRotation() {
  console.log('\n📋 Example 3: Cross-Repository Key Rotation');
  
  const { securityBridge, rotationService } = await initializeSecurityServices();
  
  const did = 'did:cheqd:mainnet:example123';
  const password = 'secure-password-123';
  
  try {
    // Create rotation plan
    const rotationPlan = await rotationService.createRotationPlan(did);
    console.log('✅ Key rotation plan created');
    console.log(`   Rotation ID: ${rotationPlan.rotationId}`);
    console.log(`   Keys to rotate: ${rotationPlan.keyIds.length}`);
    
    // Execute key rotation
    const rotationResult = await rotationService.executeKeyRotation(rotationPlan, password);
    
    if (rotationResult.success) {
      console.log('✅ Key rotation completed successfully');
      console.log(`   Rotated keys: ${rotationResult.rotatedKeys.length}`);
      console.log(`   Duration: ${rotationResult.duration}ms`);
      console.log(`   Cheqd Studio synced: ${rotationResult.cheqdStudioSynced}`);
    } else {
      console.error('❌ Key rotation failed');
      console.error('   Errors:', rotationResult.errors);
    }
    
    // Emergency rotation example
    console.log('\n🚨 Testing emergency rotation...');
    const emergencyResult = await rotationService.emergencyRotation(did, password);
    
    if (emergencyResult.success) {
      console.log('✅ Emergency rotation completed');
    } else {
      console.error('❌ Emergency rotation failed');
    }
    
  } catch (error) {
    console.error('❌ Error in key rotation:', error);
  }
}

// =============================================================================
// EXAMPLE 4: SECURE DIDCOMM MESSAGING
// =============================================================================

async function exampleSecureDIDCommMessaging() {
  console.log('\n📋 Example 4: Secure DIDComm Messaging');
  
  // Initialize agent (this would be your actual agent instance)
  const agent = {} as IOVAgent; // Replace with actual agent
  
  const secureClient = new SecureDIDCommClient(agent);
  
  const recipient = 'did:cheqd:mainnet:recipient123';
  const signerDID = 'did:cheqd:mainnet:sender123';
  const password = 'secure-password-123';
  
  const messageContent = {
    type: 'credential-offer',
    credential: {
      type: 'VerifiableCredential',
      credentialSubject: {
        id: 'did:cheqd:mainnet:subject123',
        name: 'Jane Smith',
        email: 'jane.smith@example.com'
      }
    }
  };
  
  try {
    // Send secure message
    const secureMessage = await secureClient.sendSecureMessage(
      recipient,
      'credential-offer',
      messageContent,
      signerDID,
      password,
      true // encrypt message
    );
    
    console.log('✅ Secure message sent');
    console.log(`   Message ID: ${secureMessage.id}`);
    console.log(`   Encrypted: ${secureMessage.encrypted}`);
    console.log(`   Signature: ${secureMessage.signature.algorithm}`);
    
    // Verify message (simulating recipient verification)
    const isValid = await secureClient.verifySecureMessage(secureMessage);
    
    if (isValid) {
      console.log('✅ Message verification passed');
      
      // Decrypt message content
      const decryptedContent = await secureClient.decryptMessageContent(secureMessage);
      console.log('✅ Message content decrypted');
      console.log('   Content:', decryptedContent);
    } else {
      console.error('❌ Message verification failed');
    }
    
  } catch (error) {
    console.error('❌ Error in secure DIDComm messaging:', error);
  }
}

// =============================================================================
// EXAMPLE 5: SECURITY VALIDATION AND MONITORING
// =============================================================================

async function exampleSecurityValidation() {
  console.log('\n📋 Example 5: Security Validation and Monitoring');
  
  const { validationService } = await initializeSecurityServices();
  
  try {
    // Validate security state
    const validationResult = await validationService.validateSecurityState();
    
    console.log('🔍 Security Validation Results:');
    console.log(`   Overall Score: ${validationResult.score}/100`);
    console.log(`   Valid: ${validationResult.isValid}`);
    console.log(`   Issues: ${validationResult.issues.length}`);
    
    if (validationResult.issues.length > 0) {
      console.log('\n⚠️  Security Issues:');
      validationResult.issues.forEach((issue, index) => {
        console.log(`   ${index + 1}. [${issue.severity.toUpperCase()}] ${issue.description}`);
        console.log(`      Category: ${issue.category}`);
        console.log(`      Remediation: ${issue.remediation}`);
      });
    }
    
    if (validationResult.recommendations.length > 0) {
      console.log('\n💡 Recommendations:');
      validationResult.recommendations.forEach((rec, index) => {
        console.log(`   ${index + 1}. ${rec}`);
      });
    }
    
    // Generate comprehensive security report
    const securityReport = await validationService.generateSecurityReport();
    
    console.log('\n📊 Security Report:');
    console.log(`   Timestamp: ${securityReport.timestamp}`);
    console.log(`   Overall Score: ${securityReport.overallScore}/100`);
    console.log(`   Key Integrity: ${securityReport.keyIntegrityResults.isValid ? 'VALID' : 'INVALID'}`);
    console.log(`   Encryption Config: ${securityReport.encryptionConfigResults.isValid ? 'VALID' : 'INVALID'}`);
    
  } catch (error) {
    console.error('❌ Error in security validation:', error);
  }
}

// =============================================================================
// EXAMPLE 6: ERROR HANDLING AND RECOVERY
// =============================================================================

async function exampleErrorHandling() {
  console.log('\n📋 Example 6: Error Handling and Recovery');
  
  const { securityBridge } = await initializeSecurityServices();
  
  // Example with retry logic
  const maxRetries = 3;
  let retryCount = 0;
  
  const syncRequest = {
    operation: 'create' as const,
    keyId: 'retry-test-key',
    did: 'did:cheqd:mainnet:retry-test',
    customerId: 'customer-retry',
    metadata: { test: true }
  };
  
  while (retryCount < maxRetries) {
    try {
      await securityBridge.syncKeyWithCheqdStudio(syncRequest);
      console.log('✅ Key sync successful');
      break;
      
    } catch (error) {
      retryCount++;
      console.log(`❌ Sync attempt ${retryCount} failed:`, error instanceof Error ? error.message : 'Unknown error');
      
      if (retryCount < maxRetries) {
        const delay = 1000 * retryCount; // Exponential backoff
        console.log(`⏳ Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        console.error('❌ All retry attempts failed - continuing with local operation');
        // In a real application, you might want to queue this for later retry
        // or log it for manual intervention
      }
    }
  }
}

// =============================================================================
// MAIN EXECUTION
// =============================================================================

async function main() {
  console.log('🚀 OV-ID-SDK ↔ Cheqd Studio Integration Examples');
  console.log('================================================\n');
  
  // Check environment configuration
  if (!process.env.OV_MASTER_ENCRYPTION_KEY) {
    console.error('❌ OV_MASTER_ENCRYPTION_KEY not configured');
    console.log('💡 Run: npm run setup-security');
    process.exit(1);
  }
  
  try {
    // Run all examples
    await exampleSecureKeyManagement();
    await exampleEncryptedDataSharing();
    await exampleKeyRotation();
    await exampleSecureDIDCommMessaging();
    await exampleSecurityValidation();
    await exampleErrorHandling();
    
    console.log('\n🎉 All examples completed successfully!');
    console.log('\n📚 Next steps:');
    console.log('1. Configure cheqd-studio with the provided API extensions');
    console.log('2. Set up proper environment variables');
    console.log('3. Test the integration in your development environment');
    console.log('4. Deploy to production with proper security measures');
    
  } catch (error) {
    console.error('\n❌ Example execution failed:', error);
    process.exit(1);
  }
}

// Run examples if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export {
  exampleSecureKeyManagement,
  exampleEncryptedDataSharing,
  exampleKeyRotation,
  exampleSecureDIDCommMessaging,
  exampleSecurityValidation,
  exampleErrorHandling
};
