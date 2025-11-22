#!/usr/bin/env node

/**
 * Asymmetric Encryption Example for DIDComm
 * 
 * Demonstrates how to use public/private key pairs for encryption
 * instead of shared secret keys.
 */

import crypto from 'crypto';

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
}

function encryptWithPublicKey(data, publicKey) {
  const buffer = Buffer.from(data, 'utf8');
  const encrypted = crypto.publicEncrypt(publicKey, buffer);
  return encrypted.toString('base64');
}

function decryptWithPrivateKey(encryptedData, privateKey) {
  const buffer = Buffer.from(encryptedData, 'base64');
  const decrypted = crypto.privateDecrypt(privateKey, buffer);
  return decrypted.toString('utf8');
}

function demonstrateAsymmetricEncryption() {
  log('🔑 Asymmetric Encryption Demo for DIDComm', 'bright');
  log('==========================================', 'cyan');
  
  // Generate key pairs for both servers
  const cheqdStudioKeys = generateKeyPair();
  const ovVaultKeys = generateKeyPair();
  
  log('\n📋 Generated Key Pairs:', 'yellow');
  log('Cheqd Studio has its own public/private key pair', 'green');
  log('OriginVault Agent has its own public/private key pair', 'green');
  
  // Simulate message flow
  const message = JSON.stringify({
    type: 'credential_verification_request',
    data: { credentialId: '12345', issuer: 'did:cheqd:mainnet:example' },
    timestamp: new Date().toISOString()
  });
  
  log('\n🔄 Message Flow Simulation:', 'bright');
  log('=' .repeat(35), 'cyan');
  
  // Step 1: Cheqd Studio wants to send a message to OriginVault
  log('\n1️⃣ Cheqd Studio → OriginVault Agent:', 'yellow');
  log(`   Original message: ${message}`, 'cyan');
  
  // Step 2: Cheqd Studio encrypts with OriginVault's PUBLIC key
  const encryptedMessage = encryptWithPublicKey(message, ovVaultKeys.publicKey);
  log(`   Encrypted with OV's public key: ${encryptedMessage.substring(0, 50)}...`, 'green');
  
  // Step 3: OriginVault receives and decrypts with its PRIVATE key
  const decryptedMessage = decryptWithPrivateKey(encryptedMessage, ovVaultKeys.privateKey);
  log(`   Decrypted by OV with its private key: ${decryptedMessage}`, 'green');
  
  // Step 4: Reverse flow - OriginVault to Cheqd Studio
  log('\n2️⃣ OriginVault Agent → Cheqd Studio:', 'yellow');
  const responseMessage = JSON.stringify({
    type: 'credential_verification_response',
    data: { verified: true, timestamp: new Date().toISOString() },
    timestamp: new Date().toISOString()
  });
  
  log(`   Original response: ${responseMessage}`, 'cyan');
  
  // OriginVault encrypts with Cheqd Studio's PUBLIC key
  const encryptedResponse = encryptWithPublicKey(responseMessage, cheqdStudioKeys.publicKey);
  log(`   Encrypted with Cheqd's public key: ${encryptedResponse.substring(0, 50)}...`, 'green');
  
  // Cheqd Studio decrypts with its PRIVATE key
  const decryptedResponse = decryptWithPrivateKey(encryptedResponse, cheqdStudioKeys.privateKey);
  log(`   Decrypted by Cheqd with its private key: ${decryptedResponse}`, 'green');
  
  log('\n✅ Asymmetric Encryption Demo Complete!', 'bright');
  
  log('\n💡 Key Benefits:', 'cyan');
  log('   • No need to share secret keys between servers', 'green');
  log('   • Public keys can be published openly', 'green');
  log('   • Each server only needs to protect its own private key', 'green');
  log('   • Better security model for distributed systems', 'green');
  
  log('\n🔧 Implementation Notes:', 'yellow');
  log('   • Use RSA 2048-bit keys for good security', 'green');
  log('   • Store private keys securely in environment variables', 'green');
  log('   • Publish public keys in DID documents or API endpoints', 'green');
  log('   • Consider key rotation for production use', 'green');
}

// Run the demo
demonstrateAsymmetricEncryption();
