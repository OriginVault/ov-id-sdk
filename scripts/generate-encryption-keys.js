#!/usr/bin/env node

/**
 * DIDComm Encryption Key Generator
 * 
 * Generates both symmetric and asymmetric encryption keys for DIDComm server-to-server communication.
 * Choose the approach that fits your security model.
 */

import crypto from 'crypto';

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function generateSymmetricKey() {
  // Generate a 512-bit (64 bytes) encryption key for AES-256
  return crypto.randomBytes(64).toString('hex');
}

function generateAsymmetricKeyPair() {
  // Generate RSA key pair for asymmetric encryption
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
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
  
  return { publicKey, privateKey };
}

function main() {
  log('🔑 Generating DIDComm Encryption Keys...', 'bright');
  log('==========================================', 'cyan');
  
  // Generate symmetric keys (current approach)
  const cheqdStudioSymmetricKey = generateSymmetricKey();
  const ovVaultAgentSymmetricKey = generateSymmetricKey();
  
  // Generate asymmetric key pairs (your suggested approach)
  const cheqdStudioKeys = generateAsymmetricKeyPair();
  const ovVaultAgentKeys = generateAsymmetricKeyPair();
  
  log('\n🔐 SYMMETRIC ENCRYPTION KEYS (Current Approach)', 'bright');
  log('=' .repeat(50), 'cyan');
  log('Each server has its own secret key. Sender needs receiver\'s secret key.', 'yellow');
  
  log('\n📋 Cheqd Studio Server:', 'yellow');
  log(`   CHEQD_STUDIO_ENCRYPTION_KEY=${cheqdStudioSymmetricKey}`, 'green');
  
  log('\n📋 OriginVault Agent Server:', 'yellow');
  log(`   OV_VAULT_ENCRYPTION_KEY=${ovVaultAgentSymmetricKey}`, 'green');
  
  log('\n🔑 ASYMMETRIC ENCRYPTION KEYS (Your Suggested Approach)', 'bright');
  log('=' .repeat(55), 'cyan');
  log('Each server has public/private key pair. Sender uses receiver\'s public key.', 'yellow');
  
  log('\n📋 Cheqd Studio Server:', 'yellow');
  log(`   CHEQD_STUDIO_PUBLIC_KEY=${cheqdStudioKeys.publicKey.replace(/\n/g, '\\n')}`, 'green');
  log(`   CHEQD_STUDIO_PRIVATE_KEY=${cheqdStudioKeys.privateKey.replace(/\n/g, '\\n')}`, 'green');
  
  log('\n📋 OriginVault Agent Server:', 'yellow');
  log(`   OV_VAULT_PUBLIC_KEY=${ovVaultAgentKeys.publicKey.replace(/\n/g, '\\n')}`, 'green');
  log(`   OV_VAULT_PRIVATE_KEY=${ovVaultAgentKeys.privateKey.replace(/\n/g, '\\n')}`, 'green');
  
  log('\n💡 COMPARISON:', 'bright');
  log('=' .repeat(20), 'cyan');
  
  log('\n🔒 SYMMETRIC (Current):', 'yellow');
  log('   ✅ Faster encryption/decryption', 'green');
  log('   ✅ Smaller key sizes', 'green');
  log('   ❌ Key distribution problem', 'red');
  log('   ❌ Both servers need each other\'s secret keys', 'red');
  
  log('\n🔑 ASYMMETRIC (Your Suggestion):', 'yellow');
  log('   ✅ No key distribution problem', 'green');
  log('   ✅ Public keys can be shared openly', 'green');
  log('   ✅ Better security model', 'green');
  log('   ❌ Slower encryption/decryption', 'red');
  log('   ❌ Larger key sizes', 'red');
  
  log('\n🔄 HYBRID APPROACH (Recommended):', 'bright');
  log('=' .repeat(35), 'cyan');
  log('1. Use asymmetric keys to exchange symmetric session keys', 'yellow');
  log('2. Use symmetric keys for actual message encryption', 'yellow');
  log('3. Best of both worlds!', 'green');
  
  log('\n⚠️  SECURITY WARNING:', 'red');
  log('   • Keep private keys secure and never commit them to version control', 'red');
  log('   • Public keys can be shared openly', 'red');
  log('   • Store keys in secure environment variables', 'red');
  
  log('\n✅ Encryption key generation completed!', 'green');
  log('   Choose the approach that fits your security requirements.', 'yellow');
}

main();