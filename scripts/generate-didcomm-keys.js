#!/usr/bin/env ts-node
/**
 * DIDComm Encryption Key Generator (TypeScript)
 *
 * This script generates secure encryption keys for DIDComm server-to-server communication.
 * It creates keys for both cheqd-studio and ov-vault-agent servers.
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
// ANSI color codes for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};
function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}
function generateSecureKey(length = 64) {
    // Generate a cryptographically secure random key
    return crypto.randomBytes(length).toString('hex');
}
function generateSigningKey() {
    // Generate a shorter key for HMAC signing
    return crypto.randomBytes(32).toString('hex');
}
function createEnvFile(keys, outputPath) {
    const envContent = `# DIDComm Encryption Keys
# Generated on ${new Date().toISOString()}
# 
# IMPORTANT: Keep these keys secure and never commit them to version control!

# Cheqd Studio Server Keys
CHEQD_STUDIO_ENCRYPTION_KEY=${keys.cheqdStudio.encryptionKey}
CHEQD_STUDIO_SIGNING_KEY=${keys.cheqdStudio.signingKey}

# OriginVault Agent Server Keys  
OV_VAULT_ENCRYPTION_KEY=${keys.ovVaultAgent.encryptionKey}
OV_VAULT_SIGNING_KEY=${keys.ovVaultAgent.signingKey}

# DIDComm Configuration
DIDCOMM_SIGNING_KEY=${keys.shared.signingKey}
TEST_DIDCOMM_CONNECTIVITY=false

# Server Configuration
CHEQD_STUDIO_DID=did:cheqd:mainnet:53c6369f-e004-4fb9-8d89-dd31f8db566a
OV_VAULT_AGENT_DID=did:cheqd:mainnet:d010e359-b819-4d6f-bafd-f00b5620ae91

# Endpoints (update these with your actual deployment URLs)
CHEQD_STUDIO_ENDPOINT=https://studio.cheqd.io/didcomm/receive
OV_VAULT_AGENT_ENDPOINT=https://agent.create.originvault.me/secure-didcomm
`;
    fs.writeFileSync(outputPath, envContent);
    log(`✅ Environment file created: ${outputPath}`, 'green');
}
function createKeysJson(keys, outputPath) {
    const keysData = {
        generated: new Date().toISOString(),
        servers: {
            cheqdStudio: {
                name: 'Cheqd Studio Server',
                did: 'did:cheqd:mainnet:53c6369f-e004-4fb9-8d89-dd31f8db566a',
                encryptionKey: keys.cheqdStudio.encryptionKey,
                signingKey: keys.cheqdStudio.signingKey,
                endpoint: 'https://studio.cheqd.io/didcomm/receive'
            },
            ovVaultAgent: {
                name: 'OriginVault Agent Server',
                did: 'did:cheqd:mainnet:d010e359-b819-4d6f-bafd-f00b5620ae91',
                encryptionKey: keys.ovVaultAgent.encryptionKey,
                signingKey: keys.ovVaultAgent.signingKey,
                endpoint: 'https://agent.create.originvault.me/secure-didcomm'
            }
        },
        shared: {
            signingKey: keys.shared.signingKey
        }
    };
    fs.writeFileSync(outputPath, JSON.stringify(keysData, null, 2));
    log(`✅ Keys JSON file created: ${outputPath}`, 'green');
}
function displayKeys(keys) {
    log('\n🔐 Generated DIDComm Encryption Keys', 'bright');
    log('='.repeat(50), 'cyan');
    log('\n📋 Cheqd Studio Server:', 'yellow');
    log(`   Encryption Key: ${keys.cheqdStudio.encryptionKey}`, 'green');
    log(`   Signing Key:    ${keys.cheqdStudio.signingKey}`, 'green');
    log('\n📋 OriginVault Agent Server:', 'yellow');
    log(`   Encryption Key: ${keys.ovVaultAgent.encryptionKey}`, 'green');
    log(`   Signing Key:    ${keys.ovVaultAgent.signingKey}`, 'green');
    log('\n📋 Shared Configuration:', 'yellow');
    log(`   DIDComm Signing Key: ${keys.shared.signingKey}`, 'green');
    log('\n⚠️  SECURITY WARNING:', 'red');
    log('   • Keep these keys secure and private', 'red');
    log('   • Never commit them to version control', 'red');
    log('   • Store them in secure environment variables', 'red');
    log('   • Rotate keys regularly in production', 'red');
}
function displayUsage() {
    log('\n📖 Usage Examples:', 'bright');
    log('='.repeat(30), 'cyan');
    log('\n1. Generate keys and create .env files:', 'yellow');
    log('   npx ts-node scripts/generate-didcomm-keys.ts --env', 'green');
    log('\n2. Generate keys and create JSON file:', 'yellow');
    log('   npx ts-node scripts/generate-didcomm-keys.ts --json', 'green');
    log('\n3. Generate keys and display only:', 'yellow');
    log('   npx ts-node scripts/generate-didcomm-keys.ts --display', 'green');
    log('\n4. Generate all outputs:', 'yellow');
    log('   npx ts-node scripts/generate-didcomm-keys.ts --all', 'green');
    log('\n5. Help:', 'yellow');
    log('   npx ts-node scripts/generate-didcomm-keys.ts --help', 'green');
}
function main() {
    const args = process.argv.slice(2);
    if (args.includes('--help') || args.includes('-h')) {
        log('🔑 DIDComm Encryption Key Generator', 'bright');
        log('=====================================', 'cyan');
        log('\nThis script generates secure encryption keys for DIDComm server-to-server communication.');
        displayUsage();
        return;
    }
    log('🔑 Generating DIDComm Encryption Keys...', 'bright');
    log('==========================================', 'cyan');
    // Generate keys for each server
    const keys = {
        cheqdStudio: {
            encryptionKey: generateSecureKey(64), // 512-bit key
            signingKey: generateSigningKey() // 256-bit key
        },
        ovVaultAgent: {
            encryptionKey: generateSecureKey(64), // 512-bit key  
            signingKey: generateSigningKey() // 256-bit key
        },
        shared: {
            signingKey: generateSigningKey() // 256-bit key for general signing
        }
    };
    // Display generated keys
    displayKeys(keys);
    // Create output files based on arguments
    const scriptDir = path.dirname(new URL(import.meta.url).pathname);
    const projectRoot = path.join(scriptDir, '..');
    if (args.includes('--env') || args.includes('--all')) {
        log('\n📝 Creating environment files...', 'yellow');
        // Create .env file for cheqd-studio
        const cheqdStudioEnvPath = path.join(projectRoot, '..', 'cheqd-studio', '.env.didcomm');
        createEnvFile(keys, cheqdStudioEnvPath);
        // Create .env file for ov-vault-agent  
        const ovVaultEnvPath = path.join(projectRoot, '..', 'ov-vault-agent', '.env.didcomm');
        createEnvFile(keys, ovVaultEnvPath);
    }
    if (args.includes('--json') || args.includes('--all')) {
        log('\n📄 Creating JSON configuration...', 'yellow');
        const jsonPath = path.join(projectRoot, 'didcomm-keys.json');
        createKeysJson(keys, jsonPath);
    }
    if (args.includes('--display') || args.length === 0) {
        // Keys already displayed above
    }
    if (!args.includes('--env') && !args.includes('--json') && !args.includes('--display') && !args.includes('--all')) {
        log('\n💡 Tip: Use --help to see all available options', 'cyan');
    }
    log('\n✅ Key generation completed!', 'green');
    log('   Remember to add the generated keys to your environment variables.', 'yellow');
}
// Export functions for use in other modules
export { generateSecureKey, generateSigningKey, createEnvFile, createKeysJson };
// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main();
}
