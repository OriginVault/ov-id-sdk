# Security Migration Guide

This guide helps you migrate from the vulnerable legacy implementation to the new secure security services in ov-id-sdk.

## Overview

The new security implementation addresses critical vulnerabilities and provides enterprise-grade security features:

- **Secure Key Storage**: Encrypted key storage with proper file permissions
- **Envelope Encryption**: DEK/KEK encryption pattern for enhanced security
- **Memory Protection**: Automatic cleanup of sensitive data from memory
- **Key Rotation**: Automated and emergency key rotation capabilities
- **Secure DIDComm**: Enhanced message signing and verification with replay protection

## Breaking Changes

### 1. Key Storage API Changes

**Old API:**
```typescript
import { storePrivateKey, retrievePrivateKey } from '@originvault/ov-id-sdk';

// Store key (vulnerable - stored in plaintext)
await storePrivateKey(keyName, privateKey, kid);

// Retrieve key
const key = await retrievePrivateKey(keyName);
```

**New Secure API:**
```typescript
import { SecureKeyStorage } from '@originvault/ov-id-sdk';

const secureStorage = SecureKeyStorage.getInstance();

// Store key securely (encrypted with password)
await secureStorage.storeKey(keyId, did, privateKeyHex, publicKeyHex, password);

// Retrieve key securely
const keyData = await secureStorage.retrieveKey(keyId, password);
```

### 2. Message Signing API Changes

**Old API:**
```typescript
import { signMessage, verifyMessageSignature } from '@originvault/ov-id-sdk';

const signedMessage = await signMessage(agent, message, { signer: did });
const isValid = await verifyMessageSignature(agent, signedMessage);
```

**New Secure API:**
```typescript
import { SecureDIDCommClient } from '@originvault/ov-id-sdk';

const secureClient = new SecureDIDCommClient(agent);

// Send secure message with encryption and replay protection
const secureMessage = await secureClient.sendSecureMessage(
  recipient,
  messageType,
  content,
  signerDID,
  password,
  true // encrypt
);

// Verify secure message
const isValid = await secureClient.verifySecureMessage(secureMessage);
```

### 3. Encryption API Changes

**Old API:**
```typescript
import { encryptPrivateKey, decryptPrivateKey } from '@originvault/ov-id-sdk';

const encrypted = encryptPrivateKey(privateKey, password);
const decrypted = decryptPrivateKey(encrypted, password);
```

**New Secure API:**
```typescript
import { EnvelopeEncryptionService } from '@originvault/ov-id-sdk';

const envelopeService = EnvelopeEncryptionService.getInstance();

// Encrypt with envelope encryption (DEK/KEK pattern)
const encrypted = await envelopeService.encrypt(data);

// Decrypt
const decrypted = await envelopeService.decrypt(encrypted);
```

## Migration Steps

### Step 1: Update Dependencies

Ensure you have the latest version of ov-id-sdk:

```bash
npm install @originvault/ov-id-sdk@latest
```

### Step 2: Environment Configuration

Add the new environment variables to your `.env` file:

```bash
# Master encryption key for envelope encryption (32-byte hex)
OV_MASTER_ENCRYPTION_KEY=your-32-byte-hex-key-here

# Security configuration
OV_ENABLE_ENVELOPE_ENCRYPTION=true
OV_ENABLE_MEMORY_PROTECTION=true
OV_KEY_ROTATION_ENABLED=true

# Integration with cheqd-studio (optional)
OV_CHEQD_STUDIO_ENDPOINT=https://your-cheqd-studio.com
OV_CHEQD_STUDIO_SECRET=your-shared-secret
OV_ENABLE_CROSS_REPO_SYNC=true
```

### Step 3: Migrate Key Storage

**Before (Vulnerable):**
```typescript
// Old vulnerable key storage
await storePrivateKey(keyName, privateKey, kid);
const retrievedKey = await retrievePrivateKey(keyName);
```

**After (Secure):**
```typescript
import { SecureKeyStorage } from '@originvault/ov-id-sdk';

const secureStorage = SecureKeyStorage.getInstance();

// Migrate existing keys to secure storage
const keyId = kid;
const did = keyName;
const privateKeyHex = Buffer.from(privateKey).toString('hex');
const publicKeyHex = Buffer.from(await ed25519.getPublicKey(privateKey)).toString('hex');
const password = 'your-secure-password';

await secureStorage.storeKey(keyId, did, privateKeyHex, publicKeyHex, password);

// Retrieve keys securely
const keyData = await secureStorage.retrieveKey(keyId, password);
const retrievedKey = Buffer.from(keyData.privateKeyHex, 'hex');
```

### Step 4: Migrate Message Signing

**Before:**
```typescript
const signedMessage = await signMessage(agent, message, { signer: did });
const isValid = await verifyMessageSignature(agent, signedMessage);
```

**After:**
```typescript
import { SecureDIDCommClient } from '@originvault/ov-id-sdk';

const secureClient = new SecureDIDCommClient(agent);

// Send secure message
const secureMessage = await secureClient.sendSecureMessage(
  recipient,
  'message-type',
  { content: message },
  did,
  password,
  true // encrypt
);

// Verify secure message
const isValid = await secureClient.verifySecureMessage(secureMessage);
```

### Step 5: Migrate Encryption

**Before:**
```typescript
const encrypted = encryptPrivateKey(privateKey, password);
const decrypted = decryptPrivateKey(encrypted, password);
```

**After:**
```typescript
import { EnvelopeEncryptionService } from '@originvault/ov-id-sdk';

const envelopeService = EnvelopeEncryptionService.getInstance();

// Encrypt data
const encrypted = await envelopeService.encrypt(JSON.stringify(data));

// Decrypt data
const decrypted = JSON.parse(await envelopeService.decrypt(encrypted));
```

## Backward Compatibility

The legacy APIs are still available but deprecated. They will be removed in the next major version. The legacy functions now show warnings when used:

```typescript
// This will show a warning but still work
await storePrivateKey(keyName, privateKey, kid); // ⚠️ Deprecated
```

## New Security Features

### 1. Envelope Encryption

```typescript
import { EnvelopeEncryptionService } from '@originvault/ov-id-sdk';

const envelopeService = EnvelopeEncryptionService.getInstance();

// Encrypt with automatic key management
const encrypted = await envelopeService.encrypt(sensitiveData);

// Decrypt
const decrypted = await envelopeService.decrypt(encrypted);

// Rotate encryption keys
const oldKeyId = await envelopeService.rotateKeys();
```

### 2. Key Rotation

```typescript
import { KeyRotationService } from '@originvault/ov-id-sdk';

const rotationService = KeyRotationService.getInstance();

// Create rotation plan
const plan = await rotationService.createRotationPlan(did);

// Execute key rotation
const result = await rotationService.executeKeyRotation(plan, password);

// Emergency rotation
const emergencyResult = await rotationService.emergencyRotation(did, password);
```

### 3. Memory Protection

```typescript
import { MemoryProtectionService } from '@originvault/ov-id-sdk';

const memoryService = MemoryProtectionService.getInstance();

// Register sensitive buffer for automatic cleanup
const sensitiveBuffer = Buffer.from('sensitive-data');
memoryService.registerSensitiveBuffer(sensitiveBuffer);

// Manual cleanup
memoryService.zeroizeBuffer(sensitiveBuffer);
```

### 4. Integration with Cheqd Studio

```typescript
import { SecurityBridgeService } from '@originvault/ov-id-sdk';

const config = {
  cheqdStudioEndpoint: 'https://your-studio.com',
  sharedSecretKey: 'your-secret',
  enableCrossRepoSync: true
};

const bridge = SecurityBridgeService.getInstance(config);

// Sync key operations with cheqd-studio
await bridge.syncKeyWithCheqdStudio({
  operation: 'create',
  keyId: 'key-123',
  did: 'did:example:123',
  customerId: 'customer-456',
  metadata: {}
});

// Coordinate key rotation
await bridge.coordinateKeyRotation(did, customerId);
```

## Testing

Run the security tests to ensure everything is working correctly:

```bash
npm test -- --testPathPattern=security
```

## Troubleshooting

### Common Issues

1. **"OV_MASTER_ENCRYPTION_KEY not set"**
   - Generate a 32-byte hex key: `openssl rand -hex 32`
   - Add it to your environment variables

2. **"Failed to retrieve key"**
   - Ensure you're using the correct password
   - Check that the key exists in secure storage

3. **"Replay attack detected"**
   - This is expected behavior for security
   - Each message must have a unique nonce

### Performance Considerations

- Envelope encryption adds ~5-10ms overhead per operation
- Memory protection runs cleanup every 5 minutes
- Key rotation may take 30+ seconds for large key sets

## Support

For issues or questions about the migration:

1. Check the test files for usage examples
2. Review the security implementation tests
3. Contact the development team

## Security Best Practices

1. **Always use passwords** for key storage
2. **Rotate keys regularly** (monthly recommended)
3. **Monitor security logs** for suspicious activity
4. **Use envelope encryption** for sensitive data
5. **Enable memory protection** in production
6. **Keep dependencies updated**

## Next Steps

After migration:

1. Remove legacy code gradually
2. Update documentation
3. Train team on new APIs
4. Set up monitoring for security metrics
5. Plan regular security audits