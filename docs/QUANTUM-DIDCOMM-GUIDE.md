# Quantum-Safe DIDComm Implementation Guide

This guide explains how to use the quantum-safe DIDComm messaging features in the ov-id-sdk.

## Overview

The quantum-safe DIDComm implementation provides:

- **Kyber768 quantum-safe encryption** for message content
- **AES-256-GCM** for symmetric encryption
- **Enhanced key storage** with encrypted private keys
- **PostgreSQL integration** for quantum key storage
- **Backward compatibility** with existing DIDComm features

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Sender DID    │    │  Quantum Keys    │    │ Recipient DID   │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Ed25519     │ │    │ │ Kyber768     │ │    │ │ Ed25519     │ │
│ │ (Signing)   │ │    │ │ (Encryption) │ │    │ │ (Signing)   │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ Secp256k1   │ │    │ │ Dilithium5   │ │    │ │ Secp256k1   │ │
│ │ (Encryption)│ │    │ │ (Signing)    │ │    │ │ (Encryption)│ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────────┐
                    │   Message Flow      │
                    │                     │
                    │ 1. Generate AES key │
                    │ 2. Encrypt message  │
                    │ 3. Encrypt AES key  │
                    │    with Kyber768    │
                    │ 4. Send encrypted   │
                    │    message          │
                    └─────────────────────┘
```

## Setup

### 1. Install Dependencies

```bash
npm install crystals-kyber-js typeorm
```

### 2. Database Configuration

Set up your PostgreSQL database and configure the connection:

```typescript
import { DataSource } from 'typeorm';
import { KeyEntity } from '@originvault/ov-id-sdk';

const dataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_DATABASE || 'ov_id_sdk',
  entities: [KeyEntity],
  synchronize: true, // Only for development
});

await dataSource.initialize();
```

### 3. Environment Variables

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=your_password
DB_DATABASE=ov_id_sdk

# Encryption
ENCRYPTION_KEY=your-secure-encryption-key-here
```

## Usage

### Basic Quantum Messaging

```typescript
import { 
  QuantumKeyManager, 
  QuantumMessenger 
} from '@originvault/ov-id-sdk';
import { DataSource } from 'typeorm';
import { KeyEntity } from '@originvault/ov-id-sdk';

// Setup
const dataSource = new DataSource({ /* config */ });
await dataSource.initialize();
const keyRepository = dataSource.getRepository(KeyEntity);
const encryptionKey = process.env.ENCRYPTION_KEY!;

// Initialize services
const quantumKeyManager = new QuantumKeyManager(encryptionKey, keyRepository);
const quantumMessenger = new QuantumMessenger(encryptionKey, keyRepository);

// Generate quantum keys for DIDs
const aliceDID = 'did:cheqd:testnet:alice-123';
const bobDID = 'did:cheqd:testnet:bob-456';

await quantumKeyManager.generateQuantumKeys(aliceDID);
await quantumKeyManager.generateQuantumKeys(bobDID);

// Send quantum-encrypted message
const message = 'This message is quantum-safe!';
const encryptedMessage = await quantumMessenger.sendQuantumEncryptedMessage(
  bobDID,
  message,
  aliceDID
);

// Decrypt message
const decryptedMessage = await quantumMessenger.decryptQuantumMessage(
  encryptedMessage,
  bobDID
);

console.log('Decrypted:', decryptedMessage); // "This message is quantum-safe!"
```

### Advanced Key Management

```typescript
// List all quantum keys for a DID
const quantumKeys = await quantumKeyManager.listQuantumKeys(aliceDID);
console.log('Quantum keys:', quantumKeys);

// Get specific quantum public key
const publicKey = await quantumKeyManager.getQuantumPublicKey(aliceDID);
console.log('Public key:', publicKey);

// Get quantum private key (for advanced use cases)
const privateKey = await quantumKeyManager.getQuantumPrivateKey(aliceDID);
console.log('Private key:', privateKey);
```

### Direct Quantum Encryption

```typescript
import { 
  generateKyberKeyPair, 
  encryptWithKyber, 
  decryptWithKyber 
} from '@originvault/ov-id-sdk';

// Generate key pair
const { publicKey, privateKey } = generateKyberKeyPair();

// Encrypt message
const message = 'Direct quantum encryption';
const encrypted = await encryptWithKyber(message, publicKey, privateKey);

// Decrypt message
const decrypted = await decryptWithKyber(encrypted, privateKey);
console.log('Decrypted:', decrypted);
```

## Security Features

### 1. Key Encryption

All private keys are encrypted before storage using:
- **AES-256-GCM** for authenticated encryption
- **Scrypt** for key derivation
- **Random salts and IVs** for each encryption

### 2. Quantum-Safe Algorithms

- **Kyber768**: Post-quantum key encapsulation
- **Dilithium5**: Post-quantum digital signatures (planned)
- **AES-256-GCM**: Symmetric encryption

### 3. Key Storage

- **PostgreSQL**: Quantum keys stored in encrypted database
- **OS Keyring**: Traditional keys in secure OS storage
- **Hybrid approach**: Best of both worlds

## Testing

Run the quantum encryption tests:

```bash
npm test -- --testPathPattern=quantum
```

Run the example:

```bash
npx tsx examples/quantum-didcomm-example.ts
```

## Migration from Traditional DIDComm

### Before (Traditional)

```typescript
import { encryptMessage } from '@originvault/ov-id-sdk';

const result = await encryptMessage(
  recipientDID,
  'Hello world',
  { senderDID: myDID }
);
```

### After (Quantum-Safe)

```typescript
import { QuantumMessenger } from '@originvault/ov-id-sdk';

const quantumMessenger = new QuantumMessenger(encryptionKey, keyRepository);

// Generate quantum keys first
await quantumMessenger.generateQuantumKeys(myDID);
await quantumMessenger.generateQuantumKeys(recipientDID);

// Send quantum-encrypted message
const encryptedMessage = await quantumMessenger.sendQuantumEncryptedMessage(
  recipientDID,
  'Hello quantum world',
  myDID
);
```

## Performance Considerations

### Key Generation
- **Kyber768 key generation**: ~10-50ms
- **Key storage**: ~5-10ms
- **Total setup time**: ~50-100ms per DID

### Message Encryption/Decryption
- **AES encryption**: ~1-5ms
- **Kyber encryption**: ~10-30ms
- **Total per message**: ~20-50ms

### Memory Usage
- **Kyber keys**: ~1.5KB per key pair
- **Encrypted storage**: ~2-3KB per key
- **Minimal overhead**: <1MB for 1000 keys

## Troubleshooting

### Common Issues

1. **"Recipient does not have quantum keys"**
   - Solution: Generate quantum keys for the recipient DID first

2. **Database connection errors**
   - Solution: Check PostgreSQL connection and credentials

3. **Encryption key not set**
   - Solution: Set the `ENCRYPTION_KEY` environment variable

### Debug Mode

Enable debug logging:

```typescript
process.env.DEBUG = 'quantum:*';
```

## Future Enhancements

- [ ] **Dilithium5 signature support**
- [ ] **Hybrid classical/quantum encryption**
- [ ] **Key rotation and management**
- [ ] **Performance optimizations**
- [ ] **Mobile platform support**

## Contributing

When contributing to quantum features:

1. Follow the existing code patterns
2. Add comprehensive tests
3. Update documentation
4. Consider performance implications
5. Ensure backward compatibility

## References

- [Kyber Algorithm Specification](https://pq-crystals.org/kyber/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [DIDComm v2 Specification](https://identity.foundation/didcomm-messaging/spec/)
- [Veramo DIDComm Documentation](https://veramo.io/docs/veramo_agent/didcomm)
