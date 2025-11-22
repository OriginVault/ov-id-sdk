import { DataSource } from 'typeorm';
import { KeyEntity } from '../src/storage/entities/KeyEntity.js';
import { QuantumKeyManager } from '../src/identityManager.js';
import { QuantumMessenger } from '../src/messanger.js';
import { generateKyberKeyPair } from '../src/quantum/quantumEncryption.js';

/**
 * Example demonstrating quantum-safe DIDComm messaging
 */
async function quantumDIDCommExample() {
  console.log('🚀 Starting Quantum DIDComm Example...\n');

  // Setup database connection
  const dataSource = new DataSource({
    type: 'postgres', // or 'sqlite' for testing
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    database: process.env.DB_DATABASE || 'ov_id_sdk',
    entities: [KeyEntity],
    synchronize: true,
  });

  try {
    await dataSource.initialize();
    console.log('✅ Database connected');

    const keyRepository = dataSource.getRepository(KeyEntity);
    const encryptionKey = process.env.ENCRYPTION_KEY || 'your-secure-encryption-key';

    // Initialize quantum services
    const quantumKeyManager = new QuantumKeyManager(encryptionKey, keyRepository);
    const quantumMessenger = new QuantumMessenger(encryptionKey, keyRepository);

    // Create test DIDs
    const aliceDID = 'did:cheqd:testnet:alice-123';
    const bobDID = 'did:cheqd:testnet:bob-456';

    console.log(`👤 Alice DID: ${aliceDID}`);
    console.log(`👤 Bob DID: ${bobDID}\n`);

    // Generate quantum keys for both users
    console.log('🔐 Generating quantum keys...');
    const aliceKeys = await quantumKeyManager.generateQuantumKeys(aliceDID);
    const bobKeys = await quantumKeyManager.generateQuantumKeys(bobDID);

    console.log(`✅ Alice quantum keys generated: ${aliceKeys.keyId}`);
    console.log(`✅ Bob quantum keys generated: ${bobKeys.keyId}\n`);

    // Verify quantum keys are stored
    const alicePublicKey = await quantumKeyManager.getQuantumPublicKey(aliceDID);
    const bobPublicKey = await quantumKeyManager.getQuantumPublicKey(bobDID);

    console.log(`🔑 Alice public key: ${alicePublicKey?.substring(0, 20)}...`);
    console.log(`🔑 Bob public key: ${bobPublicKey?.substring(0, 20)}...\n`);

    // Test quantum encryption directly
    console.log('🧪 Testing quantum encryption...');
    const { publicKey: testPubKey, privateKey: testPrivKey } = generateKyberKeyPair();
    const testMessage = 'Hello from the quantum realm!';
    
    const { encryptWithKyber, decryptWithKyber } = await import('../src/quantum/quantumEncryption.js');
    const encrypted = await encryptWithKyber(testMessage, testPubKey, testPrivKey);
    const decrypted = await decryptWithKyber(encrypted, testPrivKey);
    
    console.log(`📝 Original message: ${testMessage}`);
    console.log(`🔒 Encrypted: ${encrypted.encryptedData.substring(0, 50)}...`);
    console.log(`🔓 Decrypted: ${decrypted}`);
    console.log(`✅ Encryption test: ${testMessage === decrypted ? 'PASSED' : 'FAILED'}\n`);

    // Send quantum-encrypted message from Alice to Bob
    console.log('📨 Sending quantum-encrypted message from Alice to Bob...');
    const secretMessage = 'This message is protected by quantum-safe encryption!';
    
    const encryptedMessage = await quantumMessenger.sendQuantumEncryptedMessage(
      bobDID,
      secretMessage,
      aliceDID
    );

    console.log(`📤 Alice sent encrypted message: ${encryptedMessage.substring(0, 100)}...\n`);

    // Bob decrypts the message
    console.log('📥 Bob decrypting the message...');
    const decryptedMessage = await quantumMessenger.decryptQuantumMessage(
      encryptedMessage,
      bobDID
    );

    console.log(`📝 Bob received: ${decryptedMessage}`);
    console.log(`✅ Message integrity: ${secretMessage === decryptedMessage ? 'VERIFIED' : 'COMPROMISED'}\n`);

    // List quantum keys for both users
    console.log('📋 Listing quantum keys...');
    const aliceQuantumKeys = await quantumKeyManager.listQuantumKeys(aliceDID);
    const bobQuantumKeys = await quantumKeyManager.listQuantumKeys(bobDID);

    console.log(`🔑 Alice has ${aliceQuantumKeys.length} quantum key(s)`);
    console.log(`🔑 Bob has ${bobQuantumKeys.length} quantum key(s)\n`);

    console.log('🎉 Quantum DIDComm example completed successfully!');

  } catch (error) {
    console.error('❌ Error in quantum DIDComm example:', error);
  } finally {
    await dataSource.destroy();
    console.log('🔌 Database connection closed');
  }
}

// Run the example if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  quantumDIDCommExample().catch(console.error);
}

export { quantumDIDCommExample };
