import { verifyPrimaryDID, QuantumKeyManager } from './identityManager.js';
import { EnhancedKeyStorage } from './storage/EnhancedKeyStorage.js';
import { encryptWithKyber, decryptWithKyber } from './quantum/quantumEncryption.js';
import { KeyEntity } from './storage/entities/KeyEntity.js';
import { Repository } from 'typeorm';

/**
 * Encrypts a message using DIDComm
 */
export async function encryptMessage(
  agent,
  message: string,
  recipientDID: string,
  senderDID?: string
): Promise<string | false> {
  try {
    const packedMessage = await agent.packDIDCommMessage({
      message: {
        id: Date.now().toString(),
        type: 'https://didcomm.org/basicmessage/2.0/message',
        to: recipientDID,
        from: senderDID,
        body: {
          content: message,
        },
      },
      packing: 'authcrypt',
    });

    return packedMessage;
  } catch (error) {
    console.error('❌ Error encrypting message with DIDComm:', error);
    throw error;
  }
}

/**
 * Decrypts a DIDComm-packed message
 */
export async function decryptMessage(
  agent,
  packedMessage: string,
  password: string,
  recipientDID?: string
): Promise<string | false> {
  try {
    const primaryDID = await verifyPrimaryDID(password);
    if (typeof primaryDID !== 'string') return false;

    const { message } = await agent.unpackDIDCommMessage({
      packedMessage,
    });

    return message?.body?.content || false;
  } catch (error) {
    console.error('❌ Error decrypting message with DIDComm:', error);
    throw error;
  }
}

/**
 * Sends a DIDComm message and optionally stores it
 */
export async function sendMessage(
  agent,
  message: string,
  recipientDID: string,
  options: {
    storeMessage?: boolean;
    senderDID?: string;
  } = {}
): Promise<any> {
  try {

    const packedMessage = await encryptMessage(
      agent,
      message,
      recipientDID,
      options.senderDID
    );

    if (!packedMessage) return false;

    const result = await agent.sendDIDCommMessage({
      packedMessage,
      messageId: Date.now().toString(),
      to: recipientDID,
    });

    console.log("🔄 Message sent", result);

    if (options.storeMessage) {
      // Optional: implement your own storage logic
    }

    return {
      id: Date.now().toString(),
      encryptedMessage: packedMessage,
      sender: options.senderDID,
      recipient: recipientDID,
    };
  } catch (error) {
    console.error('❌ Error sending message with DIDComm:', error);
    throw error;
  }
}

// Quantum-safe messaging functions
export class QuantumMessenger {
  private enhancedKeyStorage: EnhancedKeyStorage;
  private quantumKeyManager: QuantumKeyManager;

  constructor(encryptionKey: string, keyRepository: Repository<KeyEntity>) {
    this.enhancedKeyStorage = new EnhancedKeyStorage(encryptionKey, keyRepository);
    this.quantumKeyManager = new QuantumKeyManager(encryptionKey, keyRepository);
  }

  /**
   * Send encrypted message using quantum-safe encryption
   */
  async sendQuantumEncryptedMessage(
    recipientDID: string,
    message: string,
    senderDID: string
  ): Promise<string> {
    try {
      // Get recipient's quantum public key
      const recipientQuantumKey = await this.enhancedKeyStorage.retrieveKey(recipientDID, 'kyber');
      if (!recipientQuantumKey) {
        throw new Error('Recipient does not have quantum keys');
      }

      // Get sender's quantum private key
      const senderPrivateKey = await this.enhancedKeyStorage.getDecryptedPrivateKey(senderDID, 'kyber');
      if (!senderPrivateKey) {
        throw new Error('Sender does not have quantum keys');
      }

      // Encrypt message using quantum-safe encryption
      const encryptedMessage = await encryptWithKyber(
        message,
        recipientQuantumKey.publicKeyHex,
        senderPrivateKey
      );

      return JSON.stringify(encryptedMessage);
    } catch (error) {
      console.error('❌ Error sending quantum-encrypted message:', error);
      throw error;
    }
  }

  /**
   * Decrypt quantum-encrypted message
   */
  async decryptQuantumMessage(
    encryptedMessage: string,
    recipientDID: string
  ): Promise<string> {
    try {
      const messageData = JSON.parse(encryptedMessage);
      
      // Get recipient's quantum private key
      const recipientPrivateKey = await this.enhancedKeyStorage.getDecryptedPrivateKey(recipientDID, 'kyber');
      if (!recipientPrivateKey) {
        throw new Error('Recipient does not have quantum keys');
      }

      // Decrypt message
      return await decryptWithKyber(messageData, recipientPrivateKey);
    } catch (error) {
      console.error('❌ Error decrypting quantum message:', error);
      throw error;
    }
  }

  /**
   * Generate quantum keys for a DID
   */
  async generateQuantumKeys(did: string): Promise<{ publicKey: string; keyId: string }> {
    return await this.quantumKeyManager.generateQuantumKeys(did);
  }

  /**
   * Get quantum public key for a DID
   */
  async getQuantumPublicKey(did: string): Promise<string | null> {
    return await this.quantumKeyManager.getQuantumPublicKey(did);
  }
}

// Standalone quantum messaging functions for backward compatibility
export async function sendQuantumMessage(
  recipientDID: string,
  message: string,
  senderDID: string,
  encryptionKey: string,
  keyRepository: Repository<KeyEntity>
): Promise<string> {
  const messenger = new QuantumMessenger(encryptionKey, keyRepository);
  return await messenger.sendQuantumEncryptedMessage(recipientDID, message, senderDID);
}

export async function decryptQuantumMessage(
  encryptedMessage: string,
  recipientDID: string,
  encryptionKey: string,
  keyRepository: Repository<KeyEntity>
): Promise<string> {
  const messenger = new QuantumMessenger(encryptionKey, keyRepository);
  return await messenger.decryptQuantumMessage(encryptedMessage, recipientDID);
}
