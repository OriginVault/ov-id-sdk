import { IOVAgent } from '@originvault/ov-types';
import { EnvelopeEncryptionService } from '../security/envelope-encryption.service.js';
import { SecureKeyStorage } from '../security/secure-key-storage.js';
import * as ed25519 from '@noble/ed25519';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

export interface SecureSignedMessage {
  message: string;
  signature: string;
  signer: string;
  timestamp: string;
  messageId: string;
  nonce: string;
  keyId: string;
  algorithm: string;
  version: number;
}

export interface SecureDIDCommMessage {
  id: string;
  type: string;
  from: string;
  to: string;
  body: any;
  signature: SecureSignedMessage;
  encrypted?: boolean;
  timestamp: string;
}

export class SecureDIDCommClient {
  private agent: IOVAgent;
  private envelopeService: EnvelopeEncryptionService;
  private keyStorage: SecureKeyStorage;
  private nonceStore: Set<string> = new Set(); // For replay attack prevention

  constructor(agent: IOVAgent) {
    this.agent = agent;
    this.envelopeService = EnvelopeEncryptionService.getInstance();
    this.keyStorage = SecureKeyStorage.getInstance();
  }

  public async sendSecureMessage(
    recipient: string,
    messageType: string,
    content: any,
    signerDID: string,
    password: string,
    encrypt: boolean = true
  ): Promise<SecureDIDCommMessage> {
    try {
      console.log(`📤 Sending secure message from ${signerDID} to ${recipient}`);
      
      // Create base DIDComm message
      const messageId = uuidv4();
      const timestamp = new Date().toISOString();
      const nonce = crypto.randomBytes(16).toString('hex');
      
      let messageBody = content;
      
      // Encrypt message content if requested
      if (encrypt) {
        const encryptedResult = await this.envelopeService.encrypt(JSON.stringify(content));
        messageBody = {
          encrypted: true,
          data: encryptedResult
        };
      }
      
      const didcommMessage = {
        id: messageId,
        type: messageType,
        from: signerDID,
        to: recipient,
        body: messageBody,
        timestamp
      };
      
      // Create signature payload
      const signaturePayload = JSON.stringify({
        messageId,
        type: messageType,
        from: signerDID,
        to: recipient,
        body: messageBody,
        timestamp,
        nonce
      });
      
      // Sign the message
      const signature = await this.signMessageSecurely(signaturePayload, signerDID, password);
      
      const secureMessage: SecureDIDCommMessage = {
        ...didcommMessage,
        signature: {
          ...signature,
          nonce
        },
        encrypted: encrypt
      };
      
      console.log(`✅ Secure message created with ID: ${messageId}`);
      return secureMessage;
      
    } catch (error) {
      console.error('❌ Failed to send secure message:', error);
      throw error;
    }
  }

  public async verifySecureMessage(message: SecureDIDCommMessage): Promise<boolean> {
    try {
      console.log(`🔍 Verifying secure message from ${message.from}`);
      
      // Check for replay attacks
      if (this.nonceStore.has(message.signature.nonce)) {
        console.error('❌ Replay attack detected: nonce already used');
        return false;
      }
      
      // Check message age (prevent old message replay)
      const messageAge = Date.now() - new Date(message.timestamp).getTime();
      if (messageAge > 5 * 60 * 1000) { // 5 minutes
        console.error('❌ Message too old, potential replay attack');
        return false;
      }
      
      // Verify signature
      const isValidSignature = await this.verifyMessageSignature(message.signature);
      if (!isValidSignature) {
        console.error('❌ Invalid message signature');
        return false;
      }
      
      // Add nonce to store (with cleanup after 10 minutes)
      this.nonceStore.add(message.signature.nonce);
      setTimeout(() => {
        this.nonceStore.delete(message.signature.nonce);
      }, 10 * 60 * 1000);
      
      console.log(`✅ Secure message verification PASSED for ${message.from}`);
      return true;
      
    } catch (error) {
      console.error('❌ Error verifying secure message:', error);
      return false;
    }
  }

  private async signMessageSecurely(
    payload: string,
    signerDID: string,
    password: string
  ): Promise<SecureSignedMessage> {
    try {
      // Get the DID identifier
      const identifier = await this.agent.didManagerGet({ did: signerDID });
      if (!identifier || !identifier.keys || identifier.keys.length === 0) {
        throw new Error(`No keys found for DID: ${signerDID}`);
      }

      const keyRef = identifier.keys[0].kid;
      
      // Retrieve private key securely
      const keyData = await this.keyStorage.retrieveKey(keyRef, password);
      if (!keyData) {
        throw new Error(`Failed to retrieve private key for ${keyRef}`);
      }

      // Convert to bytes for signing
      const payloadBytes = Buffer.from(payload, 'utf8');
      const privateKeyBytes = Buffer.from(keyData.privateKeyHex, 'hex');
      
      // Sign with Ed25519
      const signature = await ed25519.sign(payloadBytes, privateKeyBytes);
      
      // Zero out private key from memory
      privateKeyBytes.fill(0);
      
      return {
        message: payload,
        signature: Buffer.from(signature).toString('base64'),
        signer: signerDID,
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
        nonce: crypto.randomBytes(16).toString('hex'),
        keyId: keyRef,
        algorithm: 'Ed25519',
        version: 1
      };
    } catch (error) {
      throw new Error(`Secure message signing failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async verifyMessageSignature(signedMessage: SecureSignedMessage): Promise<boolean> {
    try {
      // Get the DID identifier
      const identifier = await this.agent.didManagerGet({ did: signedMessage.signer });
      if (!identifier || !identifier.keys || identifier.keys.length === 0) {
        console.error(`No keys found for DID: ${signedMessage.signer}`);
        return false;
      }

      // Get public key
      const key = identifier.keys.find(k => k.kid === signedMessage.keyId) || identifier.keys[0];
      const publicKeyBytes = Buffer.from(key.publicKeyHex, 'hex');
      
      // Verify signature
      const signatureBytes = Buffer.from(signedMessage.signature, 'base64');
      const messageBytes = Buffer.from(signedMessage.message, 'utf8');
      
      const isValid = await ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
      
      return isValid;
    } catch (error) {
      console.error('❌ Error verifying message signature:', error);
      return false;
    }
  }

  public async decryptMessageContent(message: SecureDIDCommMessage): Promise<any> {
    if (!message.encrypted || !message.body.encrypted) {
      return message.body;
    }
    
    try {
      const decryptedContent = await this.envelopeService.decrypt(message.body.data);
      return JSON.parse(decryptedContent);
    } catch (error) {
      throw new Error(`Failed to decrypt message content: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}