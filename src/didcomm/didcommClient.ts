import { IOVAgent } from '@originvault/ov-types';
import { signMessage, verifyMessageSignature, signDIDCommMessage, verifyDIDCommMessageSignature, SignedMessage } from './messageSigning.js';
import { createSessionDID, recreateSessionDID, verifySessionDID, signWithSessionDID, SessionDIDResult, BiometricData } from './sessionDID.js';
import { encryptMessage, decryptMessage, sendMessage } from '../messanger.js';

/**
 * Interface for sending a signed message
 */
export interface SignedMessageOptions {
  recipient: string;
  message: string;
  signer: string;
  encrypt?: boolean;
  storeMessage?: boolean;
  messageType?: string;
}

/**
 * Interface for sending a session-signed message
 */
export interface SessionSignedMessageOptions {
  recipient: string;
  message: string;
  biometricData: BiometricData;
  sessionId: string;
  encrypt?: boolean;
  storeMessage?: boolean;
  messageType?: string;
}

/**
 * Enhanced DIDComm client with signing capabilities
 */
export class DIDCommClient {
  private agent: IOVAgent;

  constructor(agent: IOVAgent) {
    this.agent = agent;
  }

  /**
   * Sends a signed message using a regular DID
   * @param options - Message sending options
   * @returns Promise<any> - The sent message result
   */
  async sendSignedMessage(options: SignedMessageOptions): Promise<any> {
    try {
      console.log(`🔄 Sending signed message from ${options.signer} to ${options.recipient}`);

      // Sign the message first
      const signedMessage = await signMessage(this.agent, options.message, {
        signer: options.signer,
        messageType: options.messageType
      });

      // Create DIDComm message with signature
      const didcommMessage = {
        id: signedMessage.messageId,
        type: options.messageType || 'https://didcomm.org/basicmessage/2.0/message',
        to: options.recipient,
        from: options.signer,
        body: {
          content: options.message,
          signature: signedMessage.signature,
          timestamp: signedMessage.timestamp,
          messageId: signedMessage.messageId
        },
        attachments: [{
          id: 'message-signature',
          description: 'Message signature for verification',
          data: {
            json: signedMessage
          }
        }]
      };

      if (options.encrypt) {
        // Encrypt and send the message
        const result = await sendMessage(
          this.agent,
          JSON.stringify(didcommMessage),
          options.recipient,
          {
            senderDID: options.signer,
            storeMessage: options.storeMessage
          }
        );

        console.log(`✅ Signed and encrypted message sent successfully`);
        return result;
      } else {
        // Send unencrypted but signed message
        console.log(`✅ Signed message prepared (unencrypted)`);
        return {
          didcommMessage,
          signedMessage,
          encrypted: false
        };
      }
    } catch (error) {
      console.error('❌ Error sending signed message:', error);
      throw error;
    }
  }

  /**
   * Sends a message signed with a session DID created from biometrics
   * @param options - Session message sending options
   * @returns Promise<any> - The sent message result
   */
  async sendSessionSignedMessage(options: SessionSignedMessageOptions): Promise<any> {
    try {
      console.log(`🔄 Sending session-signed message to ${options.recipient}`);

      // Create session DID from biometric data
      const sessionDID = await createSessionDID(
        options.biometricData,
        options.sessionId,
        this.agent
      );

      console.log(`🔑 Created session DID: ${sessionDID.did}`);

      // Use the regular signed message flow with the session DID
      const result = await this.sendSignedMessage({
        recipient: options.recipient,
        message: options.message,
        signer: sessionDID.did,
        encrypt: options.encrypt,
        storeMessage: options.storeMessage,
        messageType: options.messageType
      });

      // Add session information to the result
      return {
        ...result,
        sessionDID: {
          did: sessionDID.did,
          sessionId: sessionDID.sessionId,
          keyId: sessionDID.keyId
        }
      };
    } catch (error) {
      console.error('❌ Error sending session-signed message:', error);
      throw error;
    }
  }

  /**
   * Verifies a received signed message
   * @param messageData - The received message data
   * @returns Promise<{ isValid: boolean, signedMessage?: SignedMessage, message?: any }> - Verification result
   */
  async verifyReceivedMessage(messageData: any): Promise<{
    isValid: boolean;
    signedMessage?: SignedMessage;
    message?: any;
    signer?: string;
  }> {
    try {
      console.log(`🔄 Verifying received message`);

      let didcommMessage = messageData;

      // If the message is encrypted, decrypt it first
      if (typeof messageData === 'string' && messageData.includes('JWE')) {
        console.log(`🔓 Decrypting received message`);
        // This would require the recipient's password or key - simplified for now
        // const decrypted = await decryptMessage(this.agent, messageData, recipientPassword);
        // didcommMessage = JSON.parse(decrypted);
        console.log(`ℹ️ Decryption would be handled here with proper credentials`);
        return { isValid: false };
      }

      // Parse the message if it's a string
      if (typeof didcommMessage === 'string') {
        try {
          didcommMessage = JSON.parse(didcommMessage);
        } catch {
          console.error('❌ Could not parse message as JSON');
          return { isValid: false };
        }
      }

      // Find the signature attachment
      const signatureAttachment = didcommMessage.attachments?.find(
        (att: any) => att.id === 'message-signature'
      );

      if (!signatureAttachment) {
        console.log('ℹ️ No signature attachment found - treating as unsigned message');
        return {
          isValid: true,
          message: didcommMessage,
          signer: didcommMessage.from
        };
      }

      const signedMessage: SignedMessage = signatureAttachment.data.json;

      // Verify the signature
      const isValid = await verifyMessageSignature(this.agent, signedMessage);

      if (isValid) {
        console.log(`✅ Message signature verification PASSED`);
        console.log(`   🆔 Signer: ${signedMessage.signer}`);
        console.log(`   ⏰ Timestamp: ${signedMessage.timestamp}`);
      } else {
        console.log(`❌ Message signature verification FAILED`);
      }

      return {
        isValid,
        signedMessage,
        message: didcommMessage,
        signer: signedMessage.signer
      };
    } catch (error) {
      console.error('❌ Error verifying received message:', error);
      return { isValid: false };
    }
  }

  /**
   * Verifies that a session DID was created from specific biometric data
   * @param sessionDID - The session DID to verify
   * @param biometricData - The biometric data to check against
   * @param sessionId - The session ID to check against
   * @returns Promise<boolean> - True if the DID matches the biometric + session
   */
  async verifySessionDIDOrigin(
    sessionDID: string,
    biometricData: BiometricData,
    sessionId: string
  ): Promise<boolean> {
    return verifySessionDID(sessionDID, biometricData, sessionId);
  }

  /**
   * Recreates a session DID from biometric data (for message verification)
   * @param biometricData - The biometric data
   * @param sessionId - The session ID
   * @returns Promise<SessionDIDResult> - The recreated session DID
   */
  async recreateSessionDIDForVerification(
    biometricData: BiometricData,
    sessionId: string
  ): Promise<SessionDIDResult> {
    return recreateSessionDID(biometricData, sessionId, this.agent);
  }

  /**
   * Signs a raw message with any DID
   * @param message - The message to sign
   * @param signerDID - The DID to use for signing
   * @param options - Additional signing options
   * @returns Promise<SignedMessage> - The signed message
   */
  async signRawMessage(
    message: string,
    signerDID: string,
    options?: { messageType?: string; includeNonce?: boolean }
  ): Promise<SignedMessage> {
    return signMessage(this.agent, message, {
      signer: signerDID,
      messageType: options?.messageType,
      includeNonce: options?.includeNonce
    });
  }

  /**
   * Verifies a raw signed message
   * @param signedMessage - The signed message to verify
   * @returns Promise<boolean> - True if signature is valid
   */
  async verifyRawMessage(signedMessage: SignedMessage): Promise<boolean> {
    return verifyMessageSignature(this.agent, signedMessage);
  }

  /**
   * Gets the agent instance
   * @returns IOVAgent - The Veramo agent
   */
  getAgent(): IOVAgent {
    return this.agent;
  }
}
