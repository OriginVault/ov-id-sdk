import { verifyPrimaryDID } from './identityManager.js';

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
