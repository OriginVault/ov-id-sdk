import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.js';
import { createDID } from '../src/identityManager.ts';
import { sendMessage } from '../src/messanger.js';

dotenv.config();

(async () => {
  const { agent } = await packageStore.initialize();
  try {
    const key1 = await createDID({
      method: 'key',
      agent,
    });

    const key2 = await createDID({
      method: 'key',
      agent,
    });

    const messageKey1 = await agent.keyManagerCreate({
      type: 'X25519',
      kms: 'local',
    });


    const messageKey2 = await agent.keyManagerCreate({
      type: 'X25519',
      kms: 'local',
    });

    await agent.didManagerAddKey({
      did: key1.did.did,
      key: messageKey1,
    });

    await agent.didManagerAddKey({
      did: key2.did.did,
      key: messageKey2,
    });

    // Send a DIDComm message
    const result = await sendMessage(
      agent,
      'Hello from test!',
      key2.did.did,
      {
        senderDID: key1.did.did,
        storeMessage: false,
      }
    );

    console.log("✅ Message sent:");
    console.log(result);
  } catch (error) {
    console.error('❌ Error in sendMessage test:', error);
    process.exit(1);
  }
})();