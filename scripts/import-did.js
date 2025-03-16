import dotenv from 'dotenv';
import { importDID } from '../src/identityManager.ts';
import { userStore } from '../src/userAgent.ts';
import { convertRecoveryToPrivateKey } from '../src/encryption.ts';

dotenv.config();

const testnetMnemonic = process.env.TESTNET_MNEMONIC;

(async () => {
    const { agent } = await userStore.initialize();
    try {
        const privateKey = await convertRecoveryToPrivateKey(testnetMnemonic);
        console.log('privateKey', agent);
        const { did, credentials } = await importDID({
            didString: 'did:cheqd:mainnet:280dd37c-aa96-5e71-8548-5125505a968e',
            privateKey,
            method: 'cheqd:mainnet',
            agent,
        });
        console.log("🔑 DID:", did);
        console.log("🔑 CREDENTIALS:", credentials);
    } catch (error) {
        console.error("❌ Error importing DID:", error);
        process.exit(1);
    }
})(); 