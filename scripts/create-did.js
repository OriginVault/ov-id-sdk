import dotenv from 'dotenv';
import { createDID } from '../src/identityManager.ts';
import { userStore } from '../src/userAgent.js';

dotenv.config();

(async () => {
    const { agent } = await packageStore.initialize();
    try {
        const { did, mnemonic, credentials } = await createDID({
            method: 'cheqd:mainnet',
            agent,
        });
        console.log("🔑 DID:", did);
        console.log("🔑 MNEMONIC:", mnemonic);
        console.log("🔑 CREDENTIALS:", credentials);
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        process.exit(1);
    }
})(); 