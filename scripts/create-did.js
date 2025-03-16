import dotenv from 'dotenv';
import { createDID } from '../src/identityManager.ts';
import { packageStore } from '../src/packageAgent.ts';
import { privateKeyStore } from '../src/OVAgent.ts';

dotenv.config();


(async () => {
    const { agent } = await packageStore.initialize();

    try {
        const { did, mnemonic, credentials } = await createDID({
            method: 'cheqd:testnet',
            agent,
            privateKeyStore
        });
        console.log("🔑 DID:", did);
        console.log("🔑 MNEMONIC:", mnemonic);
        console.log("🔑 CREDENTIALS:", credentials);
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        process.exit(1);
    }
})(); 