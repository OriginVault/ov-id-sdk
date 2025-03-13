import dotenv from 'dotenv';
import { retrieveMnemonicForDID } from '../src/storePrivateKeys.ts';
import { userStore } from '../src/userAgent.js';

dotenv.config();

(async () => {
    await userStore.initialize();
    try {
        const mnemonic = await retrieveMnemonicForDID('did:cheqd:mainnet:3e24a9d3-856f-5f5c-9baa-2b157c0e4d59');
        console.log("🔑 MNEMONIC:", mnemonic);
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        process.exit(1);
    }
})(); 