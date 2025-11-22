import dotenv from 'dotenv';
import { retrieveMnemonicForDID } from '../src/storePrivateKeys.ts';
import { userStore } from '../src/userAgent.js';

dotenv.config();

const testnetDID = process.env.TESTNET_DID;

(async () => {
    await userStore.initialize();
    try {
        const mnemonic = await retrieveMnemonicForDID(testnetDID);
        console.log("🔑 MNEMONIC:", mnemonic);
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        process.exit(1);
    }
})(); 