import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.ts';

dotenv.config();

const testnetDID = process.env.TESTNET_DID;

(async () => {
    const { agent } = await packageStore.initialize();

    try {
        const did = await agent.resolveDid({ didUrl: testnetDID});
        console.log(did);
    } catch (error) {
        console.error("❌ Error resolving DID:", error);
        process.exit(1);
    }
})(); 