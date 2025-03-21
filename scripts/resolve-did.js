import dotenv from 'dotenv';
import { getResolver } from '@verida/vda-did-resolver';
dotenv.config();

const testnetDID = process.env.TESTNET_DID;

(async () => {
    const resolver = getResolver();
    try {
        const did = await resolver.vda(testnetDID);
        console.log(did);
    } catch (error) {
        console.error("❌ Error resolving DID:", error);
        process.exit(1);
    }
})(); 