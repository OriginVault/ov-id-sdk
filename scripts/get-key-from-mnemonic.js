import dotenv from 'dotenv';
import { convertHexKeyToRecovery, convertRecoveryToPrivateKey } from '../src/encryption.ts';

dotenv.config();

(async () => {
    try {

        const privateKey = await convertHexKeyToRecovery("81bd3eece0dd906018b7c2362385f6cd9eb3f669930d830e98c2e5e1ac307a12b6f30850bd49ef37e4799e65ac2171b6c5aa9d2a0a12ffd5690d836e296bb888");
        console.log("🔑 Key:", privateKey);
        const recovery = await convertRecoveryToPrivateKey(privateKey);
        console.log("🔑 Recovery:", recovery);
    } catch (error) {
        console.error("❌ Error:", error);
        process.exit(1);
    }
})(); 