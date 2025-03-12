import dotenv from 'dotenv';
import { signRelease } from '../src/releaseManager.ts';
import { packageStore } from '../src/packageAgent.js';

dotenv.config();

(async () => {
    try {
        await signRelease(packageStore);
    } catch (error) {
        console.error("❌ Error signing release metadata:", error);
        process.exit(1);
    }
})(); 