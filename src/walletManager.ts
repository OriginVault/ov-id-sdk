import axios from 'axios';
import { userAgent } from './userAgent.js';
import { storePrivateKey, retrievePrivateKey } from './storePrivateKeys.js';
import { convertPrivateKeyToRecovery } from './encryption.js';

// Function to prompt for Cosmos payer seed if not in environment
async function getCosmosPayerSeed(): Promise<string | null> {
    const primaryDid = await userAgent?.getPrimaryDID();
    if (!primaryDid) {
        console.warn("Primary DID not found. Cannot retrieve Cosmos payer seed.");
        return null;
    }
    const COSMOS_SEED = `${primaryDid}-cosmos-payer`;
    const seed = await retrievePrivateKey(COSMOS_SEED);
    if (!seed) {
        console.warn("Cosmos payer seed not found. Cannot retrieve Cosmos payer seed.");
        return null;
    }
    // Convert the seed to a base64 string
    const seedBase64 = Buffer.from(seed).toString('base64');
    const mnemonic = await convertPrivateKeyToRecovery(seedBase64);

    return mnemonic;
}

async function storeCosmosPayerSeed(seed: string): Promise<void> {
    const primaryDid = await userAgent?.getPrimaryDID();
    if (!primaryDid) {
        console.warn("Primary DID not found. Cannot store Cosmos payer seed.");
        return;
    }
    const COSMOS_SEED = `${primaryDid}-cosmos-payer`;
    const privateKey = await convertPrivateKeyToRecovery(seed);
    if (!privateKey) {
        console.warn("Failed to convert private key to recovery.");
        return;
    }
    const privateKeyBuffer = Buffer.from(privateKey, 'base64');
    await storePrivateKey(COSMOS_SEED, privateKeyBuffer, "default");
    console.log("Cosmos payer seed stored successfully.");

    return;
}

// Function to check wallet balance
async function checkBalance(address: string): Promise<number> {
    try {
        const response = await axios.get(`https://api.cosmos.network/bank/balances/${address}`);
        const balance = response.data.result[0]?.amount || 0;
        return parseFloat(balance);
    } catch (error) {
        console.error("❌ Error fetching balance:", error);
        return 0;
    }
}

// Function to show recovery phrase
async function showRecoveryPhrase(): Promise<string | null> {
    let recoveryPhrase: string | null = process.env.RECOVERY_PHRASE || null; // Attempt to get recovery phrase from environment
    if (!recoveryPhrase) {
        console.warn("A cosmos wallet is required to proceed with Cheqd blockchain transactions.");
    }

    return recoveryPhrase;
}

export { getCosmosPayerSeed, checkBalance, showRecoveryPhrase, storeCosmosPayerSeed };
