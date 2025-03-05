import axios from 'axios';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getPrimaryDID } from './identityManager.js';
import { storePrivateKey, retrievePrivateKey } from './storePrivateKeys.js';
import { convertPrivateKeyToRecovery } from './encryption.js';
// Define constants for file paths

// Function to prompt for Cosmos payer seed if not in environment
async function getCosmosPayerSeed(): Promise<string | null> {
    const primaryDid = await getPrimaryDID();
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
    return seed;
}

async function storeCosmosPayerSeed(seed: string): Promise<void> {
    const primaryDid = await getPrimaryDID();
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
    const privateKeyBuffer = Uint8Array.from(Buffer.from(privateKey, 'base64'));
    await storePrivateKey(COSMOS_SEED, privateKeyBuffer);
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
