import { VerifiableCredential, IOVAgent } from '@originvault/ov-types';
import { getUniversalResolverFor } from '@veramo/did-resolver';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import dotenv from 'dotenv';
import { getDIDKeys, listDIDs, createDID, importDID } from './identityManager.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { ensureKeyring } from './storePrivateKeys.js';
import { convertRecoveryToPrivateKey } from './encryption.js';
import { createOVAgent, createCheqdProvider, CheqdNetwork, keyStore, getPrivateKeyStore, AgentStore } from './OVAgent.js';
import { DataSource } from 'typeorm';

dotenv.config();

export const PRIMARY_DID_WALLET_FILE = path.resolve(os.homedir(), '.originvault-primary-did-wallet.json');

export const ensurePrimaryDIDWallet = async () => {
    // Check if the path exists and what type it is
    if (fs.existsSync(PRIMARY_DID_WALLET_FILE)) {
        const stat = fs.statSync(PRIMARY_DID_WALLET_FILE);
        if (stat.isDirectory()) {
            console.error("❌ Error: .originvault-primary-did-wallet.json is a directory, not a file");
            console.error("Removing the directory to fix this issue...");
            fs.rmdirSync(PRIMARY_DID_WALLET_FILE);
        } else if (stat.isFile()) {
            // It's already a file, no need to create it
            return;
        }
    }
    
    // File doesn't exist or was a directory that we removed
    fs.writeFileSync(PRIMARY_DID_WALLET_FILE, JSON.stringify({}, null, 2));
}

const universalResolver = getUniversalResolverFor(['cheqd', 'key']);

let signedVCs: VerifiableCredential[] = [];

export async function getPrimaryDID(): Promise<string | null> {
    ensurePrimaryDIDWallet();
    try {
        const kr = await ensureKeyring();
        const pairs = kr.getPairs();
        const primaryPair = pairs.find(p => p.meta?.isPrimary);
        const did = (primaryPair?.meta?.did || '') as string;
        
        if(did) return did;
        
        try {
            // Check if the file exists and is actually a file
            if (fs.existsSync(PRIMARY_DID_WALLET_FILE)) {
                const stat = fs.statSync(PRIMARY_DID_WALLET_FILE);
                if (stat.isDirectory()) {
                    console.error("❌ Error: .originvault-primary-did-wallet.json is a directory, not a file");
                    console.error("Removing the directory to fix this issue...");
                    fs.rmdirSync(PRIMARY_DID_WALLET_FILE);
                    return null;
                }
            }
            
            const storedData = fs.readFileSync(PRIMARY_DID_WALLET_FILE, 'utf8');
            const { meta } = JSON.parse(storedData);
            if(!meta) return null;
            const { did, didCredential } = meta;
            if(!didCredential) return null;
            if(did) return did;
        } catch (error) {
            console.error("❌ Error accessing keyring. File may not exist",);
        }
        return null;
    } catch (error) {
        console.error("❌ Error accessing keyring:", error);
        return null;
    }
}

let cheqdMainnetProvider: CheqdDIDProvider | null = null;
let cheqdTestnetProvider: CheqdDIDProvider | null = null;
export let userAgent: IOVAgent | null = null;

const initializeAgent = async ({ payerSeed, didRecoveryPhrase, dbConnection }: { payerSeed?: string, didRecoveryPhrase?: string, dbConnection?: DataSource } = {}) => {
    let cosmosPayerSeed = payerSeed || process.env.COSMOS_PAYER_SEED || '';
    let didMnemonic = didRecoveryPhrase || process.env.USER_DID_RECOVERY_PHRASE || '';

    cheqdMainnetProvider = createCheqdProvider(CheqdNetwork.Mainnet, cosmosPayerSeed, process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443');
    cheqdTestnetProvider = createCheqdProvider(CheqdNetwork.Testnet, cosmosPayerSeed, process.env.CHEQD_RPC_URL || 'https://rpc.cheqd.network');

    userAgent = createOVAgent({ cheqdProvider: cheqdMainnetProvider, universalResolver, additionalResolvers: {}, cheqdTestnetProvider, dbConnection });

    if(!userAgent) {
        throw new Error("User agent could not be initialized");
    }

    const primaryDID = await getPrimaryDID();
    if(primaryDID && didMnemonic) {
        const primaryPrivateKey = await convertRecoveryToPrivateKey(didMnemonic);
        const { credentials } = await importDID({ didString: primaryDID, privateKey: primaryPrivateKey, method: 'cheqd', agent: userAgent });

        signedVCs.concat(credentials);
    }

    return { agent: userAgent, did: primaryDID || '', key: primaryDID || '', credentials: signedVCs, privateKeyStore: getPrivateKeyStore(), cheqdTestnetProvider, cheqdMainnetProvider };
}

const userStore: AgentStore = {
    initialize: initializeAgent,
    agent: userAgent,
    cheqdMainnetProvider,
    cheqdTestnetProvider,
    privateKeyStore: getPrivateKeyStore(),
    keyStore,
    listDids: (provider?: string) => userAgent ? listDIDs(userAgent, provider) : Promise.reject(new Error("User agent not initialized")),
    getDID: (didString: string) => userAgent ? getDIDKeys(didString) : Promise.reject(new Error("User agent not initialized")),
    createDID: (props: { method: string, alias: string, isPrimary?: boolean }) => userAgent ? createDID({ ...props, agent: userAgent }) : Promise.reject(new Error("User agent not initialized")),
    importDID: (didString: string, privateKey: string, method: string) => userAgent ? importDID({ didString, privateKey, method, agent: userAgent }) : Promise.reject(new Error("User agent not initialized")),
    getPrimaryDID: async () => await getPrimaryDID() || Promise.reject(new Error("User agent not initialized")),
}

export { userStore };