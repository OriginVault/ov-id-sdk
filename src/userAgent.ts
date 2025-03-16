import { VerifiableCredential, IOVAgent } from '@originvault/ov-types';
import { getUniversalResolverFor } from '@veramo/did-resolver';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { DIDClient } from '@verida/did-client';
import dotenv from 'dotenv';
import { getDIDKeys, listDIDs, createDID, importDID } from './identityManager.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { ensureKeyring } from './storePrivateKeys.js';
import { convertRecoveryToPrivateKey } from './encryption.js';
import { createOVAgent, createCheqdProvider, CheqdNetwork, keyStore, privateKeyStore, AgentStore } from './OVAgent.js';

dotenv.config();

export const PRIMARY_DID_WALLET_FILE = path.resolve(os.homedir(), '.originvault-primary-did-wallet.json');

export const ensurePrimaryDIDWallet = async () => {
    if (!fs.existsSync(PRIMARY_DID_WALLET_FILE)) {
        fs.writeFileSync(PRIMARY_DID_WALLET_FILE, JSON.stringify({}, null, 2));
    }
}

const universalResolver = getUniversalResolverFor(['cheqd', 'key']);
const veridaDidClient = new DIDClient({
    network: process.env.NODE_ENV === 'development' ? 'local' : 'banksia' as any,
    rpcUrl: process.env.VDA_RPC_URL || 'https://rpc.verida.net',
});

// Custom resolver for did:vda
const VeridaResolver = {
    resolve: async (did: string) => {
        const didDocument = await veridaDidClient.get(did);
        return {
            didResolutionMetadata: { contentType: 'application/did+ld+json' },
            didDocument,
            didDocumentMetadata: {}
        };
    },
};

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
export let userAgent: IOVAgent | null = null;

const initializeAgent = async ({ payerSeed, didRecoveryPhrase }: { payerSeed?: string, didRecoveryPhrase?: string } = {}) => {
    let cosmosPayerSeed = payerSeed || process.env.COSMOS_PAYER_SEED || '';
    let didMnemonic = didRecoveryPhrase || process.env.USER_DID_RECOVERY_PHRASE || '';

    cheqdMainnetProvider = createCheqdProvider(CheqdNetwork.Mainnet, cosmosPayerSeed, process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443');

    userAgent = createOVAgent(cheqdMainnetProvider, universalResolver, { 'did:vda': VeridaResolver.resolve });

    if(!userAgent) {
        throw new Error("User agent could not be initialized");
    }

    const primaryDID = await getPrimaryDID();
    if(primaryDID && didMnemonic) {
        const primaryPrivateKey = await convertRecoveryToPrivateKey(didMnemonic);
        const { credentials } = await importDID({ didString: primaryDID, privateKey: primaryPrivateKey, method: 'cheqd', agent: userAgent });

        signedVCs.concat(credentials);

    }

    return { agent: userAgent, did: primaryDID || '', key: primaryDID || '', credentials: signedVCs };
}

const userStore: AgentStore = {
    initialize: initializeAgent,
    agent: userAgent,
    cheqdMainnetProvider,
    privateKeyStore,
    keyStore,
    listDids: (provider?: string) => userAgent ? listDIDs(userAgent, provider) : Promise.reject(new Error("User agent not initialized")),
    getDID: (didString: string) => userAgent ? getDIDKeys(didString) : Promise.reject(new Error("User agent not initialized")),
    createDID: (props: { method: string, alias: string, isPrimary?: boolean }) => userAgent ? createDID({ ...props, agent: userAgent }) : Promise.reject(new Error("User agent not initialized")),
    importDID: (didString: string, privateKey: string, method: string) => userAgent ? importDID({ didString, privateKey, method, agent: userAgent }) : Promise.reject(new Error("User agent not initialized")),
    getPrimaryDID: async () => await getPrimaryDID() || Promise.reject(new Error("User agent not initialized")),
}

export { userStore };