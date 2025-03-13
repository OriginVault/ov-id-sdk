import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { KeyManagementSystem } from '@veramo/kms-local';
import { VerifiableCredential, IOVAgent, IIdentifier } from '@originvault/ov-types';
import { getUniversalResolverFor, DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { DIDClient } from '@verida/did-client';
import { Resolver } from 'did-resolver';
import dotenv from 'dotenv';
import { getDIDKeys, listDIDs, createDID, importDID } from './identityManager.js';
import { KeyringPair$Json, KeyringPair$Meta } from '@polkadot/keyring/types.js';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { ensureKeyring } from './storePrivateKeys.js';
import { convertRecoveryToPrivateKey } from './encryption.js';

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

// Create a key store instance
const keyStore = new MemoryKeyStore();
export const privateKeyStore = new MemoryPrivateKeyStore();
let signedVCs: VerifiableCredential[] = [];

export declare enum CheqdNetwork {
    Mainnet = "mainnet",
    Testnet = "testnet"
}

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

    cheqdMainnetProvider = new CheqdDIDProvider({
        defaultKms: 'local',
        networkType: 'mainnet' as CheqdNetwork,
        dkgOptions: { chain: 'cheqdMainnet' },
        rpcUrl: process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443',
        cosmosPayerSeed,
    })

    userAgent = createAgent<IOVAgent>({
        plugins: [
            new KeyManager({
                store: keyStore,
            kms: {
                local: new KeyManagementSystem(privateKeyStore),
            },
        }),
        new DIDManager({
            store: new MemoryDIDStore(),
            defaultProvider: 'did:cheqd:mainnet',
            providers: {
                'did:cheqd:mainnet': cheqdMainnetProvider,
                'did:cheqd:testnet': new CheqdDIDProvider({
                    defaultKms: 'local',
                    networkType: 'testnet' as CheqdNetwork,
                    dkgOptions: { chain: 'cheqdTestnet' },
                    rpcUrl: process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443',
                    cosmosPayerSeed: process.env.COSMOS_PAYER_SEED || '',
                }),
                'did:key': new KeyDIDProvider({
                    defaultKms: 'local',
                }),
            }
        }),
        new DIDResolverPlugin({
            resolver: new Resolver({
                ...universalResolver,
                'did:vda': VeridaResolver.resolve,
            })
        }),
        new CredentialPlugin(),
        ],
    })

    const primaryDID = await getPrimaryDID();
    if(primaryDID && didMnemonic) {
        const primaryPrivateKey = await convertRecoveryToPrivateKey(didMnemonic);
        const { credentials } = await importDID(primaryDID, primaryPrivateKey, 'cheqd', userAgent);

        signedVCs.concat(credentials);

    }

    return { agent: userAgent, did: primaryDID || '', key: primaryDID || '', credentials: signedVCs };
}

interface AgentStore {
    initialize: (args: { payerSeed?: string, didRecoveryPhrase?: string }) => Promise<{ agent: IOVAgent, did: string, key: string, credentials: VerifiableCredential[], publishWorkingKey?: (() => Promise<string | undefined>) | null, publishRelease?: (releaseCredential: any, name: string, version: string) => Promise<string | undefined> }>,
    agent: IOVAgent | null,
    keyStore: MemoryKeyStore,
    cheqdMainnetProvider: CheqdDIDProvider | null,
    listDids: (provider?: string) => Promise<IIdentifier[]>,
    getDID: (didString: string) => Promise<KeyringPair$Meta | undefined>,
    createDID: (props: { method: string, alias: string, isPrimary: boolean }) => Promise<{ did: IIdentifier, mnemonic: string, credentials: VerifiableCredential[] }>,
    importDID: (didString: string, privateKey: string, method: string) => Promise<{ did: IIdentifier, credentials: VerifiableCredential[] }>,
    getPrimaryDID: () => Promise<string>,
    [key: string]: any,
}

const userStore: AgentStore = {
    initialize: initializeAgent,
    agent: userAgent,
    cheqdMainnetProvider,
    privateKeyStore,
    keyStore,
    listDids: (provider?: string) => userAgent ? listDIDs(userAgent, provider) : Promise.reject(new Error("User agent not initialized")),
    getDID: (didString: string) => userAgent ? getDIDKeys(didString) : Promise.reject(new Error("User agent not initialized")),
    createDID: (props: { method: string, alias: string, isPrimary: boolean }) => userAgent ? createDID({ ...props, agent: userAgent }) : Promise.reject(new Error("User agent not initialized")),
    importDID: (didString: string, privateKey: string, method: string) => userAgent ? importDID(didString, privateKey, method, userAgent) : Promise.reject(new Error("User agent not initialized")),
    getPrimaryDID: async () => await getPrimaryDID() || Promise.reject(new Error("User agent not initialized")),
}

export { userStore };