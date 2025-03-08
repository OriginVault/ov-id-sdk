import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { KeyManagementSystem } from '@veramo/kms-local';
import { getUniversalResolverFor, DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { DIDClient } from '@verida/did-client';
import { Resolver } from 'did-resolver';
import dotenv from 'dotenv';
import { getDIDKeys, listDIDs, createDID, importDID } from './identityManager.js';

dotenv.config();

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

export declare enum CheqdNetwork {
    Mainnet = "mainnet",
    Testnet = "testnet"
}

let cheqdMainnetProvider: CheqdDIDProvider | null = null;
let userAgent: any;

const initializeAgent = async ({ payerSeed }: { payerSeed?: string } = {}) => {
    let cosmosPayerSeed = payerSeed || process.env.COSMOS_PAYER_SEED || '';

    cheqdMainnetProvider = new CheqdDIDProvider({
        defaultKms: 'local',
        networkType: 'mainnet' as CheqdNetwork,
        dkgOptions: { chain: 'cheqdMainnet' },
        rpcUrl: process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443',
        cosmosPayerSeed,
    })

    userAgent = createAgent({
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
}

initializeAgent();

const userStore = {
    initialize: initializeAgent,
    agent: userAgent,
    cheqdMainnetProvider,
    privateKeyStore,
    keyStore,
    listDids: (provider?: string) => listDIDs(userAgent, provider),
    getDID: (didString: string) => getDIDKeys(didString, userAgent),
    createDID: (props: { method: string, alias: string, isPrimary: boolean }) => createDID({ ...props, agent: userAgent }),
    importDID: (didString: string, privateKey: string, method: string) => importDID(didString, privateKey, method, userAgent),
}

export { userAgent, initializeAgent, cheqdMainnetProvider, userStore };