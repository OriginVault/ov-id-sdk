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
const privateKeyStore = new MemoryPrivateKeyStore();

export const agent = createAgent({
    plugins: [
        new KeyManager({
            store: keyStore,
            kms: {
                local: new KeyManagementSystem(privateKeyStore),
            },
        }),
        new DIDManager({
            store: new MemoryDIDStore(),
            defaultProvider: 'did:cheqd',
            providers: {
                'did:cheqd': new CheqdDIDProvider({
                    defaultKms: 'local',
                    dkgOptions: { chain: 'cheqdMainnet' },
                    rpcUrl: process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.io',
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
}); 