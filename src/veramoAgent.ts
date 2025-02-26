import { createAgent, IResolver } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { KeyManagementSystem } from '@veramo/kms-local';
import { getUniversalResolverFor, DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { DIDClient } from '@verida/did-client';
import { Resolver } from 'did-resolver'

export declare enum Network {
    LOCAL = "local",
    DEVNET = "devnet",
    BANKSIA = "banksia",
    MYRTLE = "myrtle"
}

const universalResolver = getUniversalResolverFor(['cheqd', 'key']);

const veridaDidClient = new DIDClient({
  network: process.env.NODE_ENV === 'development' ? Network.LOCAL : Network.BANKSIA,
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

export const agent = createAgent<IResolver>({
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
          dkgOptions: { chain: process.env.NODE_ENV === 'development' ? 'cheqdTestnet' : 'cheqdMainnet' },
          rpcUrl: process.env.CHEQD_RPC_URL || (process.env.NODE_ENV === 'development' ? 'https://cheqd-testnet.rpc.extrnode.com' : 'https://cheqd.originvault.io'),
          cosmosPayerSeed: process.env.COSMOS_PAYER_SEED || '',
        }),
        'did:key': new KeyDIDProvider({
          defaultKms: 'local',
        }),
      }
    }),
    new DIDResolverPlugin({ 
      ...universalResolver,
      resolver: new Resolver({
        'did:vda': VeridaResolver.resolve,
      })
    }),
    new CredentialPlugin(),
  ],
}); 