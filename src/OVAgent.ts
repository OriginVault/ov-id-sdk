import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { KeyManagementSystem } from '@veramo/kms-local';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { Resolver } from 'did-resolver';
import dotenv from 'dotenv';
import { IOVAgent, VerifiableCredential, IIdentifier } from '@originvault/ov-types';
import { KeyringPair$Meta } from '@polkadot/keyring/types.js';

dotenv.config();

export const keyStore = new MemoryKeyStore();
export const privateKeyStore = new MemoryPrivateKeyStore();

export enum CheqdNetwork {
    Mainnet = "mainnet",
    Testnet = "testnet"
}

/**
 * Creates a CheqdDIDProvider for the specified network type.
 * @param networkType - The network type (Mainnet or Testnet).
 * @param cosmosPayerSeed - The Cosmos payer seed.
 * @param rpcUrl - The RPC URL.
 * @returns A CheqdDIDProvider instance.
 */
export function createCheqdProvider(networkType: CheqdNetwork, cosmosPayerSeed: string, rpcUrl: string): CheqdDIDProvider {
    return new CheqdDIDProvider({
        defaultKms: 'local',
        networkType,
        dkgOptions: { chain: networkType === CheqdNetwork.Mainnet ? 'cheqdMainnet' : 'cheqdTestnet' },
        rpcUrl,
        cosmosPayerSeed,
    });
}

/**
 * Creates an OVAgent with the specified plugins and resolvers.
 * @param cheqdProvider - The CheqdDIDProvider instance.
 * @param universalResolver - The universal resolver configuration.
 * @param additionalResolvers - Additional resolvers to include.
 * @returns A configured agent instance.
 */
export function createOVAgent(cheqdProvider: CheqdDIDProvider, universalResolver: any, additionalResolvers: any = {}, cheqdTestnetProvider?: CheqdDIDProvider): IOVAgent {
    const testnetProvider = cheqdTestnetProvider ? cheqdTestnetProvider : createCheqdProvider(CheqdNetwork.Testnet, process.env.COSMOS_PAYER_SEED || '', process.env.CHEQD_RPC_URL || 'https://rpc.cheqd.network');
    return createAgent({
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
                    'did:cheqd': cheqdProvider,
                    'did:cheqd:mainnet': cheqdProvider,
                    'did:cheqd:testnet': testnetProvider,
                    'did:key': new KeyDIDProvider({
                        defaultKms: 'local',
                    }),
                }
            }),
            new DIDResolverPlugin({
                resolver: new Resolver({
                    ...universalResolver,
                    ...additionalResolvers
                })
            }),
            new CredentialPlugin(),
        ],
    });
}

/**
 * Interface for the AgentStore.
 */
export interface AgentStore {
    initialize: (args: { payerSeed?: string, didRecoveryPhrase?: string }) => Promise<{ agent: IOVAgent, did: string, key: string, credentials: VerifiableCredential[], publishWorkingKey?: (() => Promise<string | undefined>) | null, publishRelease?: (releaseCredential: any, name: string, version: string) => Promise<string | undefined> }>,
    agent: IOVAgent | null,
    keyStore: MemoryKeyStore,
    cheqdMainnetProvider: CheqdDIDProvider | null,
    listDids: (provider?: string) => Promise<IIdentifier[]>,
    getDID: (didString: string) => Promise<KeyringPair$Meta | undefined>,
    createDID: (props: { method: string, alias: string, isPrimary?: boolean }) => Promise<{ did: IIdentifier, mnemonic: string, credentials: VerifiableCredential[] }>,
    importDID: (didString: string, privateKey: string, method: string) => Promise<{ did: IIdentifier, credentials: VerifiableCredential[] }>,
    getPrimaryDID: () => Promise<string>,
    [key: string]: any,
} 