import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { KeyManagementSystem } from '@veramo/kms-local';
import { getUniversalResolverFor, DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { Resolver } from 'did-resolver';
import { getParentDIDFromPackageJson, getParentBundlePrivateKey, getParentBundleHash } from './packageManager.js';
import { generateDIDKey } from './didKey.js';
import dotenv from 'dotenv';
import { DIDAssertionCredential } from '@originvault/ov-types';
import { v5 as uuidv5 } from 'uuid';
import { convertRecoveryToPrivateKey } from './encryption.js';
import { importDID, listDIDs, getDIDKeys, createDID } from './identityManager.js';
import { createResource } from './resourceManager.js';
import { getProductionEnvironmentMetadata } from './environment.js';

dotenv.config();

const universalResolver = getUniversalResolverFor(['cheqd', 'key']);

// Create a key store instance
const keyStore = new MemoryKeyStore();
const privateKeyStore = new MemoryPrivateKeyStore();

declare enum CheqdNetwork {
    Mainnet = "mainnet",
    Testnet = "testnet"
}

interface VerifiableCredential {
  credentialSubject: any;
  issuer: { id: string };
  type: string[];
  '@context': string[];
  issuanceDate: string;
  proof: any;
}

let cheqdMainnetProvider: CheqdDIDProvider | null = null;
let parentAgent: any;
let parentAuth: string | object | null = null;
let currentDIDKey: string | null = null;
let signedVCs: VerifiableCredential[] = [];
let publishWorkingKey: (() => Promise<string | undefined>) | null = null;
let publishRelease: (releaseCredential: any, name: string, version: string) => Promise<string | undefined> = async () => {
    return Promise.reject(new Error("publishRelease not initialized"));
};

const initializeParentAgent = async ({ payerSeed, didRecoveryPhrase }: { payerSeed?: string, didRecoveryPhrase?: string } = {}) => {
    let cosmosPayerSeed = payerSeed || process.env.COSMOS_PAYER_SEED || '';
    let didMnemonic = didRecoveryPhrase || process.env.PARENT_DID_RECOVERY_PHRASE || '';

    cheqdMainnetProvider = new CheqdDIDProvider({
        defaultKms: 'local',
        networkType: 'mainnet' as CheqdNetwork,
        dkgOptions: { chain: 'cheqdMainnet' },
        rpcUrl: process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443',
        cosmosPayerSeed,
    })

    parentAgent = createAgent({
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
                    cosmosPayerSeed,
                }),
                'did:key': new KeyDIDProvider({
                    defaultKms: 'local',
                }),
            }
        }),
        new DIDResolverPlugin({
            resolver: new Resolver(universalResolver)
        }),
        new CredentialPlugin(),
        ],
    })

    const parentDIDString = await getParentDIDFromPackageJson();

    if (didMnemonic) {
        const parentPrivateKey = await convertRecoveryToPrivateKey(didMnemonic);
        const { credentials } = await importDID(parentDIDString, parentPrivateKey, 'cheqd', parentAgent);
        
        signedVCs.concat(credentials);
    }

    // Generate did:web after agent initialization
    const bundle = await getParentBundlePrivateKey();

    const privateKeyHex = Buffer.from(bundle.key).toString("hex")

    const importedKey = await parentAgent.keyManagerImport({
        privateKeyHex,
        type: "Ed25519",
        kms: "local"
    });

    const { didKey, id } = await generateDIDKey(bundle.key);

    await parentAgent.didManagerImport({
        did: didKey,
        keys: [{
            kid: importedKey.id,
            type: 'Ed25519',
            kms: 'local',
            privateKeyHex,
        }],
        provider: `did:key`,
        alias: didKey
    });

    const environmentMetadata = await getProductionEnvironmentMetadata();
    const environmentCredentialId = uuidv5(bundle.hash + new Date().toISOString(), uuidv5.URL);

    const environmentCredential: DIDAssertionCredential = {
        id: environmentCredentialId,
        issuer: { id: didKey },
        credentialSubject: {
            id,
            assertionType: "environment-metadata",
            assertionDate: new Date().toISOString(),
            assertionDetails: environmentMetadata,
            assertionResult: 'Passed',
            verificationSteps: [
                {
                    step: "Get development environment metadata using read-parent-json-fast & process.env",
                    result: 'Passed',
                    timestamp: new Date().toISOString()
                }
            ]
        },
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        expirationDate: new Date().toISOString()
    };

    const signedEnvironmentVC = await parentAgent.createVerifiableCredential({
        credential: environmentCredential,
        proofFormat: 'jwt'
    });

    const credentialId = uuidv5(didKey + new Date().toISOString(), uuidv5.URL); // Generate a UUID from the did
    const credential: DIDAssertionCredential = {
        id: credentialId,
        issuer: { id: didKey },
        credentialSubject: {
            id: didKey,
            assertionType: "parent-runtime-agent-verification",
            assertionDate: new Date().toISOString(),
            assertionResult: 'Passed',
            assertionDetails: {
                bundleHash: bundle.hash,
                bundleFiles: bundle.files,
                environmentMetadata: environmentMetadata,
                environmentCredential: signedEnvironmentVC
            },
        },
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        expirationDate: new Date().toISOString()
    };

    const signedVC = await parentAgent.createVerifiableCredential({
        credential,
        proofFormat: 'jwt'
    });

    if(cheqdMainnetProvider !== null) {
        publishWorkingKey = async () => {
            const result = await createResource({
                data: signedVC,
                did: parentDIDString,
                name: `${parentDIDString}-keys`,
                directory: 'package-keys',
                provider: cheqdMainnetProvider as CheqdDIDProvider,
                agent: parentAgent,
                keyStore: privateKeyStore,
                resourceId: uuidv5(id, uuidv5.URL),
                resourceType: 'Working-Directory-Derived-Key',
                version: credentialId
            });

            if(!result) {
                throw new Error("Failed to publish release");
            }

            return result;
        }
    }

    signedVCs.push(signedVC);
    currentDIDKey = didKey;

    publishRelease = async (releaseCredential: any, name: string, version: string) => {
        const result = await createResource({
            data: releaseCredential,
            did: parentDIDString,
            name,
            version,
            directory: 'versions',  
            provider: cheqdMainnetProvider as CheqdDIDProvider,
            agent: parentAgent,
            keyStore: privateKeyStore,
            resourceType: 'NPM-Package-Publish-Event',
        });

        if(!result) {
            throw new Error("Failed to publish release");
        }

        return result;
    }

    return { parentAgent, parentDIDString, currentDIDKey, signedVCs, publishWorkingKey, publishRelease };
}

const parentStore = {
    initialize: initializeParentAgent,
    agent: parentAgent,
    privateKeyStore,
    cheqdMainnetProvider,
    didKey: currentDIDKey,
    credentials: signedVCs,
    listDids: (provider?: string) => listDIDs(parentAgent, provider),
    getDID: (didString: string) => getDIDKeys(didString, parentAgent),
    createDID: (props: { method: string, alias: string, isPrimary: boolean }) => createDID({ ...props, agent: parentAgent }),
    importDID: (didString: string, privateKey: string, method: string) => importDID(didString, privateKey, method, parentAgent),
    getPrimaryDID: async () => await getParentDIDFromPackageJson(),
    getBundleHash: async () => await getParentBundleHash(),
    publishWorkingKey
}

export { parentStore };