import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { KeyManagementSystem } from '@veramo/kms-local';
import { getUniversalResolverFor, DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { Resolver } from 'did-resolver';
import { IOVAgent, ManagedKeyInfo, DIDAssertionCredential, VerifiableCredential, IIdentifier } from '@originvault/ov-types';
import { getSelfBundlePrivateKey, getPackageDIDFromPackageJson, getSelfBundleHash } from './packageManager.js';
import { generateDIDKey } from './didKey.js';
import dotenv from 'dotenv';
import { v5 as uuidv5 } from 'uuid';
import { convertRecoveryToPrivateKey } from './encryption.js';
import { importDID, listDIDs, getDIDKeys, createDID } from './identityManager.js';
import { createResource } from './resourceManager.js';
import { getEnvironmentMetadata } from './environment.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { KeyringPair$Json } from '@polkadot/keyring/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const universalResolver = getUniversalResolverFor(['cheqd', 'key']);

// Create a key store instance
const keyStore = new MemoryKeyStore();
const privateKeyStore = new MemoryPrivateKeyStore();

declare enum CheqdNetwork {
    Mainnet = "mainnet",
    Testnet = "testnet"
}

let cheqdMainnetProvider: CheqdDIDProvider | null = null;
let packageAgent: IOVAgent | null = null;
let currentDIDKey: string | null = null;
let signedVCs: VerifiableCredential[] = [];
let publishWorkingKey: (() => Promise<string | undefined>) | null = null;
let publishRelease: (releaseCredential: any, id: string, version: string) => Promise<string | undefined> = async () => {
    return Promise.reject(new Error("publishRelease not initialized"));
};

const initializePackageAgent = async ({ payerSeed, didRecoveryPhrase }: { payerSeed?: string, didRecoveryPhrase?: string } = {}) => {
    let cosmosPayerSeed = payerSeed || process.env.COSMOS_PAYER_SEED || '';
    let didMnemonic = didRecoveryPhrase || process.env.PACKAGE_DID_RECOVERY_PHRASE || '';

    cheqdMainnetProvider = new CheqdDIDProvider({
        defaultKms: 'local',
        networkType: 'mainnet' as CheqdNetwork,
        dkgOptions: { chain: 'cheqdMainnet' },
        rpcUrl: process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443',
        cosmosPayerSeed,
    })

    packageAgent = createAgent<IOVAgent>({
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

    const packageJsonDIDString = await getPackageDIDFromPackageJson();

    if (didMnemonic) {
        const packagePrivateKey = await convertRecoveryToPrivateKey(didMnemonic);
        const { credentials } = await importDID(packageJsonDIDString, packagePrivateKey, 'cheqd', packageAgent);

        signedVCs.concat(credentials);
    }
    
    // Generate did:web after agent initialization
    const bundle = await getSelfBundlePrivateKey();

    const privateKeyHex = Buffer.from(bundle.key).toString("hex")

    const importedKey: ManagedKeyInfo = await packageAgent.keyManagerImport({
        privateKeyHex,
        type: "Ed25519",
        kms: "local"
    });

    const { didKey, id } = await generateDIDKey(bundle.key);

    await packageAgent.didManagerImport({
        did: didKey,
        keys: [{
            kid: importedKey.kid,
            type: 'Ed25519',
            kms: 'local',
            privateKeyHex,
        }],
        provider: `did:key`,
        alias: didKey
    });

    const packageJsonPath = path.join(__dirname, '../package.json');
    const environmentMetadata = await getEnvironmentMetadata(packageJsonPath);
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
                    step: "Get development environment metadata using read-package-json-fast & process.env",
                    result: 'Passed',
                    timestamp: new Date().toISOString()
                }
            ]
        },
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        expirationDate: new Date().toISOString()
    };

    const signedEnvironmentVC = await packageAgent.createVerifiableCredential({
        credential: environmentCredential,
        proofFormat: 'jwt'
    });

    const credentialId = uuidv5(didKey + new Date().toISOString(), uuidv5.URL); // Generate a UUID from the did
    const credential: DIDAssertionCredential = {
        id: credentialId,
        issuer: { id: didKey },
        credentialSubject: {
            id: didKey,
            assertionType: "package-runtime-agent-verification",
            assertionDate: new Date().toISOString(),
            assertionResult: 'Passed',
            assertionDetails: {
                bundleHash: bundle.hash,
                bundleFiles: bundle.files,
                environmentCredential: signedEnvironmentVC
            },
        },
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        expirationDate: new Date().toISOString() + '1000000000000'
    };

    const signedVC = await packageAgent.createVerifiableCredential({
        credential,
        proofFormat: 'jwt'
    });

    if(cheqdMainnetProvider !== null) {
        publishWorkingKey = async () => {
            if(!packageAgent) {
                throw new Error("Package agent not initialized");
            }

            const result: string | undefined = await createResource({
                data: signedVC,
                did: packageJsonDIDString,
                name: `${packageJsonDIDString}-keys`,
                provider: cheqdMainnetProvider as CheqdDIDProvider,
                agent: packageAgent,
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
        if(!packageAgent) {
            throw new Error("Package agent not initialized");
        }

        const resolvedPackageDid = await packageAgent.resolveDid({ didUrl: packageJsonDIDString });
        const alreadyPublished = resolvedPackageDid?.didDocumentMetadata?.linkedResourceMetadata?.some(resource => resource.resourceName === name && resource.resourceVersion === version);
        
        if(!resolvedPackageDid?.didDocument) {
            throw new Error("Failed to resolve package DID");
        }

        if(alreadyPublished) {
            console.warn("Package already published. Skipping.");
            return;        
        }

        const result = await createResource({
            data: releaseCredential,
            did: resolvedPackageDid.didDocument.id,
            name,
            provider: cheqdMainnetProvider as CheqdDIDProvider,
            agent: packageAgent,
            keyStore: privateKeyStore,
            resourceType: 'NPM-Package-Publish-Event',
            version
        });

        if(!result) {
            throw new Error("Failed to publish release");
        }

        return result;
    }

    return { packageAgent, packageJsonDIDString, currentDIDKey, signedVCs, publishWorkingKey, publishRelease };
}

interface AgentStore {
    initialize: (args: { payerSeed?: string, didRecoveryPhrase?: string }) => Promise<{ packageAgent: IOVAgent, packageJsonDIDString: string, currentDIDKey: string, signedVCs: VerifiableCredential[], publishWorkingKey: (() => Promise<string | undefined>) | null, publishRelease: (releaseCredential: any, name: string, version: string) => Promise<string | undefined> }>,
    agent: IOVAgent | null,
    keyStore: MemoryKeyStore,
    cheqdMainnetProvider: CheqdDIDProvider | null,
    listDids: (provider?: string) => Promise<IIdentifier[]>,
    getDID: (didString: string) => Promise<KeyringPair$Json | null>,
    createDID: (props: { method: string, alias: string, isPrimary: boolean }) => Promise<{ did: IIdentifier, mnemonic: string, credentials: VerifiableCredential[] }>,
    importDID: (didString: string, privateKey: string, method: string) => Promise<{ did: IIdentifier, credentials: VerifiableCredential[] }>,
    getPrimaryDID: () => Promise<string>,
    [key: string]: any,
}

const packageStore: AgentStore = {
    initialize: initializePackageAgent,
    agent: packageAgent,
    keyStore,
    cheqdMainnetProvider,
    listDids: async (provider?: string) => packageAgent ? listDIDs(packageAgent, provider) : [] as IIdentifier[],
    getDID: async (didString: string) => getDIDKeys(didString),
    createDID: (props: { method: string, alias: string, isPrimary: boolean }) => packageAgent ? createDID({ ...props, agent: packageAgent }) : Promise.reject(new Error("Package agent not initialized")),
    importDID: (didString: string, privateKey: string, method: string) => packageAgent ? importDID(didString, privateKey, method, packageAgent) : Promise.reject(new Error("Package agent not initialized")),
    getPrimaryDID: async () => await getPackageDIDFromPackageJson(),
    getBundleHash: async () => await getSelfBundleHash(),
    publishWorkingKey,
    publishRelease,
    didKey: currentDIDKey,
}

export { packageStore };