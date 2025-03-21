import { createOVAgent, createCheqdProvider, CheqdNetwork, keyStore, privateKeyStore, AgentStore } from './OVAgent.js';
import { getUniversalResolverFor } from '@veramo/did-resolver';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { IOVAgent, ICreateVerifiableCredentialArgs, ManagedKeyInfo, DIDAssertionCredential, VerifiableCredential, IIdentifier } from '@originvault/ov-types';
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
import { co2 } from "@tgwf/co2";
import { getResolver } from "@verida/vda-did-resolver";
import { DIDClient } from '@verida/did-client';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const universalResolver = getUniversalResolverFor(['cheqd', 'key']);
const vdaResolver = getResolver();

const packageJsonPath = path.join(__dirname, '../package.json');

let cheqdMainnetProvider: CheqdDIDProvider | null = null;
let cheqdTestnetProvider: CheqdDIDProvider | null = null;
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

    cheqdMainnetProvider = createCheqdProvider(CheqdNetwork.Mainnet, cosmosPayerSeed, process.env.CHEQD_MAINNET_RPC_URL || 'https://cheqd.originvault.box:443');
    cheqdTestnetProvider = createCheqdProvider(CheqdNetwork.Testnet, cosmosPayerSeed, process.env.CHEQD_TESTNET_RPC_URL || 'https://rpc.cheqd.network');
    packageAgent = createOVAgent(cheqdMainnetProvider, universalResolver, vdaResolver, cheqdTestnetProvider);

    if(!packageAgent) {
        throw new Error("Package agent could not be initialized");
    }

    const packageJsonDIDString = await getPackageDIDFromPackageJson();

    if (didMnemonic) {
        const packagePrivateKey = await convertRecoveryToPrivateKey(didMnemonic);

        try {
            const { credentials } = await importDID({ didString: packageJsonDIDString, privateKey: packagePrivateKey, method: 'cheqd', agent: packageAgent });
            signedVCs.concat(credentials);
        } catch (error) {
            console.error("❌ Error importing DID:", error);
            throw error;
        }
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

    const args: ICreateVerifiableCredentialArgs = {
        credential,
        proofFormat: 'jwt'
    };

    const co2Emission = new co2();
    const co2EmissionResult = co2Emission.perByte(JSON.stringify(args).length);
    
    console.log(`🌱 ${packageJsonDIDString} - Package Runtime Credential size in carbon: ${co2EmissionResult.toFixed(5)}g`);

    const signedVC = await packageAgent.createVerifiableCredential(args);

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

    return { agent: packageAgent, did: packageJsonDIDString, key: currentDIDKey, credentials: signedVCs, publishWorkingKey, publishRelease, privateKeyStore, cheqdTestnetProvider, cheqdMainnetProvider };
}

const packageStore: AgentStore = {
    initialize: initializePackageAgent,
    agent: packageAgent,
    keyStore,
    cheqdMainnetProvider,
    listDids: async (provider?: string) => packageAgent ? listDIDs(packageAgent, provider) : [] as IIdentifier[],
    getDID: async (didString: string) => getDIDKeys(didString),
    createDID: (props: { method: string, alias: string, isPrimary?: boolean }) => packageAgent ? createDID({ ...props, agent: packageAgent }) : Promise.reject(new Error("Package agent not initialized")),
    importDID: (didString: string, privateKey: string, method: string) => packageAgent ? importDID({ didString, privateKey, method, agent: packageAgent }) : Promise.reject(new Error("Package agent not initialized")),
    getPrimaryDID: async () => await getPackageDIDFromPackageJson(),
    getBundleHash: async () => await getSelfBundleHash(),
    publishWorkingKey,
    publishRelease,
    didKey: currentDIDKey,
    packageJsonPath,
    privateKeyStore
}

export { packageStore };