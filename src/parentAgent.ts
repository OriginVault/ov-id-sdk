import { createOVAgent, createCheqdProvider, CheqdNetwork, keyStore, privateKeyStore, AgentStore } from './OVAgent';
import { MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { getUniversalResolverFor } from '@veramo/did-resolver';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';
import { ICreateVerifiableCredentialArgs, DIDAssertionCredential, VerifiableCredential, IResolver, IKeyManager, ICredentialPlugin, IDIDManager, TAgent, IIdentifier, IOVAgent } from '@originvault/ov-types';
import { getParentDIDFromPackageJson, getParentBundlePrivateKey, getParentBundleHash } from './packageManager.js';
import { generateDIDKey } from './didKey.js';
import dotenv from 'dotenv';
import { v5 as uuidv5 } from 'uuid';
import { convertRecoveryToPrivateKey } from './encryption.js';
import { importDID, listDIDs, getDIDKeys, createDID } from './identityManager.js';
import { createResource } from './resourceManager.js';
import { getEnvironmentMetadata } from './environment.js';
import path from 'path';
import { KeyringPair$Meta } from '@polkadot/keyring/types.js';
import { co2 } from "@tgwf/co2";

dotenv.config();

const universalResolver = getUniversalResolverFor(['cheqd', 'key']);
const packageJsonPath = path.join(process.cwd(), './package.json');

let cheqdMainnetProvider: CheqdDIDProvider | null = null;
export let parentAgent: IOVAgent | null = null;
let currentDIDKey: string | null = null;
let signedVCs: VerifiableCredential[] = [];
let publishWorkingKey: (() => Promise<string | undefined>) | null = null;
let publishRelease: (releaseCredential: any, name: string, version: string) => Promise<string | undefined> = async () => {
    return Promise.reject(new Error("publishRelease not initialized"));
};

const initializeParentAgent = async ({ payerSeed, didRecoveryPhrase }: { payerSeed?: string, didRecoveryPhrase?: string } = {}) => {
    let cosmosPayerSeed = payerSeed || process.env.COSMOS_PAYER_SEED || '';
    let didMnemonic = didRecoveryPhrase || process.env.PARENT_DID_RECOVERY_PHRASE || '';

    cheqdMainnetProvider = createCheqdProvider(CheqdNetwork.Mainnet, cosmosPayerSeed, process.env.CHEQD_RPC_URL || 'https://cheqd.originvault.box:443');

    parentAgent = createOVAgent(cheqdMainnetProvider, universalResolver);

    if(!parentAgent) {
        throw new Error("Parent agent could not be initialized");
    }

    const parentDIDString = await getParentDIDFromPackageJson();

    if (didMnemonic) {
        const parentPrivateKey = await convertRecoveryToPrivateKey(didMnemonic);
        const { credentials } = await importDID({ didString: parentDIDString, privateKey: parentPrivateKey, method: 'cheqd', agent: parentAgent });

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

    const args: ICreateVerifiableCredentialArgs = {
        credential,
        proofFormat: 'jwt'
    };

    const co2Emission = new co2();
    const co2EmissionResult = co2Emission.perByte(JSON.stringify(args).length);
    
    console.log(`🌱 ${parentDIDString} - Parent Runtime Credential size in carbon: ${co2EmissionResult.toFixed(5)}g`);
    const signedVC = await parentAgent.createVerifiableCredential(args);

    if(cheqdMainnetProvider !== null) {
        publishWorkingKey = async () => {
            if(!parentAgent) {
                throw new Error("Parent agent not initialized");
            }

            const result = await createResource({
                data: signedVC,
                did: parentDIDString,
                name: `${parentDIDString}-keys`,
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
        if(!parentAgent) {
            throw new Error("Parent agent not initialized");
        }

        const resolvedPackageDid = await parentAgent?.resolveDid({ didUrl: parentDIDString });
        const alreadyPublished = resolvedPackageDid?.didDocumentMetadata?.linkedResourceMetadata?.some(resource => resource.resourceVersion === version);
        if(alreadyPublished) {
            console.warn("Package already published. Skipping.");
            return;
        }

        const result = await createResource({
            data: releaseCredential,
            did: parentDIDString,
            name,
            version,
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

    return { agent: parentAgent, did: parentDIDString, key: currentDIDKey, credentials: signedVCs, publishWorkingKey, publishRelease };
}

const parentStore: AgentStore = {
    initialize: initializeParentAgent,
    agent: parentAgent,
    keyStore,
    cheqdMainnetProvider,
    didKey: currentDIDKey,
    credentials: signedVCs,
    listDids: async (provider?: string) => parentAgent ? listDIDs(parentAgent, provider) : [] as IIdentifier[],
    getDID: async (didString: string) => getDIDKeys(didString),
    createDID: (props: { method: string, alias: string, isPrimary?: boolean }) => parentAgent ? createDID({ ...props, agent: parentAgent }) : Promise.reject(new Error("Parent agent not initialized")),
    importDID: (didString: string, privateKey: string, method: string) => parentAgent ? importDID({ didString, privateKey, method, agent: parentAgent }) : Promise.reject(new Error("Parent agent not initialized")),
    getPrimaryDID: async () => await getParentDIDFromPackageJson(),
    getBundleHash: async () => await getParentBundleHash(),
    publishWorkingKey,
    packageJsonPath
}

export { parentStore };