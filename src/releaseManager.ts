import { execSync } from 'child_process';
import fs from 'fs';
import { CredentialPayload, ICreateVerifiableCredentialArgs, IOVAgent } from '@originvault/ov-types';
import { v5 as uuidv5 } from 'uuid';
import ora from 'ora';
import { parentStore } from './parentAgent.js';
import { userStore } from './userAgent.js';
import { co2 } from "@tgwf/co2";

interface AgentStore {
    initialize: (args: { payerSeed?: string, didRecoveryPhrase?: string }) => Promise<any>;
    agent: IOVAgent;
    currentDIDKey: string;
    publishWorkingKey: () => Promise<boolean>;
    publishRelease: (metadata: any, name: string, version: string) => Promise<any>;
    getBundleHash: () => Promise<string>;
    packageJsonPath: string;
}

export async function signRelease(agentStore: AgentStore | null) {
    await userStore.initialize({});
    const store = agentStore || parentStore;
    const initialize = store.initialize;
    const packageJsonPath = store.packageJsonPath;

    const spinner = ora();
    const startTime = Date.now();

    const timer = setInterval(() => {
        const elapsedSeconds = Math.floor((Date.now() - startTime) / 1000);
        spinner.text = `Signing release metadata... (${elapsedSeconds}s elapsed)`;
    }, 1000);

    spinner.start();

    try {
        const { did, publishWorkingKey, publishRelease }: {
            did: string;
            publishWorkingKey: () => Promise<boolean>;
            publishRelease: (metadata: any, name: string, version: string) => Promise<any>;
            getBundleHash: () => Promise<string>;
        } = await initialize({});

        const commits = execSync('git log --pretty=%H').toString().trim().split('\n');
        if (commits.length === 0) {
            console.log("⚠️ No new commits to sign.");
            clearInterval(timer);
            process.exit(0);
        }

        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        
        const releaseId = uuidv5(`${packageJson.name}-${packageJson.version}-${new Date().toISOString()}`, uuidv5.URL);
        const bundleHash = await store.getBundleHash();

        const releaseMetadata: CredentialPayload = {
            name: packageJson.name,
            version: execSync('npm pkg get version').toString().trim().replace(/"/g, ''),
            bundleHash: bundleHash,
            commits: commits,
            id: releaseId,
            issuer: did
        };

        // const args: ICreateVerifiableCredentialArgs = {
        //     credential: releaseMetadata,
        //     proofFormat: 'jwt'
        // };

        // const co2Emission = new co2();
        // const co2EmissionResult = co2Emission.perByte(JSON.stringify(args).length, false);
        
        // console.log(`🌱 ${packageJson.name}@${packageJson.version} - Release Metadata Credential size in carbon grams: ${co2EmissionResult.toFixed(5)}g`);

        // const signedReleaseMetadata = await agent.createVerifiableCredential(args);

        let publishedWorkingKey;

        try {
            publishedWorkingKey = await publishWorkingKey();
            if (!publishedWorkingKey) {
                console.log(`❌ Failed to publish working key`);
            }
        } catch (error) {
            console.error("❌ Error publishing working key:", error);
            throw error;
        }

        const publishedRelease = await publishRelease(releaseMetadata, packageJson.name, packageJson.version);
        clearInterval(timer);
        spinner.succeed(`✅ Release metadata signatures for ${packageJson.name}@${packageJson.version} published successfully: ${JSON.stringify({
            publishedRelease,
            publishedWorkingKey
        })}`);
    } catch (error) {
        clearInterval(timer);
        console.error("❌ Error signing release metadata:", error);
        process.exit(1);
    }
}