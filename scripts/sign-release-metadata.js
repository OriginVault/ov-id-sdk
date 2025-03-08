import { execSync } from 'child_process';
import fs from 'fs';
import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.js';
import { v5 as uuidv5 } from 'uuid';
import ora from 'ora';


dotenv.config();

async function getCommitsSinceLastTag() {
    try {
        const lastTag = execSync('git describe --tags --abbrev=0').toString().trim();
        const commitHashes = execSync(`git log ${lastTag}..HEAD --pretty=%H`).toString().trim().split('\n');
        return commitHashes.filter(Boolean);
    } catch {
        console.warn("⚠️ No previous tag found, signing all commits.");
        return execSync('git log --pretty=%H').toString().trim().split('\n');
    }
}

async function getCommits() {
    try {
        return execSync('git log --pretty=%H').toString().trim().split('\n');
    } catch {
        console.warn("⚠️ No previous tag found, signing all commits.");
        return [];
    }
}

async function signRelease() {
    const spinner = ora('Signing release metadata...').start();
    try {
        const { packageAgent, currentDIDKey, publishWorkingKey, publishRelease } = await packageStore.initialize();
        const commits = await getCommits();
        if (commits.length === 0) {
            console.log("⚠️ No new commits to sign.");
            process.exit(0);
        }

        const packageJson = JSON.parse(fs.readFileSync('./package.json', 'utf-8'));
        
        const releaseId = uuidv5(`${packageJson.name}-${packageJson.version}-${new Date().toISOString()}`, uuidv5.URL);
        const bundleHash = await packageStore.getBundleHash();

        const releaseMetadata = {
            id: releaseId,
            issuer: currentDIDKey,
            credentialSubject: {
                name: packageJson.name,
                version: execSync('npm pkg get version').toString().trim().replace(/"/g, ''),
                bundleHash: bundleHash,
                commits: commits
            },
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential'],
            expirationDate: new Date().toISOString() + '1000000000000'
        };

        const signedReleaseMetadata = await packageAgent.createVerifiableCredential({
            credential: releaseMetadata,
            proofFormat: 'jwt'
        });

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

        const publishedRelease = await publishRelease(signedReleaseMetadata, packageJson.name);
        spinner.succeed(`✅ Release metadata signatures for ${packageJson.name}@${packageJson.version} published successfully`, {
            publishedRelease,
            publishedWorkingKey
        });
    } catch (error) {
        console.error("❌ Error signing release metadata:", error);
        process.exit(1);
    }
}

(async () => {
    await signRelease();
})(); 