import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { signVC } from '../src/signer.js'; // Ensure this function signs with the developer's DID
import { getCertDir } from '../src/config.js';
import readline from 'readline';
import { getStoredPassword, getPrimaryDID } from '../src/storePrivateKeys.js';
import os from 'os';
import tar from 'tar'; // Import tar
import { createHash } from 'crypto';

dotenv.config();

const CERT_DIR = getCertDir();

// Ensure the certificate directory exists
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

async function getCommitsSinceLastTag() {
    try {
        const lastTag = execSync('git describe --tags --abbrev=0').toString().trim();
        const commitHashes = execSync(`git log ${lastTag}..HEAD --pretty=%H`).toString().trim().split('\n');
        return commitHashes.filter(Boolean); // Remove empty lines
    } catch {
        console.warn("⚠️ No previous tag found, signing all commits.");
        return execSync('git log --pretty=%H').toString().trim().split('\n');
    }
}

// Create a tarball of the entire package at the time of publish
export async function createCommitBundle(commitHash) {
    const bundlePath = path.join(CERT_DIR, `${commitHash}.tar.gz`);
    
    // Get all files in the repository
    const allFiles = execSync('git ls-files')
        .toString()
        .trim()
        .split('\n');

    if (allFiles.length === 0) {
        throw new Error(`❌ No files found in the repository for commit ${commitHash}`);
    }

    await tar.create(
        { gzip: true, file: bundlePath, cwd: process.cwd() },
        allFiles
    );

    return bundlePath;
}

// Compute SHA-256 hash of the tarball
export function computeBundleHash(bundlePath) {
    const bundleContent = fs.readFileSync(bundlePath);
    return createHash('sha256').update(bundleContent).digest('hex');
}


async function signCommit(commitHash, developerDID, storedPassword) {
    const metadata = {
        id: `urn:ov-commit:${commitHash}`,
        issuer: developerDID,
        issued: new Date().toISOString(),
        commit: {
            hash: commitHash,
            message: execSync(`git log -1 --pretty=%B ${commitHash}`).toString().trim(),
            author: execSync(`git log -1 --pretty=format:"%an <%ae>" ${commitHash}`).toString().trim(),
            timestamp: execSync(`git log -1 --pretty=%aI ${commitHash}`).toString().trim(),
        },
        environment: {
            nodeVersion: process.version,
            operatingSystem: `${os.platform()} ${os.release()}`,
        }
    };

    const signedMetadata = await signVC(metadata, storedPassword);
    const certPath = path.join(CERT_DIR, `${commitHash}.json`);
    fs.writeFileSync(certPath, JSON.stringify(signedMetadata, null, 2));
    console.log(`✅ Signed commit metadata stored at: ${certPath}`);
    return signedMetadata;
}

async function signRelease() {
    try {
        const commits = await getCommitsSinceLastTag();
        if (commits.length === 0) {
            console.log("⚠️ No new commits to sign.");
            process.exit(0);
        }

        const developerDID = await getPrimaryDID();
        let storedPassword = getStoredPassword();

        if (!storedPassword.length) {
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });

            storedPassword = await new Promise((resolve) => {
                rl.question("Password not found. Please enter your password: ", (password) => {
                    rl.close();
                    resolve(password);
                });
            });
        }

        const packageJson = JSON.parse(fs.readFileSync('./package.json', 'utf-8'));
        
        // Remove the date string from the file name
        const releaseFileName = `${packageJson.name}-${packageJson.version}.json`;
        const releaseFilePath = path.join(CERT_DIR, releaseFileName);

        console.log(`Release file path: ${releaseFilePath}`); // Debugging output

        // Ensure the directory for the release file exists
        const releaseDir = path.dirname(releaseFilePath);
        if (!fs.existsSync(releaseDir)) {
            fs.mkdirSync(releaseDir, { recursive: true });
        }

        const commitsMetadata = [];

        for (const commitHash of commits) {
            const signedMetadata = await signCommit(commitHash, developerDID, storedPassword);
            const metadataHash = createHash('sha256').update(JSON.stringify(signedMetadata)).digest('hex');
            commitsMetadata.push({ commitHash, metadataHash });
        }

        // Create a bundle of the package and compute its hash
        const bundlePath = await createCommitBundle(commits[0]); // Assuming the first commit for the bundle
        const bundleHash = computeBundleHash(bundlePath);

        const releaseMetadata = {
            id: `urn:ov-release:${new Date().toISOString()}`,
            issuer: developerDID,
            issued: new Date().toISOString(),
            commits: commitsMetadata,
            package: {
                name: packageJson.name,
                version: execSync('npm pkg get version').toString().trim().replace(/"/g, ''),
                bundleHash: bundleHash // Add the bundle hash to the release metadata
            }
        };

        const signedReleaseMetadata = await signVC(releaseMetadata, storedPassword);

        // Store the release metadata
        fs.writeFileSync(releaseFilePath, JSON.stringify(signedReleaseMetadata, null, 2));
        console.log(`✅ Release metadata stored at: ${releaseFilePath}`);
    } catch (error) {
        console.error("❌ Error signing release metadata:", error);
        process.exit(1);
    }
}

(async () => {
    await signRelease();
})(); 