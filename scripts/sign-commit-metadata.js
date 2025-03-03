import { execSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { signVC } from '../src/signer.js'; // Updated to match previous code
import dotenv from 'dotenv';
import { getCertDir } from '../src/config.js';
import { getStoredPassword } from '../src/storePrivateKeys.js';
import { getPrimaryDID } from '../src/storePrivateKeys.js'; // Import getPrimaryDID
import readline from 'readline'; // Import readline
import tar from 'tar'; // Import tar
import { createHash } from 'crypto';

dotenv.config();

const CERT_DIR = getCertDir();

// Ensure the certificate directory exists
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

const MAX_COMMITS_TO_KEEP = 50; // Configurable

function cleanupOldCommits() {
    const files = fs.readdirSync(CERT_DIR)
        .filter(file => file.endsWith('.json'))
        .map(file => ({
            path: path.join(CERT_DIR, file),
            mtime: fs.statSync(path.join(CERT_DIR, file)).mtime.getTime()
        }))
        .sort((a, b) => b.mtime - a.mtime);

    if (files.length > MAX_COMMITS_TO_KEEP) {
        const oldFiles = files.slice(MAX_COMMITS_TO_KEEP);
        oldFiles.forEach(file => fs.unlinkSync(file.path));
        console.log(`🧹 Cleaned up ${oldFiles.length} old commit metadata files.`);
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

// Generate commit metadata
async function generateCommitMetadata(commitHash) {
    const developerDID = await getPrimaryDID();
    const bundlePath = await createCommitBundle(commitHash);
    const bundleHash = computeBundleHash(bundlePath);

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
        bundleHash, // Include the bundle hash
        environment: {
            nodeVersion: process.version,
            operatingSystem: `${os.platform()} ${os.release()}`,
        }
    };

    return metadata;
}

async function storeMinimalMetadata(commitHash, signedMetadata) {
    const certPath = path.join(CERT_DIR, `${commitHash}.json`);
    fs.writeFileSync(certPath, JSON.stringify({ commitHash, signedMetadata }, null, 2));

    console.log(`✅ Stored environment metadata: ${certPath}`);
}

// Run this on commit
(async () => {
    try {
        const commitHash = execSync('git rev-parse HEAD').toString().trim();
        console.log(`🔍 Commit hash: ${commitHash}`);
        const metadata = await generateCommitMetadata(commitHash);
        
        // Retrieve the stored password
        let storedPassword = getStoredPassword();

        if (!storedPassword.length) {
            // Prompt for password if not found
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

        // Sign the metadata using DID
        const signedMetadata = await signVC(metadata, storedPassword);
        
        // Store as a JSON file in .ov-certificates/
        await storeMinimalMetadata(commitHash, signedMetadata);

        // Call cleanup after signing metadata
        cleanupOldCommits();
    } catch (error) {
        console.error("❌ Error signing commit metadata:", error);
        process.exit(1);
    }
})(); 