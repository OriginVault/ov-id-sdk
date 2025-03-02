import { execSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { signVC } from '../src/signer'; // Ensure this function signs with the developer's DID
import dotenv from 'dotenv';
import { createHash } from 'crypto';
import { getCertDir } from '../src/config';
import { getStoredPassword } from '../src/storePrivateKeys';

dotenv.config();

const CERT_DIR = getCertDir();

// Ensure the certificate directory exists
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

const MAX_COMMITS_TO_KEEP = 50; // Configurable

const encryptionKey = process.env.ENCRYPTION_KEY;

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

async function generateCommitMetadata(commitHash: string) {
    const developerDID = process.env.DEV_DID || 'did:example:developer'; // Replace with actual DID resolution

    const metadata = {
        id: `urn:ov-commit:${commitHash}`,
        issuer: developerDID,
        issued: new Date().toISOString(),
        commit: {
            hash: commitHash,
            message: execSync(`git log -1 --pretty=%B ${commitHash}`).toString().trim(),
            author: execSync(`git log -1 --pretty=%an <%ae> ${commitHash}`).toString().trim(),
            timestamp: execSync(`git log -1 --pretty=%aI ${commitHash}`).toString().trim(),
        },
        environment: {
            nodeVersion: process.version,
            operatingSystem: `${os.platform()} ${os.release()}`,
        }
    };

    return metadata;
}

async function storeMinimalMetadata(commitHash: string, signedMetadata: any) {
    const metadataString = JSON.stringify(signedMetadata);
    const metadataHash = createHash('sha256').update(metadataString).digest('hex');

    const certPath = path.join(CERT_DIR, `${commitHash}.json`);
    fs.writeFileSync(certPath, JSON.stringify({ commitHash, metadataHash }, null, 2));

    console.log(`✅ Stored minimal metadata: ${certPath}`);
}

// Run this on commit
(async () => {
    try {
        const commitHash = execSync('git rev-parse HEAD').toString().trim();
        const metadata = await generateCommitMetadata(commitHash);
        
        // Retrieve the stored password
        const storedPassword = getStoredPassword();
        if (!storedPassword) {
            throw new Error("Password not found");
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