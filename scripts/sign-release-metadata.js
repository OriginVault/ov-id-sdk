import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { signVC } from '../src/signer'; // Ensure this function signs with the developer's DID
import { getCertDir } from '../src/config';

dotenv.config();

const CERT_DIR = getCertDir();

// Ensure the certificate directory exists
if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

// Define the password variable
const encryptionKey = process.env.ENCRYPTION_KEY;

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

(async () => {
    try {
        const commits = await getCommitsSinceLastTag();
        if (commits.length === 0) {
            console.log("⚠️ No new commits to sign.");
            process.exit(0);
        }

        const developerDID = process.env.DEV_DID || 'did:example:developer';
        const commitMetadata = commits.map((commitHash) => {
            const certPath = path.join(CERT_DIR, `${commitHash}.json`);
            if (fs.existsSync(certPath)) {
                return JSON.parse(fs.readFileSync(certPath, 'utf-8'));
            } else {
                return { commitHash, error: "Commit metadata not found." };
            }
        });

        const releaseMetadata = {
            id: `urn:ov-release:${new Date().toISOString()}`,
            issuer: developerDID,
            issued: new Date().toISOString(),
            commits: commitMetadata,
            package: {
                name: JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf-8')).name,
                version: execSync('npm pkg get version').toString().trim().replace(/"/g, ''),
            }
        };

        // Sign the entire release metadata
        const signedReleaseMetadata = await signVC(releaseMetadata, encryptionKey);

        // Store as JSON
        const releaseCertPath = path.join(CERT_DIR, 'latest-release.json');
        fs.writeFileSync(releaseCertPath, JSON.stringify(signedReleaseMetadata, null, 2));

        console.log(`✅ Signed release metadata stored at: ${releaseCertPath}`);
    } catch (error) {
        console.error("❌ Error signing release metadata:", error);
        process.exit(1);
    }
})(); 