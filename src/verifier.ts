import { getCertDir } from './config.js';
import { execSync } from 'child_process';
import { userAgent } from './userAgent.js';
import fs from 'fs';
import path from 'path';

const LOG_FILE = path.join(getCertDir(), 'verification.log');

function logVerificationResult(commitHash: string, result: boolean) {
    const logEntry = `${new Date().toISOString()} | Commit: ${commitHash} | Result: ${result ? '✅ Verified' : '❌ Failed'}\n`;
    fs.appendFileSync(LOG_FILE, logEntry);
}



export async function verifySoftwareExecution() {
    try {
        const commitHash = execSync('git rev-parse HEAD').toString().trim();
        const certPath = path.join(getCertDir(), `${commitHash}.json`);

        if (!fs.existsSync(certPath)) {
            console.warn("⚠️ No local commit metadata found. Checking remote storage...");
            
            if (process.env.ENABLE_REMOTE_STORAGE === 'true') {
                console.log("⏳ Fetching commit metadata from external storage...");
                // Placeholder: Fetch from Ceramic/Cheqd
                return;
            } else {
                throw new Error("❌ Execution verification failed: No local or remote metadata found.");
            }
        }

        const metadata = JSON.parse(fs.readFileSync(certPath, 'utf-8'));
        const isValid = await userAgent?.verifyVerifiableCredential(metadata);

        logVerificationResult(commitHash, isValid);

        if (!isValid) throw new Error("❌ Invalid signature detected.");

        console.log("✅ Software execution verified.");
        return true;
    } catch (error) {
        console.error(error);
        process.exit(1);
    }
}

export async function verifyCredential({
  credential,
  requiredType,
  requiredIssuer
}: {
  credential: any;
  requiredType: string;
  requiredIssuer: string;
}): Promise<boolean> {
  try {
    // 1. Check credential type
    if (!credential.type?.includes(requiredType)) {
      console.warn(`⚠️ Invalid credential type. Expected: ${requiredType}`);
      return false;
    }

    // 2. Check issuer
    if (credential.issuer !== requiredIssuer) {
      console.warn(`⚠️ Invalid issuer. Expected: ${requiredIssuer}`);
      return false;
    }

    // 3. Verify the credential using the same verification logic as verifySoftwareExecution
    const isValid = await userAgent?.verifyVerifiableCredential(credential);

    if (!isValid) {
      console.warn("⚠️ Invalid credential signature");
      return false;
    }

    console.log("✅ Service credential verified.");
    return true;
  } catch (error) {
    console.error("❌ Error verifying credential:", error);
    return false;
  }
} 