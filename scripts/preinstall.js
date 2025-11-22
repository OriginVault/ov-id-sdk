import { promises as fs } from 'fs';
import path from 'path';
import { verifyCredential } from '../src/verifier';
export async function ensureServiceCredential() {
    const vcPath = path.resolve(process.cwd(), 'service-credential.json');
    // 1. Check file exists
    try {
        await fs.access(vcPath);
    }
    catch {
        throw new Error('❌ Missing required ServiceCredential at project root: service-credential.json');
    }
    // 2. Parse JSON
    let vc;
    try {
        const raw = await fs.readFile(vcPath, 'utf-8');
        vc = JSON.parse(raw);
    }
    catch {
        throw new Error('❌ service-credential.json is not valid JSON');
    }
    // 3. Verify VC
    const valid = await verifyCredential({
        credential: vc,
        requiredType: 'ServiceCredential',
        requiredIssuer: 'did:cheqd:cheqDeepCorp'
    });
    if (!valid) {
        throw new Error('❌ Invalid or expired ServiceCredential');
    }
    console.log('✅ ServiceCredential valid — proceeding with install.');
}
// Only run if this file is being executed directly
if (require.main === module) {
    ensureServiceCredential()
        .catch(err => {
        console.error(err.message);
        process.exit(1);
    });
}
