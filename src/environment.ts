import { execSync } from 'child_process';
import rpj from 'read-package-json-fast';
import crypto from 'crypto';
import path from 'path';
import os from 'os';
import { DevelopmentEnvironmentMetadata } from '@originvault/ov-types';

const __dirname = path.dirname(new URL(import.meta.url).pathname); // Define __dirname for ES module

export async function getDevelopmentEnvironmentMetadata(): Promise<DevelopmentEnvironmentMetadata> {
    const packageJson = await rpj(path.join(__dirname, '../package.json'));
    const normalizedPackageJson = await rpj.normalize(packageJson);
    // Combine dependencies and devDependencies
    const allDependencies = {
        ...normalizedPackageJson.dependencies,
        ...normalizedPackageJson.devDependencies
    };

    return {
        environment: process.env.NODE_ENV || `Node.js ${process.version}`,
        packageJson: packageJson,
        timestamp: new Date().toISOString(),
        commitHash: process.env.COMMIT_HASH || execSync('git rev-parse HEAD').toString().trim(),
        operatingSystem: `${os.platform()} ${os.release()}`,
        hostname: crypto.createHash('sha256').update(os.hostname()).digest('hex'),
        ipAddress: crypto.createHash('sha256').update(
            Object.values(os.networkInterfaces())
                .flat()
                .find((iface) => iface && iface.family === 'IPv4' && !iface.internal)?.address || ''
        ).digest('hex') || '',
    }
};

