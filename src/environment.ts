import { execSync } from 'child_process';
import rpj from 'read-package-json-fast';
import crypto from 'crypto';
import os from 'os';
import { DevelopmentEnvironmentMetadata } from '@originvault/ov-types';

export async function getEnvironmentMetadata(packageJsonPath: string): Promise<DevelopmentEnvironmentMetadata> {
    const packageJson = await rpj(packageJsonPath);
    const normalizedPackageJson = await rpj.normalize(packageJson);
    const metadata: DevelopmentEnvironmentMetadata = {
        environment: process.env.NODE_ENV || `Node.js ${process.version}`,
        packageJson: normalizedPackageJson,
        timestamp: new Date().toISOString(),
        operatingSystem: `${os.platform()} ${os.release()}`,
        hostname: crypto.createHash('sha256').update(os.hostname()).digest('hex'),
        ipAddress: crypto.createHash('sha256').update(
            Object.values(os.networkInterfaces())
                .flat()
                .find((iface) => iface && iface.family === 'IPv4' && !iface.internal)?.address || ''
        ).digest('hex') || '',
    }

    if (process.env.NODE_ENV === 'development') {
        metadata.commitHash = execSync('git rev-parse HEAD').toString().trim();
    }

    return metadata;
};
