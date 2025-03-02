import fs from 'fs';
import path from 'path';

const CONFIG_FILE = path.join(process.cwd(), '.ov-config.json');

export function getConfig() {
    if (fs.existsSync(CONFIG_FILE)) {
        return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
    }
    return { certDir: 'ov-dev-certs' }; // Default value
}

export function getCertDir() {
    return path.join(process.cwd(), getConfig().certDir);
} 