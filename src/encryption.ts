import crypto from 'crypto';

export function encryptPrivateKey(privateKey, password) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(password).digest();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    let encrypted = cipher.update(privateKey, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    return { iv: iv.toString('hex'), encrypted };
}


export function decryptPrivateKey(encryptedData: { iv: string, encrypted: string }, password: string): string | null {
    try {
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const key = crypto.createHash('sha256').update(password).digest();
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf-8');
        decrypted += decipher.final('utf-8');

        return decrypted;
    } catch (error) {
        console.error("❌ Decryption failed");
        return null;
    }
}