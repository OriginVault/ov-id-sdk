import crypto from 'crypto';

(async () => {
    // Generate a random 16-byte key and encode it in base64
    const key = crypto.randomBytes(16).toString('base64');
    console.log(`Generated base64 key: ${key}`);

    // Convert the base64 key to a Uint8Array
    const uint8Array = Uint8Array.from(atob(key), c => c.charCodeAt(0));

    // Convert the Uint8Array to a hex string
    const hexString = Array.from(uint8Array)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
    console.log(`Hex string for env variable: ${hexString}`);
})(); 