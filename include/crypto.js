import crypto from 'crypto';

export const symmetric_encrypt = (key, data) => {
    const nonce = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);

    const ciphertext = Buffer.concat([
        cipher.update(data, 'utf8'),
        cipher.final()
    ]);

    const tag = cipher.getAuthTag();

    return Buffer.concat([ciphertext, tag, nonce]);
}

export const symmetric_decrypt = (key, encryptedData) => {
    const blockSize = 16;
    const tagSize = 16;

    const nonce = encryptedData.slice(-blockSize);
    const tag = encryptedData.slice(-2 * blockSize, -blockSize);
    const ciphertext = encryptedData.slice(0, -blockSize - tagSize);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    return JSON.parse(decrypted.toString('utf8'));
}

export const asymmetric_encrypt = (ida_certificate, data) => {
    const publicKeyObject = crypto.createPublicKey(ida_certificate);
    const encrypted = crypto.publicEncrypt(
        {
            key: publicKeyObject,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        data
    );

    return encrypted;
}

export const asymmetric_decrypt = (partner_private_key, encrypted_data) => {
    const private_key = {
        key: partner_private_key,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
    };

    return crypto.privateDecrypt(private_key, encrypted_data);
}