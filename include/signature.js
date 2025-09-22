import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { SignJWT, importPKCS8 } from 'jose';
import dotenv from 'dotenv';

if (!globalThis.crypto) {
  globalThis.crypto = require('crypto').webcrypto;
}

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const create_signature = async (payload, keyLocation) => {
    const partnerId = process.env.PARTNER_ID;
    if (!partnerId) throw new Error('Missing PARTNER_ID in environment variables');

    const privateKeyPem = await fs.readFile(keyLocation, 'utf8');

    const certPath = path.join(
        __dirname,
        '..',
        'keys',
        partnerId,
        `${partnerId}-signedcertificate.cer`
    );

    let signedCertificate = await fs.readFile(certPath, 'utf8');

    signedCertificate = signedCertificate
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r?\n/g, '');

    const privateKey = await importPKCS8(privateKeyPem, 'RS256');

    const jwt = await new SignJWT(payload)
        .setProtectedHeader({
            x5c: [signedCertificate],
            alg: 'RS256',
        })
        .sign(privateKey);

    const parts = jwt.split('.');
    const detachedJwt = `${parts[0]}..${parts[2]}`;

    return detachedJwt;
}