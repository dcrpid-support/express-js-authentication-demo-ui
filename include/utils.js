import crypto from 'crypto';
import fs from 'fs/promises';
import dotenv from 'dotenv';
import path from 'path';

import { base64_url_decode } from './base64.js';
import { asymmetric_decrypt, symmetric_decrypt } from './crypto.js';

dotenv.config();

export const get_current_time = () => {
    return new Date().toISOString().slice(0, -1) + 'Z';
};

export const print_hex_binary = (data) => {
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.from(data, 'utf8'));
    const digest = hash.digest('hex').toUpperCase();

    return digest;
}

export const get_thumbprint = async (filePath) => {
    const certPem = await fs.readFile(filePath);

    const certBase64 = certPem
        .toString()
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r?\n|\r/g, '');

    const certDer = Buffer.from(certBase64, 'base64');

    const fingerprint = crypto.createHash('sha256').update(certDer).digest('hex');
    return fingerprint;
}

export const decrypt_response = async (response) => {
    const partner_id = process.env.PARTNER_ID;
    const partner_private_key_path = path.join(
        '.',
        'keys',
        partner_id,
        `${partner_id}-partner-private-key.pem`
    );

    const response_session_key_encrypted = base64_url_decode(response['responseSessionKey']);
    const response_encrypted = base64_url_decode(response['response']);
    const partner_private_key = await fs.readFile(partner_private_key_path, 'utf8');

    const response_session_key = asymmetric_decrypt(partner_private_key, response_session_key_encrypted);
    const result = symmetric_decrypt(response_session_key, response_encrypted);

    return result;
}

export const create_transaction_id = (len) => {
    return Math.floor(Math.random() * (10**len));
}
