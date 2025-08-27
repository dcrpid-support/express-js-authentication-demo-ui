import { Buffer } from 'buffer';

export const base64_url_safe_string = (data) => {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);

    let base64 = buffer.toString('base64');
    base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    return base64;
}

export const base64_url_decode = (base64URL) => {
    let base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');

    const padding = base64.length % 4;

    if (padding > 0) {
        base64 += '='.repeat(padding);
    }

    return Buffer.from(base64, 'base64');
}