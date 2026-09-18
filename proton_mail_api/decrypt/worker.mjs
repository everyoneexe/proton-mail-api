/**
 * Proton Mail PGP Worker — stdin/stdout JSON-line daemon.
 *
 * Stays alive, reads JSON requests from stdin (one per line),
 * writes JSON responses to stdout (one per line).
 *
 * Request types:
 *   {"type": "decrypt", "key_password": "...", "primary_key": "...", "body": "...", "address_key": "...", "token": "..."}
 *   {"type": "generate_key", "email": "...", "key_password": "...", "primary_key": "..."}
 *   {"type": "ping"}
 *   {"type": "exit"}
 *
 * Response:
 *   {"ok": true, "data": "..."} or {"ok": false, "error": "..."}
 */

import * as openpgp from 'openpgp';
import { createInterface } from 'readline';
import { webcrypto } from 'crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const PROTON_CONFIG = {
    preferredHashAlgorithm: openpgp.enums.hash.sha256,
    preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
};

// Key cache — avoid re-decrypting same primary key
const keyCache = new Map();

function respond(data) {
    process.stdout.write(JSON.stringify(data) + '\n');
}

async function handleDecrypt(req) {
    const { key_password, primary_key, body, address_key, token } = req;

    if (!key_password || !primary_key || !body) {
        return { ok: false, error: 'key_password, primary_key, body required' };
    }

    try {
        // Decrypt primary key (cached)
        let decryptedPrimary = keyCache.get(key_password + primary_key.slice(0, 50));
        if (!decryptedPrimary) {
            decryptedPrimary = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: primary_key }),
                passphrase: key_password,
            });
            keyCache.set(key_password + primary_key.slice(0, 50), decryptedPrimary);
        }

        let decryptionKey;

        if (token && address_key) {
            // Decrypt token -> address key passphrase
            const tokenMessage = await openpgp.readMessage({ armoredMessage: token });
            const tokenResult = await openpgp.decrypt({
                message: tokenMessage,
                decryptionKeys: decryptedPrimary,
            });
            const passphrase = tokenResult.data;

            // Decrypt address key
            decryptionKey = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: address_key }),
                passphrase: passphrase,
            });
        } else {
            decryptionKey = decryptedPrimary;
        }

        // Decrypt body
        const bodyMessage = await openpgp.readMessage({ armoredMessage: body });
        const result = await openpgp.decrypt({
            message: bodyMessage,
            decryptionKeys: decryptionKey,
        });

        return { ok: true, data: result.data };
    } catch (err) {
        return { ok: false, error: err.message };
    }
}

async function handleGenerateKey(req) {
    const { email, key_password, primary_key } = req;

    if (!email || !key_password || !primary_key) {
        return { ok: false, error: 'email, key_password, primary_key required' };
    }

    try {
        // Decrypt primary key (cached)
        let decryptedPrimary = keyCache.get(key_password + primary_key.slice(0, 50));
        if (!decryptedPrimary) {
            decryptedPrimary = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: primary_key }),
                passphrase: key_password,
            });
            keyCache.set(key_password + primary_key.slice(0, 50), decryptedPrimary);
        }

        // Generate new key
        const { privateKey: newKey } = await openpgp.generateKey({
            type: 'ecc',
            curve: 'curve25519',
            userIDs: [{ email, name: email }],
            format: 'object',
            config: PROTON_CONFIG,
        });

        // Token
        const tokenBytes = new Uint8Array(32);
        crypto.getRandomValues(tokenBytes);
        const tokenPassphrase = Buffer.from(tokenBytes).toString('hex');

        // Encrypt key
        const encryptedKey = await openpgp.encryptKey({
            privateKey: newKey,
            passphrase: tokenPassphrase,
            config: PROTON_CONFIG,
        });
        const encryptedKeyArmored = encryptedKey.armor();

        // Encrypt token with primary key
        const tokenMessage = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: tokenPassphrase }),
            encryptionKeys: decryptedPrimary.toPublic(),
            signingKeys: decryptedPrimary,
            config: PROTON_CONFIG,
        });

        // Fingerprint & SHA256Fingerprints
        const fingerprint = newKey.getFingerprint();

        async function sha256Fingerprint(keyPacket) {
            const pubData = keyPacket.writePublicKey();
            const fpData = new Uint8Array(3 + pubData.length);
            fpData[0] = 0x99;
            fpData[1] = (pubData.length >> 8) & 0xFF;
            fpData[2] = pubData.length & 0xFF;
            fpData.set(pubData, 3);
            return Buffer.from(await crypto.subtle.digest('SHA-256', fpData)).toString('hex');
        }

        const hashHex1 = await sha256Fingerprint(newKey.keyPacket);
        const hashHex2 = newKey.subkeys.length > 0
            ? await sha256Fingerprint(newKey.subkeys[0].keyPacket)
            : hashHex1;

        // SignedKeyList
        const decryptedNewKey = await openpgp.decryptKey({
            privateKey: await openpgp.readPrivateKey({ armoredKey: encryptedKeyArmored }),
            passphrase: tokenPassphrase,
        });

        const keyListData = JSON.stringify([{
            Primary: 1, Flags: 3, Fingerprint: fingerprint,
            SHA256Fingerprints: [hashHex1, hashHex2],
        }]);

        const keyListSignature = await openpgp.sign({
            message: await openpgp.createMessage({ text: keyListData }),
            signingKeys: decryptedNewKey,
            detached: true,
            signatureNotations: [{
                name: 'context@proton.ch',
                value: new TextEncoder().encode('key-transparency.key-list'),
                humanReadable: true, critical: false,
            }],
            config: PROTON_CONFIG,
        });

        const orgSignature = await openpgp.sign({
            message: await openpgp.createMessage({ text: keyListData }),
            signingKeys: decryptedPrimary,
            detached: true,
            config: PROTON_CONFIG,
        });

        return {
            ok: true,
            data: {
                private_key: encryptedKeyArmored,
                token: tokenMessage,
                signed_key_list: { Data: keyListData, Signature: keyListSignature },
                signature: orgSignature,
                fingerprint,
            },
        };
    } catch (err) {
        return { ok: false, error: err.message };
    }
}

// Main loop — read JSON lines from stdin
const rl = createInterface({ input: process.stdin, terminal: false });

respond({ ok: true, data: 'worker ready' });

rl.on('line', async (line) => {
    let req;
    try {
        req = JSON.parse(line);
    } catch {
        respond({ ok: false, error: 'invalid JSON' });
        return;
    }

    const { type } = req;

    if (type === 'ping') {
        respond({ ok: true, data: 'pong' });
    } else if (type === 'exit') {
        respond({ ok: true, data: 'bye' });
        process.exit(0);
    } else if (type === 'decrypt') {
        const result = await handleDecrypt(req);
        respond(result);
    } else if (type === 'generate_key') {
        const result = await handleGenerateKey(req);
        respond(result);
    } else {
        respond({ ok: false, error: `unknown type: ${type}` });
    }
});

rl.on('close', () => process.exit(0));
