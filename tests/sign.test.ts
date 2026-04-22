import { generateKeyPair } from './test-utils';
import {
    signBinary,
    signCleartextText,
    signText,
    verifyBinary,
    verifyCleartextText,
    verifyText,
} from '../nodes/PgpNode/utils/operations';
import fs from 'node:fs';
import path from 'node:path';

test('signs and verifies text message', async () => {
    const { privateKey, publicKey } = await generateKeyPair();
    const message = 'This is a message to sign.';

    const signature = await signText(message, privateKey);

    expect(signature).toBeTruthy();
    expect(signature).toContain('-----BEGIN PGP SIGNATURE-----');

    const isVerified = await verifyText(message, signature, publicKey);

    expect(isVerified).toBeTruthy();
});

test('signs and verifies text message with encrypted private key', async () => {
    const { privateKey, publicKey } = await generateKeyPair('super secret passphrase');
    const message = 'This is a message to sign.';

    const signature = await signText(message, privateKey);

    expect(signature).toBeTruthy();
    expect(signature).toContain('-----BEGIN PGP SIGNATURE-----');

    const isVerified = await verifyText(message, signature, publicKey);

    expect(isVerified).toBeTruthy();
});

test('signs and verifies cleartext message', async () => {
    const { privateKey, publicKey } = await generateKeyPair();
    const message = 'Ola, tudo bem?\n- linha com hifen';

    const signed = await signCleartextText(message, privateKey);

    expect(signed).toContain('-----BEGIN PGP SIGNED MESSAGE-----');
    expect(signed).toContain('-----BEGIN PGP SIGNATURE-----');

    const result = await verifyCleartextText(signed, publicKey);

    expect(result.verified).toBeTruthy();
    expect(result.data).toEqual(message);
});

test('fails verification on tampered cleartext body and returns parsed data', async () => {
    const { privateKey, publicKey } = await generateKeyPair();
    const originalMessage = 'Line A\n- signed line';
    const tamperedMessage = 'Line A\n- changed line';

    const signed = await signCleartextText(originalMessage, privateKey);
    const tamperedSigned = signed.replace('- signed line', '- changed line');

    const result = await verifyCleartextText(tamperedSigned, publicKey);

    expect(result.verified).toBeFalsy();
    expect(result.data).toEqual(tamperedMessage);
});

test('preserves detached signature mode as default', async () => {
    const { privateKey } = await generateKeyPair();
    const message = 'This is a message to sign.';

    const signature = await signText(message, privateKey);

    expect(signature).toContain('-----BEGIN PGP SIGNATURE-----');
    expect(signature).not.toContain('-----BEGIN PGP SIGNED MESSAGE-----');
});

test('verify fails with a different keypair', async () => {
    const { privateKey: privateKey1, publicKey: publicKey1 } = await generateKeyPair();
    const { publicKey: publicKey2 } = await generateKeyPair();
    const message = 'This is a message to sign.';

    const signature = await signText(message, privateKey1);

    expect(signature).toBeTruthy();
    expect(signature).toContain('-----BEGIN PGP SIGNATURE-----');

    const isVerifiedWithFirstKey = await verifyText(message, signature, publicKey1);
    expect(isVerifiedWithFirstKey).toBeTruthy();

    const isVerifiedWithSecondKey = await verifyText(message, signature, publicKey2);
    expect(isVerifiedWithSecondKey).toBeFalsy();
});

test('signs binary data', async () => {
    const { privateKey, publicKey } = await generateKeyPair();

    const binaryData = fs.readFileSync(path.resolve(__dirname, './files/test-image.png'));

    const signature = await signBinary(binaryData, privateKey);

    expect(signature).toBeTruthy();
    expect(signature).toContain('-----BEGIN PGP SIGNATURE-----');

    const isVerified = await verifyBinary(binaryData, signature, publicKey);

    expect(isVerified).toBeTruthy();
});

test('verify fails with a different keypair', async () => {
    const { privateKey: privateKey1, publicKey: publicKey1 } = await generateKeyPair();
    const { publicKey: publicKey2 } = await generateKeyPair();

    const binaryData = fs.readFileSync(path.resolve(__dirname, './files/test-image.png'));

    const signature = await signBinary(binaryData, privateKey1);

    expect(signature).toBeTruthy();
    expect(signature).toContain('-----BEGIN PGP SIGNATURE-----');

    const isVerifiedWithFirstKey = await verifyBinary(binaryData, signature, publicKey1);
    expect(isVerifiedWithFirstKey).toBeTruthy();

    const isVerifiedWithSecondKey = await verifyBinary(binaryData, signature, publicKey2);
    expect(isVerifiedWithSecondKey).toBeFalsy();
});
