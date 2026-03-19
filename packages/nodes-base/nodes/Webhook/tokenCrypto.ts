import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 12; // 96 bits (NIST recommended for GCM)
const SALT_LENGTH = 16; // 128 bits
const PBKDF2_ITERATIONS = 100000;

export interface TokenPayload {
	email: string;
	formPath: string;
	pageNumber: number;
	timestamp: number;
}

/**
 * Encrypts a token payload using AES-256-GCM.
 * The token format is: salt:iv:authTag:ciphertext (all base64url encoded)
 */
export function encryptToken(secret: string, payload: TokenPayload): string {
	const salt = randomBytes(SALT_LENGTH);
	const iv = randomBytes(IV_LENGTH);
	const key = pbkdf2Sync(secret, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');

	const cipher = createCipheriv(ALGORITHM, key, iv);
	const jsonPayload = JSON.stringify(payload);

	const encrypted = Buffer.concat([cipher.update(jsonPayload, 'utf8'), cipher.final()]);
	const authTag = cipher.getAuthTag();

	// Format: salt:iv:authTag:ciphertext (all base64url)
	return [
		salt.toString('base64url'),
		iv.toString('base64url'),
		authTag.toString('base64url'),
		encrypted.toString('base64url'),
	].join(':');
}

/**
 * Decrypts a token and returns the payload.
 * Throws an error if the token is invalid, tampered, or malformed.
 */
export function decryptToken(secret: string, token: string): TokenPayload {
	const parts = token.split(':');
	if (parts.length !== 4) {
		throw new Error('Invalid token format');
	}

	const [saltB64, ivB64, authTagB64, ciphertextB64] = parts;
	const salt = Buffer.from(saltB64, 'base64url');
	const iv = Buffer.from(ivB64, 'base64url');
	const authTag = Buffer.from(authTagB64, 'base64url');
	const ciphertext = Buffer.from(ciphertextB64, 'base64url');

	const key = pbkdf2Sync(secret, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');

	const decipher = createDecipheriv(ALGORITHM, key, iv);
	decipher.setAuthTag(authTag);

	const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

	return JSON.parse(decrypted.toString('utf8')) as TokenPayload;
}
