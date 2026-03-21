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
 * Payload for email-only URL tokens (used in formWaitingUrl)
 */
export interface EmailUrlPayload {
	email: string;
	timestamp: number;
}

/**
 * Generic encryption function for any JSON-serializable payload.
 * Uses AES-256-GCM with PBKDF2 key derivation.
 * Token format: salt:iv:authTag:ciphertext (all base64url encoded)
 */
function encryptPayload(secret: string, payload: object): string {
	const salt = randomBytes(SALT_LENGTH);
	const iv = randomBytes(IV_LENGTH);
	const key = pbkdf2Sync(secret, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');

	const cipher = createCipheriv(ALGORITHM, key, iv);
	const jsonPayload = JSON.stringify(payload);

	const encrypted = Buffer.concat([cipher.update(jsonPayload, 'utf8'), cipher.final()]);
	const authTag = cipher.getAuthTag();

	return [
		salt.toString('base64url'),
		iv.toString('base64url'),
		authTag.toString('base64url'),
		encrypted.toString('base64url'),
	].join(':');
}

/**
 * Generic decryption function that returns the raw decrypted JSON.
 * Uses AES-256-GCM with PBKDF2 key derivation.
 * Throws if token is invalid, tampered, or malformed.
 */
function decryptPayload<T>(secret: string, token: string): T {
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

	return JSON.parse(decrypted.toString('utf8')) as T;
}

/**
 * Encrypts a token payload using AES-256-GCM.
 * The token format is: salt:iv:authTag:ciphertext (all base64url encoded)
 */
export function encryptToken(secret: string, payload: TokenPayload): string {
	return encryptPayload(secret, payload);
}

/**
 * Encrypts just the email for use in URL query parameters.
 * Uses the same AES-256-GCM encryption as full tokens.
 */
export function encryptEmailForUrl(secret: string, email: string): string {
	const payload: EmailUrlPayload = {
		email: email.toLowerCase(),
		timestamp: Date.now(),
	};
	return encryptPayload(secret, payload);
}

/**
 * Decrypts a token and returns the payload.
 * Throws an error if the token is invalid, tampered, or malformed.
 */
export function decryptToken(secret: string, token: string): TokenPayload {
	return decryptPayload<TokenPayload>(secret, token);
}

/**
 * Decrypts email from URL query parameter.
 * Returns the email if valid, throws if invalid/tampered/expired.
 */
export function decryptEmailFromUrl(
	secret: string,
	encrypted: string,
	maxAgeMinutes: number = 60,
): string {
	const payload = decryptPayload<EmailUrlPayload>(secret, encrypted);

	// Validate timestamp
	const age = Date.now() - payload.timestamp;
	if (age > maxAgeMinutes * 60 * 1000) {
		throw new Error('Email token expired');
	}

	return payload.email;
}
