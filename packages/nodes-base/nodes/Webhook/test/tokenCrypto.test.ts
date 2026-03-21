import {
	encryptToken,
	decryptToken,
	encryptEmailForUrl,
	decryptEmailFromUrl,
	type TokenPayload,
} from '../tokenCrypto';

describe('Token Crypto', () => {
	const testSecret = 'test-encryption-secret-32-chars!';

	describe('encryptToken / decryptToken', () => {
		it('should encrypt and decrypt token payload correctly', () => {
			const payload: TokenPayload = {
				email: 'user@example.com',
				formPath: 'test/form',
				pageNumber: 1,
				timestamp: Date.now(),
			};
			const encrypted = encryptToken(testSecret, payload);
			const decrypted = decryptToken(testSecret, encrypted);
			expect(decrypted).toEqual(payload);
		});

		it('should generate unique tokens for same payload (random salt/IV)', () => {
			const payload: TokenPayload = {
				email: 'user@example.com',
				formPath: 'test',
				pageNumber: 1,
				timestamp: Date.now(),
			};
			const token1 = encryptToken(testSecret, payload);
			const token2 = encryptToken(testSecret, payload);
			expect(token1).not.toBe(token2); // Different salt/IV each time
		});

		it('should produce tokens in correct format (4 base64url parts)', () => {
			const payload: TokenPayload = {
				email: 'user@example.com',
				formPath: 'test',
				pageNumber: 1,
				timestamp: Date.now(),
			};
			const encrypted = encryptToken(testSecret, payload);
			const parts = encrypted.split(':');
			expect(parts.length).toBe(4);
			// Each part should be valid base64url
			parts.forEach((part) => {
				expect(() => Buffer.from(part, 'base64url')).not.toThrow();
			});
		});

		it('should reject tampered tokens (modified ciphertext)', () => {
			const payload: TokenPayload = {
				email: 'user@example.com',
				formPath: 'test',
				pageNumber: 1,
				timestamp: Date.now(),
			};
			const encrypted = encryptToken(testSecret, payload);
			const tampered = encrypted.slice(0, -5) + 'XXXXX';
			expect(() => decryptToken(testSecret, tampered)).toThrow();
		});

		it('should reject tokens with wrong secret', () => {
			const payload: TokenPayload = {
				email: 'user@example.com',
				formPath: 'test',
				pageNumber: 1,
				timestamp: Date.now(),
			};
			const encrypted = encryptToken(testSecret, payload);
			expect(() => decryptToken('wrong-secret-32-characters-long!', encrypted)).toThrow();
		});

		it('should reject malformed tokens (wrong number of parts)', () => {
			expect(() => decryptToken(testSecret, 'not:valid:token')).toThrow('Invalid token format');
			expect(() => decryptToken(testSecret, 'a:b:c:d:e')).toThrow('Invalid token format');
		});

		it('should reject empty token', () => {
			expect(() => decryptToken(testSecret, '')).toThrow('Invalid token format');
		});

		it('should preserve all payload fields', () => {
			const payload: TokenPayload = {
				email: 'UPPERCASE@EXAMPLE.COM',
				formPath: 'some/nested/path/with-special-chars',
				pageNumber: 42,
				timestamp: 1234567890123,
			};
			const encrypted = encryptToken(testSecret, payload);
			const decrypted = decryptToken(testSecret, encrypted);
			expect(decrypted.email).toBe(payload.email);
			expect(decrypted.formPath).toBe(payload.formPath);
			expect(decrypted.pageNumber).toBe(payload.pageNumber);
			expect(decrypted.timestamp).toBe(payload.timestamp);
		});
	});

	describe('encryptEmailForUrl / decryptEmailFromUrl', () => {
		it('should encrypt and decrypt email correctly', () => {
			const email = 'user@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);
			const decrypted = decryptEmailFromUrl(testSecret, encrypted);
			expect(decrypted).toBe('user@example.com');
		});

		it('should normalize email to lowercase', () => {
			const email = 'User@Example.COM';
			const encrypted = encryptEmailForUrl(testSecret, email);
			const decrypted = decryptEmailFromUrl(testSecret, encrypted);
			expect(decrypted).toBe('user@example.com');
		});

		it('should generate unique tokens for same email', () => {
			const email = 'user@example.com';
			const token1 = encryptEmailForUrl(testSecret, email);
			const token2 = encryptEmailForUrl(testSecret, email);
			expect(token1).not.toBe(token2); // Different due to timestamp and random salt/IV
		});

		it('should reject expired tokens', () => {
			const email = 'user@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);

			// Mock Date.now to simulate expiry
			const originalDateNow = Date.now;
			Date.now = () => originalDateNow() + 61 * 60 * 1000; // 61 minutes later

			expect(() => decryptEmailFromUrl(testSecret, encrypted, 60)).toThrow('Email token expired');

			Date.now = originalDateNow;
		});

		it('should accept tokens within expiry window', () => {
			const email = 'user@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);

			// Mock Date.now to simulate time passing but within window
			const originalDateNow = Date.now;
			Date.now = () => originalDateNow() + 30 * 60 * 1000; // 30 minutes later

			expect(() => decryptEmailFromUrl(testSecret, encrypted, 60)).not.toThrow();

			Date.now = originalDateNow;
		});

		it('should use default 60 minute expiry', () => {
			const email = 'user@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);

			// Mock Date.now to simulate 59 minutes
			const originalDateNow = Date.now;
			Date.now = () => originalDateNow() + 59 * 60 * 1000;

			expect(() => decryptEmailFromUrl(testSecret, encrypted)).not.toThrow();

			// 61 minutes should fail
			Date.now = () => originalDateNow() + 61 * 60 * 1000;
			expect(() => decryptEmailFromUrl(testSecret, encrypted)).toThrow('Email token expired');

			Date.now = originalDateNow;
		});

		it('should reject tampered email tokens', () => {
			const email = 'user@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);
			const tampered = encrypted.slice(0, -3) + 'XXX';
			expect(() => decryptEmailFromUrl(testSecret, tampered)).toThrow();
		});

		it('should reject tokens with wrong secret', () => {
			const email = 'user@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);
			expect(() => decryptEmailFromUrl('wrong-secret', encrypted)).toThrow();
		});
	});

	describe('Edge Cases', () => {
		it('should handle empty email', () => {
			const encrypted = encryptEmailForUrl(testSecret, '');
			const decrypted = decryptEmailFromUrl(testSecret, encrypted);
			expect(decrypted).toBe('');
		});

		it('should handle email with special characters', () => {
			const email = 'user+tag@sub.example.co.uk';
			const encrypted = encryptEmailForUrl(testSecret, email);
			const decrypted = decryptEmailFromUrl(testSecret, encrypted);
			expect(decrypted).toBe(email);
		});

		it('should handle unicode in email local part', () => {
			const email = 'ユーザー@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);
			const decrypted = decryptEmailFromUrl(testSecret, encrypted);
			expect(decrypted).toBe('ユーザー@example.com');
		});

		it('should handle very long form paths', () => {
			const payload: TokenPayload = {
				email: 'user@example.com',
				formPath: 'a'.repeat(1000),
				pageNumber: 1,
				timestamp: Date.now(),
			};
			const encrypted = encryptToken(testSecret, payload);
			const decrypted = decryptToken(testSecret, encrypted);
			expect(decrypted.formPath).toBe(payload.formPath);
		});

		it('should handle minimum length secret', () => {
			const shortSecret = 'short';
			const payload: TokenPayload = {
				email: 'user@example.com',
				formPath: 'test',
				pageNumber: 1,
				timestamp: Date.now(),
			};
			// Should still work, PBKDF2 handles short secrets
			const encrypted = encryptToken(shortSecret, payload);
			const decrypted = decryptToken(shortSecret, encrypted);
			expect(decrypted).toEqual(payload);
		});
	});
});
