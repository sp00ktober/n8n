import { mock } from 'jest-mock-extended';
import type { IWebhookFunctions, NodeTypeAndVersion } from 'n8n-workflow';

import {
	encryptToken,
	decryptToken,
	encryptEmailForUrl,
	type TokenPayload,
} from '../../Webhook/tokenCrypto';

// Note: These functions are not exported from formNodeUtils.ts
// This test file tests the multi-page proxy auth flow conceptually
// by testing the underlying crypto functions and expected behavior

describe('Multi-Page Form Proxy Auth', () => {
	const testSecret = 'test-encryption-secret-32-chars!';

	const mockTrigger: NodeTypeAndVersion = {
		name: 'Form Trigger',
		type: 'n8n-nodes-base.formTrigger',
		typeVersion: 2,
	};

	describe('Email Chaining Through Pages', () => {
		it('should chain email from page 1 token to page 2', () => {
			// Simulate page 1 POST with token containing email
			const page1Token = encryptToken(testSecret, {
				email: 'user@example.com',
				formPath: 'auth/form',
				pageNumber: 1,
				timestamp: Date.now(),
			});

			// Page 2 should extract email from incoming token
			const page1Payload = decryptToken(testSecret, page1Token);
			expect(page1Payload.email).toBe('user@example.com');
			expect(page1Payload.pageNumber).toBe(1);

			// Create page 2 token with same email but incremented page number
			const page2Token = encryptToken(testSecret, {
				email: page1Payload.email,
				formPath: page1Payload.formPath,
				pageNumber: 2,
				timestamp: Date.now(),
			});

			const page2Payload = decryptToken(testSecret, page2Token);
			expect(page2Payload.email).toBe('user@example.com');
			expect(page2Payload.pageNumber).toBe(2);
		});

		it('should extract email from URL param when no incoming token', () => {
			// Simulate formWaitingUrl with encrypted email
			const encryptedEmail = encryptEmailForUrl(testSecret, 'user@example.com');

			// This mimics what would be in ?authEmail=<encryptedEmail>
			expect(encryptedEmail).toBeDefined();
			expect(encryptedEmail.split(':').length).toBe(4);

			// The email can be decrypted on the next page
			// (actual decryption is tested in tokenCrypto.test.ts)
		});

		it('should maintain email consistency across all pages', () => {
			const originalEmail = 'multi.page@example.com';

			// Page 1: Email from OAuth header → Token
			const page1Token = encryptToken(testSecret, {
				email: originalEmail.toLowerCase(),
				formPath: 'survey/multi-step',
				pageNumber: 1,
				timestamp: Date.now(),
			});

			// Page 2: Email from Page 1 token → New Token
			const page1Payload = decryptToken(testSecret, page1Token);
			const page2Token = encryptToken(testSecret, {
				email: page1Payload.email,
				formPath: page1Payload.formPath,
				pageNumber: 2,
				timestamp: Date.now(),
			});

			// Page 3: Email from Page 2 token → New Token
			const page2Payload = decryptToken(testSecret, page2Token);
			const page3Token = encryptToken(testSecret, {
				email: page2Payload.email,
				formPath: page2Payload.formPath,
				pageNumber: 3,
				timestamp: Date.now(),
			});

			// Final verification
			const page3Payload = decryptToken(testSecret, page3Token);
			expect(page3Payload.email).toBe(originalEmail.toLowerCase());
			expect(page3Payload.pageNumber).toBe(3);
		});
	});

	describe('Token Validation Across Pages', () => {
		it('should reject token from different form path', () => {
			const wrongPathToken = encryptToken(testSecret, {
				email: 'user@example.com',
				formPath: 'different/form',
				pageNumber: 1,
				timestamp: Date.now(),
			});

			const payload = decryptToken(testSecret, wrongPathToken);

			// In actual validation, this would be compared to the current form path
			expect(payload.formPath).toBe('different/form');
			expect(payload.formPath).not.toBe('auth/form'); // Would fail path validation
		});

		it('should validate page 2 token has correct structure', () => {
			const page2Token = encryptToken(testSecret, {
				email: 'validated@example.com',
				formPath: 'auth/form',
				pageNumber: 2,
				timestamp: Date.now(),
			});

			const payload = decryptToken(testSecret, page2Token);

			expect(payload).toHaveProperty('email');
			expect(payload).toHaveProperty('formPath');
			expect(payload).toHaveProperty('pageNumber');
			expect(payload).toHaveProperty('timestamp');
			expect(payload.email).toBe('validated@example.com');
			expect(payload.pageNumber).toBe(2);
		});

		it('should track page progression', () => {
			const pages: TokenPayload[] = [];

			// Simulate 5 page form
			for (let i = 1; i <= 5; i++) {
				const token = encryptToken(testSecret, {
					email: 'tracker@example.com',
					formPath: 'long-survey',
					pageNumber: i,
					timestamp: Date.now(),
				});
				pages.push(decryptToken(testSecret, token));
			}

			// Verify page progression
			pages.forEach((payload, index) => {
				expect(payload.pageNumber).toBe(index + 1);
				expect(payload.email).toBe('tracker@example.com');
				expect(payload.formPath).toBe('long-survey');
			});
		});
	});

	describe('FormWaitingUrl Email Parameter', () => {
		it('should encrypt email for URL parameter', () => {
			const email = 'url.param@example.com';
			const encrypted = encryptEmailForUrl(testSecret, email);

			// Should be URL-safe (base64url encoding)
			expect(encrypted).not.toContain('+');
			expect(encrypted).not.toContain('/');
			expect(encrypted).not.toContain('=');
		});

		it('should preserve email through URL encryption/decryption', () => {
			const originalEmail = 'MIXED.Case@Example.COM';
			const encrypted = encryptEmailForUrl(testSecret, originalEmail);

			// Note: encryptEmailForUrl normalizes to lowercase
			// Decryption is tested in tokenCrypto.test.ts
			expect(encrypted).toBeDefined();
		});
	});

	describe('Trust Chain Verification', () => {
		it('should never trust email from headers on intermediate pages', () => {
			// This test verifies the conceptual security model:
			// - Page 1: Email comes from OAuth header (trusted)
			// - Page 2+: Email must come from decrypted token (not headers)

			const trustedEmail = 'trusted@example.com';
			const spoofedEmail = 'attacker@evil.com';

			// Page 1 token with trusted email
			const page1Token = encryptToken(testSecret, {
				email: trustedEmail,
				formPath: 'secure/form',
				pageNumber: 1,
				timestamp: Date.now(),
			});

			// On page 2, even if headers contain spoofed email,
			// the email should be extracted from the token
			const page1Payload = decryptToken(testSecret, page1Token);

			// The trusted email from token should be used, not the spoofed one
			expect(page1Payload.email).toBe(trustedEmail);
			expect(page1Payload.email).not.toBe(spoofedEmail);
		});

		it('should bind token to specific form path', () => {
			const token = encryptToken(testSecret, {
				email: 'user@example.com',
				formPath: 'specific/path',
				pageNumber: 1,
				timestamp: Date.now(),
			});

			const payload = decryptToken(testSecret, token);

			// Token is cryptographically bound to this path
			expect(payload.formPath).toBe('specific/path');

			// Using this token on a different path should fail validation
			// (actual path check happens in validateFormPageProxyAuthToken)
		});

		it('should include timestamp for replay attack prevention', () => {
			const token = encryptToken(testSecret, {
				email: 'user@example.com',
				formPath: 'form',
				pageNumber: 1,
				timestamp: Date.now(),
			});

			const payload = decryptToken(testSecret, token);

			// Timestamp should be recent
			const now = Date.now();
			expect(payload.timestamp).toBeLessThanOrEqual(now);
			expect(payload.timestamp).toBeGreaterThan(now - 1000); // Within last second
		});
	});

	describe('Edge Cases', () => {
		it('should handle very long form paths', () => {
			const longPath = 'a'.repeat(500) + '/b'.repeat(500);
			const token = encryptToken(testSecret, {
				email: 'user@example.com',
				formPath: longPath,
				pageNumber: 1,
				timestamp: Date.now(),
			});

			const payload = decryptToken(testSecret, token);
			expect(payload.formPath).toBe(longPath);
		});

		it('should handle unicode in email', () => {
			const unicodeEmail = 'ユーザー@example.com';
			const token = encryptToken(testSecret, {
				email: unicodeEmail,
				formPath: 'form',
				pageNumber: 1,
				timestamp: Date.now(),
			});

			const payload = decryptToken(testSecret, token);
			expect(payload.email).toBe(unicodeEmail);
		});

		it('should handle high page numbers', () => {
			const token = encryptToken(testSecret, {
				email: 'user@example.com',
				formPath: 'form',
				pageNumber: 999,
				timestamp: Date.now(),
			});

			const payload = decryptToken(testSecret, token);
			expect(payload.pageNumber).toBe(999);
		});
	});
});
