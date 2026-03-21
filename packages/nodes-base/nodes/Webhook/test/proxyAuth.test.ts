import { mock } from 'jest-mock-extended';
import type { IWebhookFunctions, INode } from 'n8n-workflow';

import {
	generateFormPostProxyAuthToken,
	validateFormPostProxyAuthToken,
	getProxyAuthSettings,
} from '../utils';
import { decryptToken } from '../tokenCrypto';

describe('Proxy Auth', () => {
	const testSecret = 'test-encryption-secret-32-chars!';

	describe('getProxyAuthSettings', () => {
		it('should return default settings when not configured', () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockReturnValue({});

			const settings = getProxyAuthSettings(ctx);

			expect(settings.emailHeaderName).toBe('x-auth-request-email');
			expect(settings.tokenExpiryMinutes).toBe(10);
		});

		it('should return custom email header name', () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockReturnValue({
				settings: { emailHeaderName: 'X-User-Email' },
			});

			const settings = getProxyAuthSettings(ctx);

			expect(settings.emailHeaderName).toBe('x-user-email'); // lowercase
		});

		it('should return custom token expiry', () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockReturnValue({
				settings: { tokenExpiryMinutes: 30 },
			});

			const settings = getProxyAuthSettings(ctx);

			expect(settings.tokenExpiryMinutes).toBe(30);
		});

		it('should handle missing settings gracefully', () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation(() => {
				throw new Error('Parameter not found');
			});

			const settings = getProxyAuthSettings(ctx);

			expect(settings.emailHeaderName).toBe('x-auth-request-email');
			expect(settings.tokenExpiryMinutes).toBe(10);
		});
	});

	describe('generateFormPostProxyAuthToken', () => {
		it('should return undefined for non-proxyAuth authentication', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockReturnValue('basicAuth');

			const token = await generateFormPostProxyAuthToken(ctx, 'authentication');

			expect(token).toBeUndefined();
		});

		it('should return undefined for none authentication', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockReturnValue('none');

			const token = await generateFormPostProxyAuthToken(ctx, 'authentication');

			expect(token).toBeUndefined();
		});

		it('should generate token when proxyAuth is enabled', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				if (name === 'path') return 'test/form';
				return {};
			});
			ctx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			ctx.getRequestObject.mockReturnValue({
				headers: { 'x-auth-request-email': 'user@example.com' },
			} as any);
			ctx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const token = await generateFormPostProxyAuthToken(ctx, 'authentication');

			expect(token).toBeDefined();
			expect(typeof token).toBe('string');
			expect(token!.split(':').length).toBe(4); // salt:iv:authTag:ciphertext
		});

		it('should include email in token payload', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				if (name === 'path') return 'test/form';
				return {};
			});
			ctx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			ctx.getRequestObject.mockReturnValue({
				headers: { 'x-auth-request-email': 'USER@EXAMPLE.COM' },
			} as any);
			ctx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const token = await generateFormPostProxyAuthToken(ctx, 'authentication');
			const payload = decryptToken(testSecret, token!);

			expect(payload.email).toBe('user@example.com'); // lowercase normalized
		});

		it('should include form path in token payload', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				if (name === 'path') return 'authenticated/my-form';
				return {};
			});
			ctx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			ctx.getRequestObject.mockReturnValue({
				headers: { 'x-auth-request-email': 'user@example.com' },
			} as any);
			ctx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const token = await generateFormPostProxyAuthToken(ctx, 'authentication');
			const payload = decryptToken(testSecret, token!);

			expect(payload.formPath).toBe('authenticated/my-form');
		});

		it('should throw when email header is missing', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				return {};
			});
			ctx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			ctx.getRequestObject.mockReturnValue({ headers: {} } as any);

			await expect(generateFormPostProxyAuthToken(ctx, 'authentication')).rejects.toThrow(
				'Missing authentication header',
			);
		});

		it('should throw when credentials are not configured', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				return {};
			});
			ctx.getCredentials.mockRejectedValue(new Error('Credential not found'));

			await expect(generateFormPostProxyAuthToken(ctx, 'authentication')).rejects.toThrow(
				'Proxy Auth credentials not configured',
			);
		});

		it('should throw when encryption secret is empty', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				return {};
			});
			ctx.getCredentials.mockResolvedValue({ encryptionSecret: '' });

			await expect(generateFormPostProxyAuthToken(ctx, 'authentication')).rejects.toThrow(
				'Encryption secret not configured',
			);
		});

		it('should use custom email header name', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings')
					return { settings: { emailHeaderName: 'x-custom-email' } };
				if (name === 'path') return 'test/form';
				return {};
			});
			ctx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			ctx.getRequestObject.mockReturnValue({
				headers: { 'x-custom-email': 'custom@example.com' },
			} as any);
			ctx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const token = await generateFormPostProxyAuthToken(ctx, 'authentication');
			const payload = decryptToken(testSecret, token!);

			expect(payload.email).toBe('custom@example.com');
		});
	});

	describe('validateFormPostProxyAuthToken', () => {
		it('should return valid for non-proxyAuth authentication', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockReturnValue('basicAuth');

			const result = await validateFormPostProxyAuthToken(ctx, 'authentication');

			expect(result.valid).toBe(true);
			expect(result.email).toBeUndefined();
		});

		it('should validate token and return trusted email', async () => {
			// First generate a token
			const genCtx = mock<IWebhookFunctions>();
			genCtx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: { tokenExpiryMinutes: 10 } };
				if (name === 'path') return 'test/form';
				return {};
			});
			genCtx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			genCtx.getRequestObject.mockReturnValue({
				headers: { 'x-auth-request-email': 'user@example.com' },
			} as any);
			genCtx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const token = await generateFormPostProxyAuthToken(genCtx, 'authentication');

			// Now validate it
			const valCtx = mock<IWebhookFunctions>();
			valCtx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: { tokenExpiryMinutes: 10 } };
				if (name === 'path') return 'test/form';
				return {};
			});
			valCtx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			valCtx.getHeaderData.mockReturnValue({ 'x-auth-token': token });
			valCtx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const result = await validateFormPostProxyAuthToken(valCtx, 'authentication');

			expect(result.valid).toBe(true);
			expect(result.email).toBe('user@example.com');
		});

		it('should throw when CSRF token header is missing', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockReturnValue('proxyAuth');
			ctx.getHeaderData.mockReturnValue({});

			await expect(validateFormPostProxyAuthToken(ctx, 'authentication')).rejects.toThrow(
				'Missing CSRF token',
			);
		});

		it('should throw when token is invalid/tampered', async () => {
			const ctx = mock<IWebhookFunctions>();
			ctx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				return {};
			});
			ctx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			ctx.getHeaderData.mockReturnValue({ 'x-auth-token': 'invalid:token:format:here' });

			await expect(validateFormPostProxyAuthToken(ctx, 'authentication')).rejects.toThrow(
				'Invalid or tampered token',
			);
		});

		it('should throw when token is expired', async () => {
			// Generate a token
			const genCtx = mock<IWebhookFunctions>();
			genCtx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				if (name === 'path') return 'test/form';
				return {};
			});
			genCtx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			genCtx.getRequestObject.mockReturnValue({
				headers: { 'x-auth-request-email': 'user@example.com' },
			} as any);
			genCtx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const token = await generateFormPostProxyAuthToken(genCtx, 'authentication');

			// Mock time to simulate expiry
			const originalDateNow = Date.now;
			Date.now = () => originalDateNow() + 11 * 60 * 1000; // 11 minutes later

			const valCtx = mock<IWebhookFunctions>();
			valCtx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: { tokenExpiryMinutes: 10 } };
				if (name === 'path') return 'test/form';
				return {};
			});
			valCtx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			valCtx.getHeaderData.mockReturnValue({ 'x-auth-token': token });
			valCtx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			await expect(validateFormPostProxyAuthToken(valCtx, 'authentication')).rejects.toThrow(
				'Token expired',
			);

			Date.now = originalDateNow;
		});

		it('should throw when form path does not match', async () => {
			// Generate token for path A
			const genCtx = mock<IWebhookFunctions>();
			genCtx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				if (name === 'path') return 'form/path-a';
				return {};
			});
			genCtx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			genCtx.getRequestObject.mockReturnValue({
				headers: { 'x-auth-request-email': 'user@example.com' },
			} as any);
			genCtx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			const token = await generateFormPostProxyAuthToken(genCtx, 'authentication');

			// Validate for path B
			const valCtx = mock<IWebhookFunctions>();
			valCtx.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'authentication') return 'proxyAuth';
				if (name === 'proxyAuthSettings') return { settings: {} };
				if (name === 'path') return 'form/path-b'; // Different path
				return {};
			});
			valCtx.getCredentials.mockResolvedValue({ encryptionSecret: testSecret });
			valCtx.getHeaderData.mockReturnValue({ 'x-auth-token': token });
			valCtx.getNode.mockReturnValue({ webhookId: 'test-webhook' } as INode);

			await expect(validateFormPostProxyAuthToken(valCtx, 'authentication')).rejects.toThrow(
				'Token form path mismatch',
			);
		});
	});
});
