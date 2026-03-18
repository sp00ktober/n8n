import basicAuth from 'basic-auth';
import { rm } from 'fs/promises';
import jwt from 'jsonwebtoken';
import { WorkflowConfigurationError } from 'n8n-workflow';
import type {
	IWebhookFunctions,
	INodeExecutionData,
	IDataObject,
	ICredentialDataDecryptedObject,
	MultiPartFormData,
	INode,
} from 'n8n-workflow';
import * as a from 'node:assert';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { BlockList, isIPv6 } from 'node:net';

import { WebhookAuthorizationError } from './error';
import { formatPrivateKey } from '../../utils/utilities';

export type WebhookParameters = {
	httpMethod: string | string[];
	responseMode: string;
	responseData: string;
	responseCode?: number; //typeVersion <= 1.1
	options?: {
		responseData?: string;
		responseCode?: {
			values?: {
				responseCode: number;
				customCode?: number;
			};
		};
		noResponseBody?: boolean;
	};
};

export const getResponseCode = (parameters: WebhookParameters) => {
	if (parameters.responseCode) {
		return parameters.responseCode;
	}
	const responseCodeOptions = parameters.options;
	if (responseCodeOptions?.responseCode?.values) {
		const { responseCode, customCode } = responseCodeOptions.responseCode.values;

		if (customCode) {
			return customCode;
		}

		return responseCode;
	}
	return 200;
};

export const getResponseData = (parameters: WebhookParameters) => {
	const { responseData, responseMode, options } = parameters;
	if (responseData) return responseData;

	if (responseMode === 'onReceived') {
		const data = options?.responseData;
		if (data) return data;
	}

	if (options?.noResponseBody) return 'noData';

	return undefined;
};

export const configuredOutputs = (parameters: WebhookParameters) => {
	const httpMethod = parameters.httpMethod;

	if (!Array.isArray(httpMethod))
		return [
			{
				type: 'main',
				displayName: httpMethod,
			},
		];

	const outputs = httpMethod.map((method) => {
		return {
			type: 'main',
			displayName: method,
		};
	});

	return outputs;
};

export const setupOutputConnection = (
	ctx: IWebhookFunctions,
	method: string,
	additionalData: {
		jwtPayload?: IDataObject;
	},
) => {
	const httpMethod = ctx.getNodeParameter('httpMethod', []) as string[] | string;
	let webhookUrl = ctx.getNodeWebhookUrl('default') as string;
	const executionMode = ctx.getMode() === 'manual' ? 'test' : 'production';

	if (executionMode === 'test') {
		webhookUrl = webhookUrl.replace('/webhook/', '/webhook-test/');
	}

	// multi methods could be set in settings of node, so we need to check if it's an array
	if (!Array.isArray(httpMethod)) {
		return (outputData: INodeExecutionData): INodeExecutionData[][] => {
			outputData.json.webhookUrl = webhookUrl;
			outputData.json.executionMode = executionMode;
			if (additionalData?.jwtPayload) {
				outputData.json.jwtPayload = additionalData.jwtPayload;
			}
			return [[outputData]];
		};
	}

	const outputIndex = httpMethod.indexOf(method.toUpperCase());
	const outputs: INodeExecutionData[][] = httpMethod.map(() => []);

	return (outputData: INodeExecutionData): INodeExecutionData[][] => {
		outputData.json.webhookUrl = webhookUrl;
		outputData.json.executionMode = executionMode;
		if (additionalData?.jwtPayload) {
			outputData.json.jwtPayload = additionalData.jwtPayload;
		}
		outputs[outputIndex] = [outputData];
		return outputs;
	};
};

export const isIpAllowed = (
	allowlist: string | string[] | undefined,
	ips: string[],
	ip?: string,
) => {
	if (allowlist === undefined || allowlist === '') {
		return true;
	}

	if (!Array.isArray(allowlist)) {
		allowlist = allowlist.split(',').map((entry) => entry.trim());
	}

	const allowList = getAllowList(allowlist);

	// Check the primary IP address with proper family detection
	if (ip) {
		const ipFamily = isIPv6(ip) ? 'ipv6' : 'ipv4';
		if (allowList.check(ip, ipFamily)) {
			return true;
		}
	}

	// Check proxy IPs with proper family detection
	if (
		ips.some((ipEntry) => {
			const ipFamily = isIPv6(ipEntry) ? 'ipv6' : 'ipv4';
			return allowList.check(ipEntry, ipFamily);
		})
	) {
		return true;
	}

	return false;
};

const getAllowList = (allowlist: string[]) => {
	const allowList = new BlockList();

	for (const entry of allowlist) {
		try {
			// Check if entry is in CIDR notation (contains /)
			if (entry.includes('/')) {
				const [network, prefixStr] = entry.split('/');
				const prefix = parseInt(prefixStr, 10);

				// Validate prefix is a number
				if (isNaN(prefix)) {
					continue;
				}

				// Detect IP type (IPv4 vs IPv6)
				const type = network.includes(':') ? 'ipv6' : 'ipv4';

				// Validate prefix range
				const maxPrefix = type === 'ipv4' ? 32 : 128;
				if (prefix < 0 || prefix > maxPrefix) {
					continue;
				}

				allowList.addSubnet(network, prefix, type);
			} else {
				// Single IP address
				const type = entry.includes(':') ? 'ipv6' : 'ipv4';
				allowList.addAddress(entry, type);
			}
		} catch {
			// Ignore invalid entries
		}
	}

	return allowList;
};

export const checkResponseModeConfiguration = (context: IWebhookFunctions) => {
	const responseMode = context.getNodeParameter('responseMode', 'onReceived') as string;
	const connectedNodes = context.getChildNodes(context.getNode().name);

	const isRespondToWebhookConnected = connectedNodes.some(
		(node) => node.type === 'n8n-nodes-base.respondToWebhook',
	);

	if (!isRespondToWebhookConnected && responseMode === 'responseNode') {
		throw new WorkflowConfigurationError(
			context.getNode(),
			new Error('No Respond to Webhook node found in the workflow'),
			{
				description:
					'Insert a Respond to Webhook node to your workflow to respond to the webhook or choose another option for the “Respond” parameter',
			},
		);
	}

	if (isRespondToWebhookConnected && !['responseNode', 'streaming'].includes(responseMode)) {
		throw new WorkflowConfigurationError(
			context.getNode(),
			new Error('Unused Respond to Webhook node found in the workflow'),
			{
				description:
					'Set the “Respond” parameter to “Using Respond to Webhook Node” or remove the Respond to Webhook node',
			},
		);
	}
};

export async function validateWebhookAuthentication(
	ctx: IWebhookFunctions,
	authPropertyName: string,
) {
	const authentication = ctx.getNodeParameter(authPropertyName) as string;
	if (authentication === 'none') return;

	const req = ctx.getRequestObject();
	const headers = ctx.getHeaderData();

	if (authentication === 'basicAuth') {
		// Basic authorization is needed to call webhook
		let expectedAuth: ICredentialDataDecryptedObject | undefined;
		try {
			expectedAuth = await ctx.getCredentials<ICredentialDataDecryptedObject>('httpBasicAuth');
		} catch {}

		if (expectedAuth === undefined || !expectedAuth.user || !expectedAuth.password) {
			// Data is not defined on node so can not authenticate
			throw new WebhookAuthorizationError(500, 'No authentication data defined on node!');
		}

		const providedAuth = basicAuth(req);
		// Authorization data is missing
		if (!providedAuth) {
			const authToken = headers['x-auth-token'];
			if (!authToken) {
				throw new WebhookAuthorizationError(401);
			}

			const expectedAuthToken = generateBasicAuthToken(ctx.getNode(), expectedAuth);
			if (
				!expectedAuthToken ||
				typeof authToken !== 'string' ||
				expectedAuthToken.length !== authToken.length ||
				!timingSafeEqual(Buffer.from(expectedAuthToken), Buffer.from(authToken))
			) {
				throw new WebhookAuthorizationError(403);
			}
		} else if (
			providedAuth.name !== expectedAuth.user ||
			providedAuth.pass !== expectedAuth.password
		) {
			// Provided authentication data is wrong
			throw new WebhookAuthorizationError(403);
		}
	} else if (authentication === 'bearerAuth') {
		let expectedAuth: ICredentialDataDecryptedObject | undefined;
		try {
			expectedAuth = await ctx.getCredentials<ICredentialDataDecryptedObject>('httpBearerAuth');
		} catch {}

		const expectedToken = expectedAuth?.token as string;
		if (!expectedToken) {
			throw new WebhookAuthorizationError(500, 'No authentication data defined on node!');
		}

		if (headers.authorization !== `Bearer ${expectedToken}`) {
			throw new WebhookAuthorizationError(403);
		}
	} else if (authentication === 'headerAuth') {
		// Special header with value is needed to call webhook
		let expectedAuth: ICredentialDataDecryptedObject | undefined;
		try {
			expectedAuth = await ctx.getCredentials<ICredentialDataDecryptedObject>('httpHeaderAuth');
		} catch {}

		if (expectedAuth === undefined || !expectedAuth.name || !expectedAuth.value) {
			// Data is not defined on node so can not authenticate
			throw new WebhookAuthorizationError(500, 'No authentication data defined on node!');
		}
		const headerName = (expectedAuth.name as string).toLowerCase();
		const expectedValue = expectedAuth.value as string;

		if (
			!headers.hasOwnProperty(headerName) ||
			(headers as IDataObject)[headerName] !== expectedValue
		) {
			// Provided authentication data is wrong
			throw new WebhookAuthorizationError(403);
		}
	} else if (authentication === 'jwtAuth') {
		let expectedAuth;

		try {
			expectedAuth = await ctx.getCredentials<{
				keyType: 'passphrase' | 'pemKey';
				publicKey: string;
				secret: string;
				algorithm: jwt.Algorithm;
			}>('jwtAuth');
		} catch {}

		if (expectedAuth === undefined) {
			// Data is not defined on node so can not authenticate
			throw new WebhookAuthorizationError(500, 'No authentication data defined on node!');
		}

		const authHeader = req.headers.authorization;
		const token = authHeader?.split(' ')[1];

		if (!token) {
			throw new WebhookAuthorizationError(401, 'No token provided');
		}

		let secretOrPublicKey;

		if (expectedAuth.keyType === 'passphrase') {
			secretOrPublicKey = expectedAuth.secret;
		} else {
			secretOrPublicKey = formatPrivateKey(expectedAuth.publicKey, true);
		}

		try {
			return jwt.verify(token, secretOrPublicKey, {
				algorithms: [expectedAuth.algorithm],
			}) as IDataObject;
		} catch (error) {
			throw new WebhookAuthorizationError(403, error.message);
		}
	}
}

export async function handleFormData(
	context: IWebhookFunctions,
	prepareOutput: (data: INodeExecutionData) => INodeExecutionData[][],
) {
	const req = context.getRequestObject() as MultiPartFormData.Request;
	a.ok(req.contentType === 'multipart/form-data', 'Expected multipart/form-data');
	const options = context.getNodeParameter('options', {}) as IDataObject;
	const { data, files } = req.body;

	const returnItem: INodeExecutionData = {
		json: {
			headers: req.headers,
			params: req.params,
			query: req.query,
			body: data,
		},
	};

	if (files && Object.keys(files).length) {
		returnItem.binary = {};
	}

	let count = 0;

	for (const key of Object.keys(files)) {
		const processFiles: MultiPartFormData.File[] = [];
		let multiFile = false;
		if (Array.isArray(files[key])) {
			processFiles.push.apply(processFiles, files[key]);
			multiFile = true;
		} else {
			processFiles.push(files[key]);
		}

		let fileCount = 0;
		for (const file of processFiles) {
			let binaryPropertyName = key;
			if (binaryPropertyName.endsWith('[]')) {
				binaryPropertyName = binaryPropertyName.slice(0, -2);
			}
			if (!binaryPropertyName.trim().length) {
				binaryPropertyName = `data${count}`;
			} else if (multiFile) {
				binaryPropertyName += fileCount++;
			}
			if (options.binaryPropertyName) {
				binaryPropertyName = `${options.binaryPropertyName}${count}`;
			}

			returnItem.binary![binaryPropertyName] = await context.nodeHelpers.copyBinaryFile(
				file.filepath,
				file.originalFilename ?? file.newFilename,
				file.mimetype,
			);

			// Delete original file to prevent tmp directory from growing too large
			await rm(file.filepath, { force: true });

			count += 1;
		}
	}

	return { workflowData: prepareOutput(returnItem) };
}

export async function generateFormPostBasicAuthToken(
	context: IWebhookFunctions,
	authPropertyName: string,
) {
	const node = context.getNode();

	const authentication = context.getNodeParameter(authPropertyName);
	if (authentication === 'none') return;

	let credentials: ICredentialDataDecryptedObject | undefined;

	try {
		credentials = await context.getCredentials<ICredentialDataDecryptedObject>('httpBasicAuth');
	} catch {}

	return generateBasicAuthToken(node, credentials);
}

export function generateBasicAuthToken(
	node: INode,
	credentials: ICredentialDataDecryptedObject | undefined,
) {
	if (!credentials || !credentials.user || !credentials.password) {
		return;
	}

	const token = createHmac('sha256', `${credentials.user}:${credentials.password}`)
		.update(`${node.id}-${node.webhookId}`)
		.digest('hex');

	return token;
}

// Header Auth token expiry: 1 hour default
const HEADER_AUTH_TOKEN_EXPIRY_MS = 60 * 60 * 1000;

/**
 * Generates HMAC-SHA256 token for header auth CSRF protection.
 * Token format: timestamp:hmac
 * The token binds the authenticated email, form path, and timestamp together.
 */
export function generateHeaderAuthToken(
	secret: string,
	email: string,
	formPath: string,
	timestamp?: number,
): string {
	const ts = timestamp ?? Date.now();

	// Create HMAC binding email + formPath + timestamp
	const dataToSign = `${email}:${formPath}:${ts}`;
	const hmac = createHmac('sha256', secret).update(dataToSign).digest('hex');

	// Return timestamp:hmac format for validation
	return `${ts}:${hmac}`;
}

/**
 * Validates header auth token with timing-safe comparison.
 * Returns true if valid, false if invalid or expired.
 */
export function validateHeaderAuthToken(
	secret: string,
	email: string,
	formPath: string,
	token: string,
	expiryMs: number = HEADER_AUTH_TOKEN_EXPIRY_MS,
): boolean {
	// Parse token
	const colonIndex = token.indexOf(':');
	if (colonIndex === -1) {
		return false;
	}

	const timestampStr = token.substring(0, colonIndex);
	const providedHmac = token.substring(colonIndex + 1);

	const timestamp = parseInt(timestampStr, 10);
	if (isNaN(timestamp)) {
		return false;
	}

	// Check expiry
	const now = Date.now();
	if (now - timestamp > expiryMs) {
		return false;
	}

	// Regenerate expected token and compare
	const expectedToken = generateHeaderAuthToken(secret, email, formPath, timestamp);
	const expectedHmac = expectedToken.substring(expectedToken.indexOf(':') + 1);

	// Timing-safe comparison
	try {
		const expectedBuffer = Buffer.from(expectedHmac, 'hex');
		const providedBuffer = Buffer.from(providedHmac, 'hex');

		if (expectedBuffer.length !== providedBuffer.length) {
			return false;
		}

		return timingSafeEqual(expectedBuffer, providedBuffer);
	} catch {
		return false;
	}
}

// Type for headerAuthSettings fixedCollection
interface HeaderAuthSettings {
	settings?: {
		csrfSecret?: string;
		emailHeaderName?: string;
		tokenExpiryMinutes?: number;
	};
}

/**
 * Gets header auth settings from the node parameters.
 * Handles the fixedCollection structure.
 */
function getHeaderAuthSettings(context: IWebhookFunctions): {
	csrfSecret: string | undefined;
	emailHeaderName: string;
	tokenExpiryMinutes: number;
} {
	let headerAuthSettings: HeaderAuthSettings = {};
	try {
		headerAuthSettings = context.getNodeParameter('headerAuthSettings', {}) as HeaderAuthSettings;
	} catch {
		// Parameter might not exist
	}

	const settings = headerAuthSettings.settings ?? {};

	return {
		csrfSecret: settings.csrfSecret,
		emailHeaderName: (settings.emailHeaderName ?? 'x-auth-request-email').toLowerCase(),
		tokenExpiryMinutes: settings.tokenExpiryMinutes ?? 60,
	};
}

/**
 * Generates header auth token for form POST requests.
 * Uses the email from X-Auth-Request-Email header (or configured header name)
 * and a user-provided CSRF secret.
 */
export async function generateFormPostHeaderAuthToken(
	context: IWebhookFunctions,
	authPropertyName: string,
): Promise<string | undefined> {
	const authentication = context.getNodeParameter(authPropertyName) as string;
	if (authentication !== 'headerAuth') {
		return undefined;
	}

	const req = context.getRequestObject();
	const { csrfSecret, emailHeaderName } = getHeaderAuthSettings(context);

	if (!csrfSecret) {
		throw new WebhookAuthorizationError(500, 'CSRF secret not configured for Header Auth');
	}

	// Extract email from header (case-insensitive)
	const email = req.headers[emailHeaderName] as string;
	if (!email) {
		throw new WebhookAuthorizationError(401, `Missing authentication header: ${emailHeaderName}`);
	}

	// Get form path for binding
	let formPath = '';
	try {
		formPath = context.getNodeParameter('path', '') as string;
	} catch {
		// Parameter might not exist
	}
	if (!formPath) {
		try {
			formPath = context.getNodeParameter('options.path', '') as string;
		} catch {
			// Parameter might not exist
		}
	}
	if (!formPath) {
		formPath = context.getNode().webhookId || '';
	}

	return generateHeaderAuthToken(csrfSecret, email, formPath);
}

/**
 * Validates header auth token on POST request.
 * Returns true if valid, throws WebhookAuthorizationError if invalid.
 */
export async function validateFormPostHeaderAuthToken(
	context: IWebhookFunctions,
	authPropertyName: string,
): Promise<boolean> {
	const authentication = context.getNodeParameter(authPropertyName) as string;
	if (authentication !== 'headerAuth') {
		return true;
	}

	const req = context.getRequestObject();
	const headers = context.getHeaderData();

	// Get token from header
	const token = headers['x-auth-token'] as string;
	if (!token) {
		throw new WebhookAuthorizationError(401, 'Missing CSRF token');
	}

	const { csrfSecret, emailHeaderName, tokenExpiryMinutes } = getHeaderAuthSettings(context);

	if (!csrfSecret) {
		throw new WebhookAuthorizationError(500, 'CSRF secret not configured for Header Auth');
	}

	// Get email from header - must still be present on POST (via proxy)
	const email = req.headers[emailHeaderName] as string;
	if (!email) {
		throw new WebhookAuthorizationError(
			401,
			'Missing authentication header on POST - request may not have gone through auth proxy',
		);
	}

	// Get form path for validation
	let formPath = '';
	try {
		formPath = context.getNodeParameter('path', '') as string;
	} catch {
		// Parameter might not exist
	}
	if (!formPath) {
		try {
			formPath = context.getNodeParameter('options.path', '') as string;
		} catch {
			// Parameter might not exist
		}
	}
	if (!formPath) {
		formPath = context.getNode().webhookId || '';
	}

	const isValid = validateHeaderAuthToken(
		csrfSecret,
		email,
		formPath,
		token,
		tokenExpiryMinutes * 60 * 1000,
	);

	if (!isValid) {
		throw new WebhookAuthorizationError(403, 'Invalid or expired CSRF token');
	}

	return true;
}
