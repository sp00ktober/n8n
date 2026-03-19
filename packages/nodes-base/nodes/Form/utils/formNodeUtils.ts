import { type Response } from 'express';
import {
	type NodeTypeAndVersion,
	type IWebhookFunctions,
	type FormFieldsParameter,
	type IWebhookResponseData,
	type ICredentialDataDecryptedObject,
	NodeOperationError,
	FORM_TRIGGER_NODE_TYPE,
} from 'n8n-workflow';

import { renderForm, sanitizeHtml } from './utils';
import { generateFormPostBasicAuthToken } from '../../Webhook/utils';
import { encryptToken, decryptToken, type TokenPayload } from '../../Webhook/tokenCrypto';
import { WebhookAuthorizationError } from '../../Webhook/error';
import { FORM_TRIGGER_AUTHENTICATION_PROPERTY } from '../interfaces';

export const renderFormNode = async (
	context: IWebhookFunctions,
	res: Response,
	trigger: NodeTypeAndVersion,
	fields: FormFieldsParameter,
	mode: 'test' | 'production',
): Promise<IWebhookResponseData> => {
	const options = context.getNodeParameter('options', {}) as {
		formTitle: string;
		formDescription: string;
		buttonLabel: string;
		customCss?: string;
	};

	let title = options.formTitle;
	if (!title) {
		title = context.evaluateExpression(`{{ $('${trigger?.name}').params.formTitle }}`) as string;
	}

	let buttonLabel = options.buttonLabel;
	if (!buttonLabel) {
		buttonLabel =
			(context.evaluateExpression(
				`{{ $('${trigger?.name}').params.options?.buttonLabel }}`,
			) as string) || 'Submit';
	}

	const appendAttribution = context.evaluateExpression(
		`{{ $('${trigger?.name}').params.options?.appendAttribution === false ? false : true }}`,
	) as boolean;

	const description = sanitizeHtml(options.formDescription ?? '');

	// Get auth token from trigger for multi-page forms
	// The token is generated based on trigger's auth settings but validated on each page
	let authToken: string | undefined;
	if (trigger.typeVersion > 1) {
		// Try basic auth token first (may fail for Form nodes that don't have auth params)
		try {
			authToken = await generateFormPostBasicAuthToken(
				context,
				FORM_TRIGGER_AUTHENTICATION_PROPERTY,
			);
		} catch {
			// Form node doesn't have authentication parameter, which is expected
			// Continue to try proxy auth token
		}

		// If no basic auth token, try proxy auth token using Form node's credentials
		if (!authToken) {
			authToken = await generateFormPageProxyAuthToken(context, trigger);
		}
	}

	renderForm({
		context,
		res,
		formTitle: title,
		formDescription: description,
		formFields: fields,
		responseMode: 'responseNode',
		mode,
		redirectUrl: undefined,
		appendAttribution,
		buttonLabel,
		customCss: options.customCss,
		authToken,
	});

	return {
		noWebhookResponse: true,
	};
};

/**
 * Retrieves the active Form Trigger node from the workflow's parent nodes.
 *
 * This function searches through the parent nodes to find Form Trigger nodes,
 * then determines which one has been executed.
 *
 * @returns The NodeTypeAndVersion object representing the active Form Trigger node
 * @throws {NodeOperationError} When no Form Trigger node is found in parent nodes
 * @throws {NodeOperationError} When Form Trigger node exists but was not executed
 */
export function getFormTriggerNode(context: IWebhookFunctions): NodeTypeAndVersion {
	const parentNodes = context.getParentNodes(context.getNode().name);

	const formTriggers = parentNodes.filter((node) => node.type === FORM_TRIGGER_NODE_TYPE);

	if (!formTriggers.length) {
		throw new NodeOperationError(
			context.getNode(),
			'Form Trigger node must be set before this node',
		);
	}

	for (const trigger of formTriggers) {
		try {
			context.evaluateExpression(`{{ $('${trigger.name}').first() }}`);
		} catch (error) {
			continue;
		}
		return trigger;
	}

	throw new NodeOperationError(context.getNode(), 'Form Trigger node was not executed');
}

/**
 * Generates AES-GCM encrypted proxy auth token for intermediate Form pages.
 * Gets credentials from the Form node's own credential link (user must link proxyAuthApi to Form node).
 * Gets settings from FormTrigger via expression.
 * @param pageNumber - The page number in the multi-page form sequence
 */
async function generateFormPageProxyAuthToken(
	context: IWebhookFunctions,
	trigger: NodeTypeAndVersion,
	pageNumber: number = 1,
): Promise<string | undefined> {
	// Check if trigger uses proxyAuth
	const authentication = context.evaluateExpression(
		`{{ $('${trigger.name}').params.${FORM_TRIGGER_AUTHENTICATION_PROPERTY} }}`,
	) as string;

	if (authentication !== 'proxyAuth') {
		return undefined;
	}

	// Get credentials from THIS Form node (user must link proxyAuthApi to Form node)
	let credentials: ICredentialDataDecryptedObject | undefined;
	try {
		credentials = await context.getCredentials<ICredentialDataDecryptedObject>('proxyAuthApi');
	} catch {
		throw new WebhookAuthorizationError(
			500,
			'Proxy Auth credentials not configured on Form node. Link the same Proxy Auth credential to this Form node.',
		);
	}

	const encryptionSecret = credentials?.encryptionSecret as string;
	if (!encryptionSecret) {
		throw new WebhookAuthorizationError(
			500,
			'Encryption secret not configured in Proxy Auth credentials',
		);
	}

	// Get proxy auth settings from trigger
	const proxyAuthSettings = context.evaluateExpression(
		`{{ $('${trigger.name}').params.proxyAuthSettings }}`,
	) as { settings?: { emailHeaderName?: string } } | undefined;

	const settings = proxyAuthSettings?.settings ?? {};
	const emailHeaderName = (settings.emailHeaderName ?? 'x-auth-request-email').toLowerCase();

	// Get email from request header
	const req = context.getRequestObject();
	const email = req.headers[emailHeaderName] as string;
	if (!email) {
		throw new WebhookAuthorizationError(401, `Missing authentication header: ${emailHeaderName}`);
	}

	// Get form path - use trigger's webhook path
	const formPath =
		(context.evaluateExpression(`{{ $('${trigger.name}').params.path }}`) as string) ||
		(context.evaluateExpression(`{{ $('${trigger.name}').params.options?.path }}`) as string) ||
		'';

	// Create encrypted token payload
	const payload: TokenPayload = {
		email: email.toLowerCase(),
		formPath,
		pageNumber,
		timestamp: Date.now(),
	};

	return encryptToken(encryptionSecret, payload);
}

/**
 * Validates AES-GCM encrypted proxy auth token for intermediate Form pages.
 * Gets credentials from the Form node's own credential link (user must link proxyAuthApi to Form node).
 * Decrypts the token to get the trusted email (NOT from headers).
 * @returns Validation result with the trusted email from the decrypted token
 */
export async function validateFormPageProxyAuthToken(
	context: IWebhookFunctions,
	trigger: NodeTypeAndVersion,
): Promise<{ valid: boolean; email?: string }> {
	// Check if trigger uses proxyAuth
	const authentication = context.evaluateExpression(
		`{{ $('${trigger.name}').params.${FORM_TRIGGER_AUTHENTICATION_PROPERTY} }}`,
	) as string;

	if (authentication !== 'proxyAuth') {
		return { valid: true };
	}

	const headers = context.getHeaderData();

	// Get token from header
	const token = headers['x-auth-token'] as string;
	if (!token) {
		throw new WebhookAuthorizationError(401, 'Missing CSRF token');
	}

	// Get credentials from THIS Form node (user must link proxyAuthApi to Form node)
	let credentials: ICredentialDataDecryptedObject | undefined;
	try {
		credentials = await context.getCredentials<ICredentialDataDecryptedObject>('proxyAuthApi');
	} catch {
		throw new WebhookAuthorizationError(
			500,
			'Proxy Auth credentials not configured on Form node. Link the same Proxy Auth credential to this Form node.',
		);
	}

	const encryptionSecret = credentials?.encryptionSecret as string;
	if (!encryptionSecret) {
		throw new WebhookAuthorizationError(
			500,
			'Encryption secret not configured in Proxy Auth credentials',
		);
	}

	// Get proxy auth settings from trigger
	const proxyAuthSettings = context.evaluateExpression(
		`{{ $('${trigger.name}').params.proxyAuthSettings }}`,
	) as { settings?: { tokenExpiryMinutes?: number } } | undefined;

	const settings = proxyAuthSettings?.settings ?? {};
	const tokenExpiryMinutes = settings.tokenExpiryMinutes ?? 10;

	// Decrypt token to get trusted payload
	let payload: TokenPayload;
	try {
		payload = decryptToken(encryptionSecret, token);
	} catch {
		throw new WebhookAuthorizationError(403, 'Invalid or tampered token');
	}

	// Validate timestamp
	const age = Date.now() - payload.timestamp;
	if (age > tokenExpiryMinutes * 60 * 1000) {
		throw new WebhookAuthorizationError(403, 'Token expired');
	}

	// Get form path - use trigger's webhook path
	const formPath =
		(context.evaluateExpression(`{{ $('${trigger.name}').params.path }}`) as string) ||
		(context.evaluateExpression(`{{ $('${trigger.name}').params.options?.path }}`) as string) ||
		'';

	// Validate form path
	if (payload.formPath !== formPath) {
		throw new WebhookAuthorizationError(403, 'Token form path mismatch');
	}

	// Return trusted email from encrypted token (NOT from headers!)
	return { valid: true, email: payload.email };
}

// Alias for backwards compatibility with Form.node.ts import
export { validateFormPageProxyAuthToken as validateFormPageHeaderAuthToken };
