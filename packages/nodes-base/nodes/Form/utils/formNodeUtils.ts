import { type Response } from 'express';
import {
	type NodeTypeAndVersion,
	type IWebhookFunctions,
	type FormFieldsParameter,
	type IWebhookResponseData,
	NodeOperationError,
	FORM_TRIGGER_NODE_TYPE,
} from 'n8n-workflow';

import { renderForm, sanitizeHtml } from './utils';
import {
	generateFormPostBasicAuthToken,
	generateHeaderAuthToken,
	validateHeaderAuthToken,
} from '../../Webhook/utils';
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
		// Try basic auth token first
		authToken = await generateFormPostBasicAuthToken(context, FORM_TRIGGER_AUTHENTICATION_PROPERTY);

		// If no basic auth token, try header auth token using trigger's settings
		if (!authToken) {
			authToken = await generateFormPageHeaderAuthToken(context, trigger);
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
 * Generates header auth token for intermediate Form pages.
 * Reads settings from the FormTrigger node since intermediate pages don't have their own auth settings.
 */
async function generateFormPageHeaderAuthToken(
	context: IWebhookFunctions,
	trigger: NodeTypeAndVersion,
): Promise<string | undefined> {
	// Check if trigger uses headerAuth
	const authentication = context.evaluateExpression(
		`{{ $('${trigger.name}').params.${FORM_TRIGGER_AUTHENTICATION_PROPERTY} }}`,
	) as string;

	if (authentication !== 'headerAuth') {
		return undefined;
	}

	// Get header auth settings from trigger
	const headerAuthSettings = context.evaluateExpression(
		`{{ $('${trigger.name}').params.headerAuthSettings }}`,
	) as { settings?: { csrfSecret?: string; emailHeaderName?: string } } | undefined;

	const settings = headerAuthSettings?.settings ?? {};
	const csrfSecret = settings.csrfSecret;
	const emailHeaderName = (settings.emailHeaderName ?? 'x-auth-request-email').toLowerCase();

	if (!csrfSecret) {
		throw new WebhookAuthorizationError(500, 'CSRF secret not configured for Header Auth');
	}

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

	return generateHeaderAuthToken(csrfSecret, email, formPath);
}

/**
 * Validates header auth token for intermediate Form pages.
 * Reads settings from the FormTrigger node.
 */
export async function validateFormPageHeaderAuthToken(
	context: IWebhookFunctions,
	trigger: NodeTypeAndVersion,
): Promise<boolean> {
	// Check if trigger uses headerAuth
	const authentication = context.evaluateExpression(
		`{{ $('${trigger.name}').params.${FORM_TRIGGER_AUTHENTICATION_PROPERTY} }}`,
	) as string;

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

	// Get header auth settings from trigger
	const headerAuthSettings = context.evaluateExpression(
		`{{ $('${trigger.name}').params.headerAuthSettings }}`,
	) as
		| { settings?: { csrfSecret?: string; emailHeaderName?: string; tokenExpiryMinutes?: number } }
		| undefined;

	const settings = headerAuthSettings?.settings ?? {};
	const csrfSecret = settings.csrfSecret;
	const emailHeaderName = (settings.emailHeaderName ?? 'x-auth-request-email').toLowerCase();
	const tokenExpiryMinutes = settings.tokenExpiryMinutes ?? 60;

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

	// Get form path - use trigger's webhook path
	const formPath =
		(context.evaluateExpression(`{{ $('${trigger.name}').params.path }}`) as string) ||
		(context.evaluateExpression(`{{ $('${trigger.name}').params.options?.path }}`) as string) ||
		'';

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
