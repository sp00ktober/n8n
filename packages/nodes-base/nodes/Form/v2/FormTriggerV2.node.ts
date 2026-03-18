import {
	ADD_FORM_NOTICE,
	type INodePropertyOptions,
	NodeConnectionTypes,
	type INodeProperties,
	type INodeType,
	type INodeTypeBaseDescription,
	type INodeTypeDescription,
	type IWebhookFunctions,
} from 'n8n-workflow';

import {
	appendAttributionToForm,
	formDescription,
	formFields,
	formFieldsDynamic,
	formRespondMode,
	formTitle,
	formTriggerPanel,
	ipAllowlist,
	respondWithOptions,
	webhookPath,
} from '../common.descriptions';
import { cssVariables } from '../cssVariables';
import { FORM_TRIGGER_AUTHENTICATION_PROPERTY } from '../interfaces';
import { formWebhook } from '../utils/utils';

const useWorkflowTimezone: INodeProperties = {
	displayName: 'Use Workflow Timezone',
	name: 'useWorkflowTimezone',
	type: 'boolean',
	default: false,
	description: "Whether to use the workflow timezone set in node's settings rather than UTC",
};

const descriptionV2: INodeTypeDescription = {
	displayName: 'n8n Form Trigger',
	name: 'formTrigger',
	icon: 'file:form.svg',
	group: ['trigger'],
	// since trigger and node are sharing descriptions and logic we need to sync the versions
	// and keep them aligned in both nodes
	version: [2, 2.1, 2.2, 2.3, 2.4, 2.5],
	description: 'Generate webforms in n8n and pass their responses to the workflow',
	defaults: {
		name: 'On form submission',
	},
	builderHint: {
		relatedNodes: [
			{
				nodeType: 'n8n-nodes-base.form',
				relationHint: 'Add pages and final page to the form',
			},
		],
	},

	inputs: [],
	outputs: [NodeConnectionTypes.Main],
	webhooks: [
		{
			name: 'setup',
			httpMethod: 'GET',
			responseMode: 'onReceived',
			isFullPath: true,
			path: '={{ $parameter["path"] || $parameter["options"]?.path || $webhookId }}',
			ndvHideUrl: true,
			nodeType: 'form',
		},
		{
			name: 'default',
			httpMethod: 'POST',
			responseMode: '={{$parameter["responseMode"]}}',
			responseData: '={{$parameter["responseMode"] === "lastNode" ? "noData" : undefined}}',
			isFullPath: true,
			path: '={{ $parameter["path"] || $parameter["options"]?.path || $webhookId }}',
			ndvHideMethod: true,
			nodeType: 'form',
		},
	],
	eventTriggerDescription: 'Waiting for you to submit the form',
	activationMessage: 'You can now make calls to your production Form URL.',
	triggerPanel: formTriggerPanel,
	credentials: [
		{
			// eslint-disable-next-line n8n-nodes-base/node-class-description-credentials-name-unsuffixed
			name: 'httpBasicAuth',
			required: true,
			displayOptions: {
				show: {
					[FORM_TRIGGER_AUTHENTICATION_PROPERTY]: ['basicAuth'],
				},
			},
		},
	],
	properties: [
		{
			displayName: 'Authentication',
			name: FORM_TRIGGER_AUTHENTICATION_PROPERTY,
			type: 'options',
			options: [
				{
					name: 'Basic Auth',
					value: 'basicAuth',
				},
				{
					name: 'Header Auth',
					value: 'headerAuth',
					description:
						'For external auth proxies (e.g., oauth2-proxy) that pass authenticated user email via HTTP header',
				},
				{
					name: 'None',
					value: 'none',
				},
			],
			default: 'none',
		},
		{ ...webhookPath, displayOptions: { show: { '@version': [{ _cnd: { lte: 2.1 } }] } } },
		formTitle,
		formDescription,
		{ ...formFields, displayOptions: { show: { '@version': [{ _cnd: { lt: 2.5 } }] } } },
		{ ...formFieldsDynamic, displayOptions: { show: { '@version': [{ _cnd: { gte: 2.5 } }] } } },
		{ ...formRespondMode, displayOptions: { show: { '@version': [{ _cnd: { lte: 2.1 } }] } } },
		{
			...formRespondMode,
			options: (formRespondMode.options as INodePropertyOptions[])?.filter(
				(option) => option.value !== 'responseNode',
			),
			displayOptions: { show: { '@version': [{ _cnd: { gte: 2.2 } }] } },
		},
		{
			displayName:
				"In the 'Respond to Webhook' node, select 'Respond With JSON' and set the <strong>formSubmittedText</strong> key to display a custom response in the form, or the <strong>redirectURL</strong> key to redirect users to a URL",
			name: 'formNotice',
			type: 'notice',
			displayOptions: {
				show: { responseMode: ['responseNode'] },
			},
			default: '',
		},
		// notice would be shown if no Form node was connected to trigger
		{
			displayName: 'Build multi-step forms by adding a form page later in your workflow',
			name: ADD_FORM_NOTICE,
			type: 'notice',
			default: '',
		},
		{
			displayName: 'Header Auth Settings',
			name: 'headerAuthSettings',
			type: 'fixedCollection',
			placeholder: 'Configure Header Auth',
			default: {},
			displayOptions: {
				show: {
					[FORM_TRIGGER_AUTHENTICATION_PROPERTY]: ['headerAuth'],
				},
			},
			options: [
				{
					displayName: 'Settings',
					name: 'settings',
					values: [
						{
							displayName: 'CSRF Secret',
							name: 'csrfSecret',
							type: 'string',
							typeOptions: {
								password: true,
							},
							default: '',
							required: true,
							description:
								'Secret key used to generate CSRF tokens. Should be a random string of at least 32 characters. Keep this secure.',
						},
						{
							displayName: 'Email Header Name',
							name: 'emailHeaderName',
							type: 'string',
							default: 'x-auth-request-email',
							description:
								'The header name containing the authenticated user email from your auth proxy (e.g., X-Auth-Request-Email for oauth2-proxy)',
						},
						{
							displayName: 'Token Expiry (Minutes)',
							name: 'tokenExpiryMinutes',
							type: 'number',
							default: 60,
							description: 'How long the CSRF token remains valid (default: 60 minutes)',
						},
					],
				},
			],
		},
		{
			displayName: 'Options',
			name: 'options',
			type: 'collection',
			placeholder: 'Add option',
			default: {},
			options: [
				appendAttributionToForm,
				ipAllowlist,
				{
					displayName: 'Button Label',
					description: 'The label of the submit button in the form',
					name: 'buttonLabel',
					type: 'string',
					default: 'Submit',
				},
				{
					...webhookPath,
					required: false,
					displayOptions: { show: { '@version': [{ _cnd: { gte: 2.2 } }] } },
				},
				{
					...respondWithOptions,
					displayOptions: {
						hide: {
							'/responseMode': ['responseNode'],
						},
					},
				},
				{
					displayName: 'Ignore Bots',
					name: 'ignoreBots',
					type: 'boolean',
					default: false,
					description: 'Whether to ignore requests from bots like link previewers and web crawlers',
				},
				{
					...useWorkflowTimezone,
					default: false,
					description: "Whether to use the workflow timezone in 'submittedAt' field or UTC",
					displayOptions: {
						show: {
							'@version': [2],
						},
					},
				},
				{
					...useWorkflowTimezone,
					default: true,
					description: "Whether to use the workflow timezone in 'submittedAt' field or UTC",
					displayOptions: {
						show: {
							'@version': [{ _cnd: { gt: 2 } }],
						},
					},
				},
				{
					displayName: 'Custom Form Styling',
					name: 'customCss',
					type: 'string',
					typeOptions: {
						rows: 10,
						editor: 'cssEditor',
					},
					displayOptions: {
						show: {
							'@version': [{ _cnd: { gt: 2 } }],
						},
					},
					default: cssVariables.trim(),
					description: 'Override default styling of the public form interface with CSS',
				},
			],
		},
	],
};

export class FormTriggerV2 implements INodeType {
	description: INodeTypeDescription;

	constructor(baseDescription: INodeTypeBaseDescription) {
		this.description = {
			...baseDescription,
			...descriptionV2,
		};
	}

	async webhook(this: IWebhookFunctions) {
		return await formWebhook(this);
	}
}
