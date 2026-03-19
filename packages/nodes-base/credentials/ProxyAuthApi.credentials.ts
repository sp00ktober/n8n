import type { ICredentialType, INodeProperties } from 'n8n-workflow';

export class ProxyAuthApi implements ICredentialType {
	name = 'proxyAuthApi';

	displayName = 'Proxy Auth';

	documentationUrl = 'proxyauth';

	properties: INodeProperties[] = [
		{
			displayName: 'Encryption Secret',
			name: 'encryptionSecret',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description:
				'Secret key for AES-GCM 256-bit token encryption. Should be at least 32 random characters.',
		},
	];
}
