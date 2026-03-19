// Patch the nodes.json and credentials.json files to add Proxy Auth support
const fs = require('fs');
const path = require('path');

// Get base directory from argument or use default
const baseDir = process.argv[2] || '/tmp';

// --- Patch nodes.json ---
const nodesJsonPath = path.join(baseDir, 'types', 'nodes.json');
if (fs.existsSync(nodesJsonPath)) {
  const data = JSON.parse(fs.readFileSync(nodesJsonPath, 'utf8'));

  const formTrigger = data.find(n => n.name === 'formTrigger');
  if (!formTrigger) {
    console.error('formTrigger node not found!');
    process.exit(1);
  }

  const authProp = formTrigger.properties.find(p => p.name === 'authentication');
  if (!authProp) {
    console.error('authentication property not found!');
    process.exit(1);
  }

  // Check if proxyAuth already exists
  if (authProp.options.some(o => o.value === 'proxyAuth')) {
    console.log('proxyAuth already exists');
  } else {
    // Add Proxy Auth option after Basic Auth
    const basicAuthIndex = authProp.options.findIndex(o => o.value === 'basicAuth');
    authProp.options.splice(basicAuthIndex + 1, 0, {
      name: 'Proxy Auth',
      value: 'proxyAuth',
      description: 'For external auth proxies (e.g., oauth2-proxy) that pass authenticated user email via HTTP header'
    });
    console.log('Added proxyAuth option');
  }

  // Remove old proxyAuthSettings if it exists (we'll re-add it with updated structure)
  const existingProxyAuthSettingsIndex = formTrigger.properties.findIndex(p => p.name === 'proxyAuthSettings');
  if (existingProxyAuthSettingsIndex !== -1) {
    formTrigger.properties.splice(existingProxyAuthSettingsIndex, 1);
    console.log('Removed old proxyAuthSettings');
  }

  // Add proxyAuthSettings property (without csrfSecret - now in credentials)
  const authIndex = formTrigger.properties.findIndex(p => p.name === 'authentication');

  const proxyAuthSettings = {
    displayName: 'Proxy Auth Settings',
    name: 'proxyAuthSettings',
    type: 'fixedCollection',
    placeholder: 'Configure Proxy Auth',
    default: {},
    displayOptions: {
      show: {
        authentication: ['proxyAuth']
      }
    },
    options: [
      {
        displayName: 'Settings',
        name: 'settings',
        values: [
          {
            displayName: 'Email Header Name',
            name: 'emailHeaderName',
            type: 'string',
            default: 'x-auth-request-email',
            description: 'HTTP header name containing the authenticated user email'
          },
          {
            displayName: 'Token Expiry (minutes)',
            name: 'tokenExpiryMinutes',
            type: 'number',
            default: 10,
            description: 'How long CSRF tokens remain valid after generation (default: 10 minutes)'
          }
        ]
      }
    ]
  };

  formTrigger.properties.splice(authIndex + 1, 0, proxyAuthSettings);
  console.log('Added updated proxyAuthSettings property');

  // Add proxyAuthApi credential if not exists
  if (!formTrigger.credentials) {
    formTrigger.credentials = [];
  }

  const hasProxyAuthCred = formTrigger.credentials.some(c => c.name === 'proxyAuthApi');
  if (!hasProxyAuthCred) {
    formTrigger.credentials.push({
      name: 'proxyAuthApi',
      required: true,
      displayOptions: {
        show: {
          authentication: ['proxyAuth']
        }
      }
    });
    console.log('Added proxyAuthApi credential reference');
  }

  // Also add proxyAuthApi credential to Form node (for multi-page forms)
  const formNode = data.find(n => n.name === 'form');
  if (formNode) {
    if (!formNode.credentials) {
      formNode.credentials = [];
    }
    const formHasProxyAuthCred = formNode.credentials.some(c => c.name === 'proxyAuthApi');
    if (!formHasProxyAuthCred) {
      formNode.credentials.push({
        name: 'proxyAuthApi',
        required: false  // Not required - only for multi-page proxy auth forms
      });
      console.log('Added proxyAuthApi credential reference to Form node');
    }
  }

  fs.writeFileSync(nodesJsonPath, JSON.stringify(data));
  console.log('Patched nodes.json saved');
} else {
  // Try old path for backwards compatibility
  const oldNodesJsonPath = process.argv[2] || '/tmp/nodes.json';
  if (fs.existsSync(oldNodesJsonPath)) {
    // Run old logic for single file path
    const data = JSON.parse(fs.readFileSync(oldNodesJsonPath, 'utf8'));
    // ... (same logic as above, abbreviated for backwards compat)
    const formTrigger = data.find(n => n.name === 'formTrigger');
    if (formTrigger) {
      const authProp = formTrigger.properties.find(p => p.name === 'authentication');
      if (authProp && !authProp.options.some(o => o.value === 'proxyAuth')) {
        const basicAuthIndex = authProp.options.findIndex(o => o.value === 'basicAuth');
        authProp.options.splice(basicAuthIndex + 1, 0, {
          name: 'Proxy Auth',
          value: 'proxyAuth',
          description: 'For external auth proxies (e.g., oauth2-proxy) that pass authenticated user email via HTTP header'
        });
      }
      fs.writeFileSync(oldNodesJsonPath, JSON.stringify(data));
      console.log('Patched nodes.json (legacy path)');
    }
  }
}

// --- Patch known/credentials.json ---
const knownCredentialsPath = path.join(baseDir, 'known', 'credentials.json');
if (fs.existsSync(knownCredentialsPath)) {
  const knownCredentials = JSON.parse(fs.readFileSync(knownCredentialsPath, 'utf8'));

  if (!knownCredentials.proxyAuthApi) {
    knownCredentials.proxyAuthApi = {
      className: 'ProxyAuthApi',
      sourcePath: 'dist/credentials/ProxyAuthApi.credentials.js',
      supportedNodes: ['formTrigger', 'form']
    };
    fs.writeFileSync(knownCredentialsPath, JSON.stringify(knownCredentials, null, 2));
    console.log('Added proxyAuthApi to known/credentials.json');
  } else {
    console.log('proxyAuthApi already in known/credentials.json');
  }
} else {
  console.log('known/credentials.json not found at:', knownCredentialsPath);
}

// --- Patch types/credentials.json ---
const typesCredentialsPath = path.join(baseDir, 'types', 'credentials.json');
if (fs.existsSync(typesCredentialsPath)) {
  const typesCredentials = JSON.parse(fs.readFileSync(typesCredentialsPath, 'utf8'));

  // Check if proxyAuthApi already exists
  const existingIndex = typesCredentials.findIndex(c => c.name === 'proxyAuthApi');

  const proxyAuthCredential = {
    name: 'proxyAuthApi',
    displayName: 'Proxy Auth',
    documentationUrl: 'proxyauth',
    properties: [
      {
        displayName: 'Encryption Secret',
        name: 'encryptionSecret',
        type: 'string',
        typeOptions: { password: true },
        default: '',
        required: true,
        description: 'Secret key for AES-GCM 256-bit token encryption. Should be at least 32 random characters.'
      }
    ],
    supportedNodes: ['formTrigger', 'form'],
    iconUrl: 'icons/n8n-nodes-base/dist/nodes/Form/form.svg'
  };

  if (existingIndex === -1) {
    // Insert alphabetically (after 'promoterApi' or similar 'pro*' entries)
    let insertIndex = typesCredentials.findIndex(c => c.name > 'proxyAuthApi');
    if (insertIndex === -1) insertIndex = typesCredentials.length;
    typesCredentials.splice(insertIndex, 0, proxyAuthCredential);
    console.log('Added proxyAuthApi to types/credentials.json');
  } else {
    // Update existing
    typesCredentials[existingIndex] = proxyAuthCredential;
    console.log('Updated proxyAuthApi in types/credentials.json');
  }

  fs.writeFileSync(typesCredentialsPath, JSON.stringify(typesCredentials));
  console.log('Saved types/credentials.json');
} else {
  console.log('types/credentials.json not found at:', typesCredentialsPath);
}

console.log('Patching complete!');
