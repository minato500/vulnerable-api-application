const vulnerabilities = [
    {
        id: 'bola',
        title: 'BOLA',
        subtitle: 'Broken Object Level Authorization',
        severity: 'High',
        owasp: 'API1:2023',
        description: 'Access resources belonging to other users by manipulating object IDs in API requests.',
        endpoints: [
            { method: 'GET', path: '/api/v1/users/:id' },
            { method: 'GET', path: '/api/v1/documents/:id'},
            { method: 'GET', path: '/api/v1/users/:id/details'}
        ]
    },
    {
        id: 'bfla',
        title: 'BFLA',
        subtitle: 'Broken Function Level Authorization',
        severity: 'Critical',
        owasp: 'API5:2023',
        description: 'Administrative functions accessible without proper authorization checks.',
        endpoints: [
            { method: 'GET', path: '/api/v1/admin/users'},
            { method: 'DELETE', path: '/api/v1/admin/users/:id'},
            { method: 'POST', path: '/api/v1/admin/promote/:id'}
        ]
    },
    {
        id: 'mass-assignment',
        title: 'Mass Assignment',
        subtitle: 'Unprotected Property Binding',
        severity: 'High',
        owasp: 'API6:2019',
        description: 'Modify protected fields by including them in API request bodies.',
        endpoints: [
            { method: 'POST', path: '/api/v1/register'},
            { method: 'PUT', path: '/api/v1/users/:id/profile'},
            { method: 'PUT', path: '/api/v1/users/:id/settings'}
        ]
    },
    {
        id: 'bruteforce',
        title: 'Brute Force',
        subtitle: 'Missing Rate Limiting',
        severity: 'Medium',
        owasp: 'API4:2023',
        description: 'Authentication endpoints allow unlimited attempts, enabling password guessing.',
        endpoints: [
            { method: 'POST', path: '/api/v1/login', desc: 'Unlimited login attempts' },
            { method: 'POST', path: '/api/v1/pin-verify', desc: '4-digit PIN' }
        ]
    },
    {
        id: 'jwt-weak',
        title: 'JWT Weak Secret',
        subtitle: 'Crackable JWT Signature',
        severity: 'Critical',
        owasp: 'API2:2023',
        description: 'JWT tokens signed with weak secret that can be cracked offline.',
        endpoints: [
            { method: 'POST', path: '/api/v1/mobile/auth/login', desc: 'Mobile app authentication' },
            { method: 'GET', path: '/api/v1/mobile/account/me', desc: 'Get account info (JWT required)' },
            { method: 'POST', path: '/api/v1/enterprise/sso/authenticate', desc: 'Enterprise SSO login' },
            { method: 'GET', path: '/api/v1/enterprise/admin/dashboard', desc: 'Admin dashboard' }
        ],
        hint: `Get JWT token:
curl -X POST http://localhost:8090/api/v1/mobile/auth/login -H "Content-Type: application/json" -d '{"username": "john", "password": "password123"}'
`
    },
    {
        id: 'jwt-none',
        title: 'JWT Algorithm None',
        subtitle: 'Signature Bypass via alg:none',
        severity: 'Critical',
        owasp: 'API2:2023',
        description: 'Server uses jwt.decode() instead of jwt.verify(), accepting unsigned tokens.',
        endpoints: [
            { method: 'POST', path: '/api/v1/partner/auth/token', desc: 'Partner API authentication' },
            { method: 'GET', path: '/api/v1/partner/resources', desc: 'Access partner resources' }
        ],
        hint: `Generate a JWT token:
curl -X POST http://localhost:8090/api/v1/partner/auth/token -H "Content-Type: application/json" -d '{"username": "john", "password": "password123"}'
`
    },
    {
        id: 'jwt-escalation',
        title: 'JWT Privilege Escalation',
        subtitle: 'Crack + Modify Payload',
        severity: 'Critical',
        owasp: 'API2:2023',
        description: 'Combine weak secret cracking with payload modification for privilege escalation.',
        endpoints: [
            { method: 'POST', path: '/api/v1/enterprise/sso/authenticate', desc: 'Get initial JWT' },
            { method: 'GET', path: '/api/v1/enterprise/admin/dashboard', desc: 'Admin-only dashboard' }
        ],
        hint: 'Crack the weak secret, then forge a new token with isAdmin:true'
    },
    {
        id: 'sql-injection',
        title: 'SQL Injection',
        subtitle: 'Classic Database Injection',
        severity: 'Critical',
        owasp: 'API8:2023',
        description: 'User input concatenated directly into SQL queries without sanitization.',
        endpoints: [
            { method: 'GET', path: '/api/v1/customers/search?username='},
            { method: 'POST', path: '/api/v1/pos/authenticate'},
            { method: 'GET', path: '/api/v1/catalog/products?id=' }
        ],
        hint: `Use classic SQLi payloads like union`
    },
    {
        id: 'nosql-injection',
        title: 'NoSQL Injection',
        subtitle: 'MongoDB Operator Injection',
        severity: 'High',
        owasp: 'API8:2023',
        description: 'MongoDB queries accept operator injection via JSON and $where JavaScript execution.',
        endpoints: [
            { method: 'POST', path: '/api/v1/social/connect'}
        ],
        hint: `Try login using
curl -X POST http://localhost:8090/api/v1/social/connect -H "Content-Type: application/json" -d '{"username": "username", "password": "password"}'
`
    },
    {
        id: 'auth-bypass',
        title: 'Authentication Bypass',
        subtitle: 'Multiple Bypass Techniques',
        severity: 'Critical',
        owasp: 'API2:2023',
        description: 'Various authentication bypass methods including debug tokens and type confusion.',
        endpoints: [
            { method: 'POST', path: '/api/v1/auth/dev-login', desc: 'Development login endpoint' }
        ],
        hint: `Try login using
curl -X POST http://localhost:8090/api/v1/auth/dev-login -H "Content-Type: application/json" -d '{"username": "username", "password": "password"}'
`
    },
    {
        id: 'data-exposure',
        title: 'Excessive Data Exposure',
        subtitle: 'Sensitive Data Leakage',
        severity: 'High',
        owasp: 'API3:2023',
        description: 'APIs return complete database objects including sensitive internal fields.',
        endpoints: [
            { method: 'GET', path: '/api/v1/community/members', desc: 'Lists all users with full data' },
            { method: 'GET', path: '/api/v1/account/profile/:id', desc: 'Returns SSN, credit card, API keys' },
            { method: 'GET', path: '/api/v1/orders/history', desc: 'Orders with customer payment info' }
        ],
        hint: 'These endpoints leak passwords, SSN, credit cards, and API keys'
    },
    {
        id: 'ssrf',
        title: 'SSRF',
        subtitle: 'Server-Side Request Forgery',
        severity: 'High',
        owasp: 'API7:2023',
        description: 'Server makes HTTP requests to user-supplied URLs without validation.',
        endpoints: [
            { method: 'GET', path: '/api/v1/products/price-check', desc: 'Product price comparison and productId,supplier_url are parameters' }
        ],
        hint: `Try accessing internal endpoints: /internal/admin/dashboard, /api/internal/config, /api/internal/secrets`
    },
    {
        id: 'command-injection',
        title: 'Command Injection',
        subtitle: 'OS Command Execution',
        severity: 'Critical',
        owasp: 'API8:2023',
        description: 'User input passed directly to shell commands without sanitization.',
        endpoints: [
            { method: 'GET', path: '/api/v1/network/ping?host=', desc: 'Network ping utility' },
            { method: 'GET', path: '/api/v1/files/download?filename=', desc: 'File download service' }
        ],
        hint: 'Use command separators: ; | && || ` $() to inject commands'
    },
    {
        id: 'chain',
        title: 'Attack Chain',
        subtitle: 'Multi-Stage Exploitation',
        severity: 'Critical',
        owasp: 'Multiple',
        description: 'Combine multiple vulnerabilities for complete system compromise.',
        endpoints: [
            { method: 'GET', path: '/api/v1/onboarding/users', desc: 'Step 1: Information disclosure' },
            { method: 'GET', path: '/api/v1/users/:id/details', desc: 'Step 2: BOLA - access user data' },
            { method: 'PUT', path: '/api/v1/users/:id/settings', desc: 'Step 3: Mass assignment - become admin' },
            { method: 'GET', path: '/api/v1/admin/system-config', desc: 'Step 4: Access admin secrets' }
        ],
        hint: 'Get user IDs without admin privilege → Escalate privileges → Access admin config for the flag!'
    }
];

function generateCards() {
    const grid = document.getElementById('cardsGrid');
    grid.innerHTML = '';

    vulnerabilities.forEach(vuln => {
        const card = document.createElement('div');
        card.className = 'vuln-card';
        card.onclick = () => openModal(vuln);
        
        const severityClass = vuln.severity.toLowerCase();
        card.innerHTML = `
            <div class="card-header">
                <span class="severity-badge ${severityClass}">${vuln.severity}</span>
                <span class="owasp-badge">${vuln.owasp}</span>
            </div>
            <h3 class="card-title">${vuln.title}</h3>
            <p class="card-subtitle">${vuln.subtitle}</p>
            <p class="card-description">${vuln.description}</p>
            <div class="card-footer">
                <span class="endpoint-count">${vuln.endpoints.length} endpoint${vuln.endpoints.length > 1 ? 's' : ''}</span>
            </div>
        `;
        grid.appendChild(card);
    });
}

function openModal(vuln) {
    const overlay = document.getElementById('modalOverlay');
    const title = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');

    title.textContent = `${vuln.title} - ${vuln.subtitle}`;

    body.innerHTML = `
        <div class="modal-meta">
            <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            <span class="owasp-badge">${vuln.owasp}</span>
        </div>
        
        <div class="info-section">
            <h3>📋 Description</h3>
            <p class="vuln-description">${vuln.description}</p>
        </div>
        
        <div class="info-section">
            <h3>🎯 Vulnerable Endpoints</h3>
            <ul class="endpoint-list">
                ${vuln.endpoints.map(ep => `
                    <li>
                        <div class="endpoint-header">
                            <span class="endpoint-method ${ep.method.toLowerCase()}">${ep.method}</span>
                            <code class="endpoint-path">${ep.path}</code>
                        </div>
                        ${ep.desc ? `<div class="endpoint-desc">${ep.desc}</div>` : ''}
                    </li>
                `).join('')}
            </ul>
        </div>
        
        ${vuln.hint ? `
        <div class="info-section hint-section">
            <h3>💡 Exploitation Hint</h3>
            <pre class="hint-text">${vuln.hint}</pre>
        </div>
        ` : ''}
    `;

    overlay.classList.add('active');
}

function closeModal() {
    document.getElementById('modalOverlay').classList.remove('active');
}

document.getElementById('modalOverlay').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeModal();
});

generateCards();