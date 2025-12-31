const express = require('express');
const mongoose = require('mongoose');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const { exec } = require('child_process');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8090;
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const JWT_SECRETS = {
    weak: 'secret123',
    none: '',
    proper: 'th1s-1s-a-v3ry-l0ng-and-s3cur3-s3cr3t-k3y-2024!'
};

let mysqlPool;
async function initMySQL() {
    try {
        mysqlPool = mysql.createPool({
            host: 'mysql',
            user: 'root',
            password: 'root',
            database: 'vulndb',
            waitForConnections: true,
            connectionLimit: 10
        });
        console.log('MySQL connected');
    } catch (err) {
        console.error('MySQL connection error:', err);
        setTimeout(initMySQL, 5000);
    }
}

mongoose.connect(process.env.MONGO_URI || 'mongodb://mongo:27017/vulnapi')
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    role: { type: String, default: 'user' },
    isAdmin: { type: Boolean, default: false },
    profile: {
        firstName: String,
        lastName: String,
        phone: String,
        address: String,
        creditCard: String,
        ssn: String
    },
    apiKey: String,
    secretNotes: String
});

const DocumentSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    title: String,
    content: String,
    isPrivate: Boolean,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Document = mongoose.model('Document', DocumentSchema);

async function initSampleData() {
    const count = await User.countDocuments();
    if (count === 0) {
        const users = [
            {
                username: 'admin',
                password: await bcrypt.hash('admin123', 10),
                email: 'admin@vulnapi.com',
                role: 'admin',
                isAdmin: true,
                profile: {
                    firstName: 'Admin',
                    lastName: 'User',
                    phone: '555-0100',
                    creditCard: '4111-1111-1111-1111',
                    ssn: '123-45-6789'
                },
                apiKey: 'ak_admin_super_secret_key',
                secretNotes: 'Master password for all systems: SuperSecret2024!'
            },
            {
                username: 'john',
                password: await bcrypt.hash('password123', 10),
                email: 'john@example.com',
                role: 'user',
                isAdmin: false,
                profile: {
                    firstName: 'John',
                    lastName: 'Doe',
                    phone: '555-0101',
                    creditCard: '4222-2222-2222-2222',
                    ssn: '234-56-7890'
                },
                apiKey: 'ak_john_user_key',
                secretNotes: 'Personal notes'
            },
            {
                username: 'jane',
                password: await bcrypt.hash('jane2023', 10),
                email: 'jane@example.com',
                role: 'user',
                isAdmin: false,
                profile: {
                    firstName: 'Jane',
                    lastName: 'Smith',
                    phone: '555-0102',
                    creditCard: '4333-3333-3333-3333',
                    ssn: '345-67-8901'
                },
                apiKey: 'ak_jane_user_key'
            }
        ];
        await User.insertMany(users);
        
        const adminUser = await User.findOne({ username: 'admin' });
        const johnUser = await User.findOne({ username: 'john' });
        
        await Document.insertMany([
            { userId: adminUser._id, title: 'Admin Secrets', content: 'Internal admin credentials: root/toor', isPrivate: true },
            { userId: adminUser._id, title: 'Public Announcement', content: 'Welcome to the API!', isPrivate: false },
            { userId: johnUser._id, title: 'John Private Doc', content: 'My personal banking info...', isPrivate: true },
            { userId: johnUser._id, title: 'John Public Doc', content: 'Hello World!', isPrivate: false }
        ]);
        
        console.log('Sample data initialized');
    }
}

app.get('/api/v1/users/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/v1/documents/:id', async (req, res) => {
    try {
        const doc = await Document.findById(req.params.id);
        if (!doc) return res.status(404).json({ error: 'Document not found' });
        res.json(doc);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/v1/admin/users', async (req, res) => {
    try {
        const users = await User.find({});
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/v1/admin/users/:id', async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/v1/admin/promote/:id', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { role: 'admin', isAdmin: true },
            { new: true }
        );
        res.json({ message: 'User promoted to admin', user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/v1/register', async (req, res) => {
    try {
        const user = new User(req.body);
        user.password = await bcrypt.hash(req.body.password, 10);
        await user.save();
        res.status(201).json({ message: 'User created', userId: user._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/v1/users/:id/profile', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/v1/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role, isAdmin: user.isAdmin },
            JWT_SECRETS.weak,
            { expiresIn: '24h' }
        );
        
        res.json({ token, user: { id: user._id, username: user.username } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/v1/pin-verify', (req, res) => {
    const { pin } = req.body;
    const correctPin = '1234';
    
    if (pin === correctPin) {
        res.json({ success: true, message: 'PIN verified', secretData: 'Sensitive account information here' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid PIN' });
    }
});

app.post('/api/v1/mobile/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign(
            { userId: user._id, username, role: user.role, isAdmin: user.isAdmin },
            JWT_SECRETS.weak,
            { expiresIn: '24h' }
        );
        res.json({ success: true, token, user: { id: user._id, username: user.username } });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.get('/api/v1/mobile/account/me', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRETS.weak);
        res.json({ success: true, account: decoded });
    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired session' });
    }
});

app.post('/api/v1/partner/auth/token', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign(
            { userId: user._id, username, role: user.role, isAdmin: user.isAdmin },
            JWT_SECRETS.proper,
            { expiresIn: '24h' }
        );
        res.json({ access_token: token, token_type: 'Bearer', expires_in: 86400 });
    } else {
        res.status(401).json({ error: 'authentication_failed', error_description: 'Invalid credentials' });
    }
});

app.get('/api/v1/partner/resources', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        const decoded = jwt.decode(token); 
        if (decoded && decoded.isAdmin) {
            res.json({ 
                resources: ['inventory', 'orders', 'analytics', 'admin-settings'],
                permissions: 'full_access',
                data: { partnerLevel: 'platinum', apiQuota: 'unlimited' }
            });
        } else {
            res.json({ 
                resources: ['inventory', 'orders'],
                permissions: 'limited',
                data: { partnerLevel: 'basic', apiQuota: 1000 }
            });
        }
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.post('/api/v1/enterprise/sso/authenticate', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign(
            { userId: user._id, username, role: user.role, isAdmin: user.isAdmin },
            JWT_SECRETS.weak,
            { expiresIn: '24h' }
        );
        res.json({ 
            sessionToken: token, 
            expiresAt: new Date(Date.now() + 86400000).toISOString(),
            user: { displayName: username, role: user.role }
        });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.get('/api/v1/enterprise/admin/dashboard', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRETS.weak);
        if (decoded.isAdmin === true) {
            res.json({ 
                dashboard: {
                    totalUsers: 1523,
                    activeSubscriptions: 892,
                    monthlyRevenue: '$125,430',
                    systemHealth: 'operational'
                },
                settings: {
                    dbConnection: 'mysql://root:root@localhost/production',
                    apiKeys: { stripe: 'sk_live_xxx', sendgrid: 'SG.xxx' }
                }
            });
        } else {
            res.status(403).json({ error: 'Insufficient permissions' });
        }
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

app.get('/api/v1/customers/search', async (req, res) => {
    try {
        const { username } = req.query;
        const query = `SELECT * FROM users WHERE username = '${username}'`;
        const [rows] = await mysqlPool.query(query);
        res.json({ customers: rows });
    } catch (err) {
        res.status(500).json({ error: 'Database query failed' });
    }
});

app.post('/api/v1/pos/authenticate', async (req, res) => {
    try {
        const { username, password } = req.body;
        const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
        const [rows] = await mysqlPool.query(query);
        
        if (rows.length > 0) {
            res.json({ authenticated: true, employee: rows[0], shift: 'active' });
        } else {
            res.status(401).json({ authenticated: false, message: 'Invalid employee credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Authentication service unavailable' });
    }
});

app.get('/api/v1/catalog/products', async (req, res) => {
    try {
        const { id, sort, category } = req.query;
        let query = 'SELECT id, name, description, price FROM products';
        if (id) {
            query += ` WHERE id = ${id}`;
        }
        if (category) {
            query += id ? ` AND category = '${category}'` : ` WHERE category = '${category}'`;
        }
        if (sort) {
            query += ` ORDER BY ${sort}`;
        }
        const [rows] = await mysqlPool.query(query);
        res.json({ products: rows, total: rows.length });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

app.post('/api/v1/social/connect', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (user) {
            const isValidPassword = typeof password === 'string' 
                ? await bcrypt.compare(password, user.password)
                : await User.findOne({ username, password });
            
            if (isValidPassword) {
                res.json({ connected: true, profile: { id: user._id, username: user.username, provider: 'internal' } });
            } else {
                res.status(401).json({ connected: false, message: 'Account linking failed' });
            }
        } else {
            res.status(401).json({ connected: false, message: 'Account linking failed' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Social connect service error' });
    }
});

app.post('/api/v1/auth/dev-login', async (req, res) => {
    const { username, password, token } = req.body;

    const user = await User.findOne({ username });
    
    if (password === true || password === 1) {
        if (user) {
            return res.json({ success: true, legacyMode: true, user: username });
        }
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
 
    if (username && !password) {
        if (user) {
            return res.json({ success: true, sessionRestored: true, user: user.username });
        }
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (user && await bcrypt.compare(password, user.password)) {
        res.json({ success: true, user: { id: user._id, username: user.username } });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

app.get('/api/v1/community/members', async (req, res) => {
    try {
        const users = await User.find({});
        res.json({ members: users, count: users.length }); 
    } catch (err) {
        res.status(500).json({ error: 'Failed to load community members' });
    }
});

app.get('/api/v1/account/profile/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        res.json({
            profile: user,
            accountDetails: {
                apiKey: user.apiKey,
                notes: user.secretNotes,
                paymentMethod: user.profile?.creditCard,
                taxId: user.profile?.ssn
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Profile not found' });
    }
});

app.get('/api/v1/orders/history', async (req, res) => {
    try {
        const [orders] = await mysqlPool.query(`
            SELECT o.*, u.username, u.email, u.credit_card, u.ssn, 
                   p.name as product_name, p.secret_cost, p.internal_notes
            FROM orders o
            JOIN users u ON o.user_id = u.id
            JOIN products p ON o.product_id = p.id
        `);
        res.json({ orders: orders, total: orders.length });  
    } catch (err) {
        res.status(500).json({ error: 'Failed to load order history' });
    }
});

app.get('/internal/admin/dashboard', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress || '';
    const host = req.headers.host || '';
    const forwardedFor = req.headers['x-forwarded-for'] || '';
    const isInternal = clientIP.includes('127.0.0.1') || 
                       clientIP === '::1' || 
                       clientIP.includes('::ffff:127.0.0.1') ||
                       host.includes('localhost') ||
                       host.includes('127.0.0.1');
    
    if (isInternal) {
        res.json({
            status: 'success',
            message: 'Welcome to Internal Admin Dashboard',
            adminPanel: {
                totalRevenue: '$1,542,890.50',
                activeUsers: 15234,
                pendingOrders: 847,
                systemHealth: 'operational'
            },
            sensitiveData: {
                masterApiKey: 'mk_live_9a8b7c6d5e4f3g2h1i0j',
                dbConnectionString: 'mysql://root:root@mysql:3306/vulndb',
                adminCredentials: {
                    username: 'superadmin',
                    password: 'Pr0d_Adm1n_2024!'
                },
                internalEndpoints: [
                    '/internal/admin/users',
                    '/internal/admin/logs',
                    '/internal/admin/config'
                ]
            },
            flag: 'FLAG{SSRF_4cc3ss_t0_1nt3rn4l_d4shb04rd}'
        });
    } else {
        res.status(403).json({ 
            error: 'Access Denied', 
            message: 'This endpoint is only accessible from internal network' 
        });
    }
});

app.get('/api/v1/products/price-check', async (req, res) => {
    try {
        const { productId, supplier_url } = req.query;
        
        if (!productId) {
            return res.status(400).json({ error: 'Product ID is required' });
        }
        
        const [products] = await mysqlPool.query(
            'SELECT id, name, price FROM products WHERE id = ?', 
            [productId]
        );
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        const product = products[0];
        let supplierPrice = null;
        let supplierData = null;
        
        if (supplier_url) {
            try {
                const response = await axios.get(supplier_url, { timeout: 5000 });
                supplierData = response.data;
                supplierPrice = response.data?.price || response.data;
            } catch (err) {
                supplierData = { error: 'Could not fetch supplier price' };
            }
        }
        
        res.json({
            product: {
                id: product.id,
                name: product.name,
                ourPrice: product.price
            },
            supplierComparison: supplierData,
            checkedAt: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ error: 'Price check service unavailable' });
    }
});

app.get('/api/internal/config', (req, res) => {
    res.json({
        adminPassword: 'internal_admin_secret',
        databaseCredentials: { host: 'mysql', user: 'root', password: 'root' },
        internalServices: ['http://localhost:8090/api/internal/secrets']
    });
});

app.get('/api/internal/secrets', (req, res) => {
    res.json({
        jwtSecret: 'th1s-1s-a-v3ry-l0ng-and-s3cur3-s3cr3t-k3y-2024!',
        encryptionKey: 'aes-256-cbc-encryption-key-xxx',
        stripeKey: 'sk_test_xxxxxxxxxxxxxxxxxxxx'
    });
});

app.get('/api/v1/network/ping', (req, res) => {
    const { host } = req.query;
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        res.json({ result: stdout || stderr || error?.message, timestamp: new Date().toISOString() });
    });
});

app.get('/api/v1/files/download', (req, res) => {
    const { filename } = req.query;
    exec(`cat /app/public/${filename}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).json({ error: 'File not found or access denied' });
        } else {
            res.json({ filename: filename, content: stdout });
        }
    });
});

app.get('/api/v1/onboarding/users', async (req, res) => {
    const users = await User.find({}, 'username _id email');
    res.json({ users: users, page: 1, totalPages: 1 });
});

app.get('/api/v1/users/:id/details', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json({ user: user });
});

app.put('/api/v1/users/:id/settings', async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ updated: true, user: user });
});

app.get('/api/v1/admin/system-config', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
        const decoded = jwt.decode(token);
        if (decoded?.isAdmin) {
            res.json({
                config: {
                    masterKey: 'CONGRATULATIONS_YOU_COMPLETED_THE_CHAIN!',
                    systemFlag: 'CTF{C0ngr4tul4t10ns_y0u_h4v3_w0n}',
                    encryptionKey: 'aes256-production-key-xxx'
                }
            });
        } else {
            res.status(403).json({ error: 'Admin privileges required' });
        }
    } catch (err) {
        res.status(401).json({ error: 'Invalid authentication token' });
    }
});

app.get('/api/v1/docs', (req, res) => {
    res.json({
        apiVersion: '1.0.0',
        endpoints: {
            authentication: {
                login: 'POST /api/v1/login',
                register: 'POST /api/v1/register',
                pinVerify: 'POST /api/v1/pin-verify',
                mobileLogin: 'POST /api/v1/mobile/auth/login',
                partnerAuth: 'POST /api/v1/partner/auth/token',
                enterpriseSSO: 'POST /api/v1/enterprise/sso/authenticate',
                devLogin: 'POST /api/v1/auth/dev-login',
                socialConnect: 'POST /api/v1/social/connect'
            },
            users: {
                getUser: 'GET /api/v1/users/:id',
                updateProfile: 'PUT /api/v1/users/:id/profile',
                updateSettings: 'PUT /api/v1/users/:id/settings',
                getUserDetails: 'GET /api/v1/users/:id/details',
                communityMembers: 'GET /api/v1/community/members',
                accountProfile: 'GET /api/v1/account/profile/:id',
                onboardingUsers: 'GET /api/v1/onboarding/users'
            },
            documents: {
                getDocument: 'GET /api/v1/documents/:id'
            },
            admin: {
                listUsers: 'GET /api/v1/admin/users',
                deleteUser: 'DELETE /api/v1/admin/users/:id',
                promoteUser: 'POST /api/v1/admin/promote/:id',
                systemConfig: 'GET /api/v1/admin/system-config',
                enterpriseDashboard: 'GET /api/v1/enterprise/admin/dashboard'
            },
            products: {
                catalog: 'GET /api/v1/catalog/products',
                customerSearch: 'GET /api/v1/customers/search',
                priceCheck: 'GET /api/v1/products/price-check?productId=1&supplier_url=<url>'
            },
            orders: {
                history: 'GET /api/v1/orders/history',
                posAuth: 'POST /api/v1/pos/authenticate'
            },
            integrations: {
                partnerResources: 'GET /api/v1/partner/resources'
            },
            utilities: {
                networkPing: 'GET /api/v1/network/ping',
                fileDownload: 'GET /api/v1/files/download'
            },
            mobile: {
                accountInfo: 'GET /api/v1/mobile/account/me'
            }
        }
    });
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
    await initMySQL();
    await initSampleData();
    
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Vulnerable API running on port ${PORT}`);
        console.log(`Access the application at http://localhost:${PORT}`);
    });
}

start();
