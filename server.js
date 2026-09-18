const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;

// 1. Dual Neon Database Connections
const landingPool = new Pool({
    connectionString: process.env.LANDING_DB_URL || process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const authPool = new Pool({
    connectionString: process.env.AUTH_DB_URL || process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Auth Guard Middleware for Standard Portal
const verifyToken = (req, res, next) => {
    const token = req.cookies.eco_auth_token;
    if (!token) return res.redirect('/login');

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie('eco_auth_token');
        return res.redirect('/login');
    }
};

// ---------------- MOUNT ROUTERS ----------------

// Super Admin Router
const superAdminRoutes = require('./routes/super_admin')(authPool);
app.use('/super-admin', superAdminRoutes);

// ---------------- PUBLIC ROUTES ----------------

// Landing Page (Uses Landing DB)
app.get('/', async (req, res) => {
    try {
        const contentQuery = landingPool.query('SELECT * FROM public_landing_content WHERE is_active = TRUE LIMIT 1;');
        const videosQuery = landingPool.query('SELECT * FROM landing_videos WHERE is_active = TRUE ORDER BY display_order ASC;');
        const modulesQuery = landingPool.query('SELECT * FROM landing_module_showcase WHERE is_active = TRUE ORDER BY display_order ASC;');
        const plansQuery = landingPool.query('SELECT * FROM landing_pricing_plans WHERE is_active = TRUE ORDER BY display_order ASC;');

        const [contentResult, videosResult, modulesResult, plansResult] = await Promise.all([
            contentQuery, videosQuery, modulesQuery, plansQuery
        ]);

        res.render('landing', {
            content: contentResult.rows[0] || {},
            videos: videosResult.rows || [],
            modules: modulesResult.rows || [],
            plans: plansResult.rows || []
        });
    } catch (err) {
        console.error('Error fetching landing page data:', err);
        res.status(500).send('Error loading landing page');
    }
});

// GET: Signup Page
app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

// POST: Signup Action (Uses Auth DB)
app.post('/api/auth/signup', async (req, res) => {
    const { fullName, companyName, email, password, phone } = req.body;
    const client = await authPool.connect();

    try {
        await client.query('BEGIN');

        // Check if user exists
        const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.render('signup', { error: 'Email address is already registered.' });
        }

        // 1. Create Organization (14-Day Trial)
        const orgResult = await client.query(
            `INSERT INTO organizations (company_name, account_status) 
             VALUES ($1, 'trial') RETURNING id, trial_ends_at`,
            [companyName]
        );
        const org = orgResult.rows[0];

        // 2. Fetch ORG_ADMIN Role ID
        const roleResult = await client.query("SELECT id FROM roles WHERE role_name = 'ORG_ADMIN'");
        const roleId = roleResult.rows[0]?.id || 2;

        // 3. Hash Password & Create User
        const passwordHash = await bcrypt.hash(password, 10);
        const userResult = await client.query(
            `INSERT INTO users (organization_id, full_name, email, password_hash, phone_number, role_id)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, full_name, email`,
            [org.id, fullName, email, passwordHash, phone, roleId]
        );
        const user = userResult.rows[0];

        await client.query('COMMIT');

        // 4. Generate Session Token & Cookie
        const token = jwt.sign(
            {
                userId: user.id,
                orgId: org.id,
                role: 'ORG_ADMIN',
                fullName: user.full_name,
                companyName: companyName,
                trialEndsAt: org.trial_ends_at
            },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '14d' }
        );

        res.cookie('eco_auth_token', token, { httpOnly: true, secure: false, maxAge: 14 * 24 * 60 * 60 * 1000 });
        res.redirect('/app/dashboard');

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Signup Error:', err);
        res.render('signup', { error: 'Failed to create account. Please try again.' });
    } finally {
        client.release();
    }
});

// GET: Standard User Login Page
app.get('/login', (req, res) => {
    res.render('login', { error: null, isAdmin: false });
});

// POST: Standard Login Action
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const genericError = 'Invalid email or password.';

    try {
        const userResult = await authPool.query(
            `SELECT u.id, u.full_name, u.email, u.password_hash, u.organization_id, r.role_name, o.company_name, o.trial_ends_at 
             FROM users u
             JOIN roles r ON u.role_id = r.id
             LEFT JOIN organizations o ON u.organization_id = o.id
             WHERE u.email = $1 AND u.is_active = TRUE`,
            [email]
        );

        if (userResult.rows.length === 0) {
            return res.render('login', { error: genericError, isAdmin: false });
        }

        const user = userResult.rows[0];

        // Reject Super Admins on standard portal
        if (user.role_name === 'SUPER_ADMIN') {
            return res.render('login', { error: genericError, isAdmin: false });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.render('login', { error: genericError, isAdmin: false });
        }

        const token = jwt.sign(
            {
                userId: user.id,
                orgId: user.organization_id,
                role: user.role_name,
                fullName: user.full_name,
                companyName: user.company_name,
                trialEndsAt: user.trial_ends_at
            },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '14d' }
        );

        res.cookie('eco_auth_token', token, { httpOnly: true, secure: false, maxAge: 14 * 24 * 60 * 60 * 1000 });
        res.redirect('/app/dashboard');

    } catch (err) {
        console.error('Standard Login error:', err);
        res.render('login', { error: genericError, isAdmin: false });
    }
});

// GET: Organization Admin Shell Dashboard
app.get('/app/dashboard', verifyToken, async (req, res) => {
    try {
        const modulesResult = await authPool.query(
            'SELECT * FROM system_modules WHERE is_active = TRUE ORDER BY module_name ASC'
        );

        res.render('app_dashboard', {
            user: req.user,
            modules: modulesResult.rows
        });
    } catch (err) {
        console.error('Error loading dashboard:', err);
        res.status(500).send('Error loading ecosystem shell.');
    }
});

// Logout Route
app.get('/logout', (req, res) => {
    res.clearCookie('eco_auth_token');
    res.redirect('/');
});

app.listen(PORT, () => console.log(`Ecosystem Server running on http://localhost:${PORT}`));