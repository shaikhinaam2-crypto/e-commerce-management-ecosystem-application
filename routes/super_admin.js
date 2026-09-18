const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

module.exports = function(authPool) {

    // Auth Guard Middleware strictly for Super Admins
    const verifySuperAdmin = (req, res, next) => {
        const token = req.cookies.eco_auth_token;
        if (!token) return res.redirect('/super-admin/login');

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
            if (decoded.role !== 'SUPER_ADMIN') {
                res.clearCookie('eco_auth_token');
                return res.redirect('/super-admin/login');
            }
            req.user = decoded;
            next();
        } catch (err) {
            res.clearCookie('eco_auth_token');
            return res.redirect('/super-admin/login');
        }
    };

    // GET: Super Admin Login View
    router.get('/login', (req, res) => {
        res.render('login', { error: null, isAdmin: true });
    });

    // POST: Super Admin Login Action
    router.post('/login', async (req, res) => {
        const { email, password } = req.body;
        const genericError = 'Invalid email or password.';

        try {
            const userResult = await authPool.query(
                `SELECT u.id, u.full_name, u.email, u.password_hash, r.role_name 
                 FROM users u
                 JOIN roles r ON u.role_id = r.id
                 WHERE u.email = $1 AND u.is_active = TRUE`,
                [email]
            );

            if (userResult.rows.length === 0) {
                return res.render('login', { error: genericError, isAdmin: true });
            }

            const user = userResult.rows[0];

            if (user.role_name !== 'SUPER_ADMIN') {
                return res.render('login', { error: genericError, isAdmin: true });
            }

            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (!isMatch) {
                return res.render('login', { error: genericError, isAdmin: true });
            }

            const token = jwt.sign(
                {
                    userId: user.id,
                    role: 'SUPER_ADMIN',
                    fullName: user.full_name,
                    companyName: 'System Administration'
                },
                process.env.JWT_SECRET || 'fallback_secret',
                { expiresIn: '1d' }
            );

            res.cookie('eco_auth_token', token, { httpOnly: true, secure: false, maxAge: 24 * 60 * 60 * 1000 });
            res.redirect('/super-admin/dashboard');

        } catch (err) {
            console.error('Super Admin Login error:', err);
            res.render('login', { error: genericError, isAdmin: true });
        }
    });

    // GET: Master Dashboard Shell
    router.get('/dashboard', verifySuperAdmin, (req, res) => {
        res.render('super_admin_dashboard');
    });

    // GET: Render Dynamic Partial View Modules for Super Admin
    router.get('/modules/:moduleName', verifySuperAdmin, async (req, res) => {
        const { moduleName } = req.params;

        try {
            if (moduleName === 'users') {
                // Query all users with role name and organization owner details
                const usersResult = await authPool.query(
                    `SELECT 
                        u.id as user_id, 
                        u.full_name, 
                        u.email, 
                        r.role_name,
                        o.id as organization_id, 
                        o.company_name, 
                        o.account_status, 
                        o.trial_ends_at,
                        owner.full_name as org_admin_name
                     FROM users u
                     JOIN roles r ON u.role_id = r.id
                     JOIN organizations o ON u.organization_id = o.id
                     LEFT JOIN users owner ON owner.organization_id = o.id 
                        AND owner.role_id = (SELECT id FROM roles WHERE role_name = 'ORG_ADMIN')
                     WHERE r.role_name != 'SUPER_ADMIN'
                     ORDER BY o.created_at DESC, r.role_name ASC`
                );

                return res.render('super_admin/users_module', { users: usersResult.rows });
            }

            res.status(404).send('Module view not found.');
        } catch (err) {
            console.error('Error fetching module partial:', err);
            res.status(500).send('Failed to load requested module view.');
        }
    });

    // POST: Manage Account Status & Trial Dates
    router.post('/update-account', verifySuperAdmin, async (req, res) => {
        const { orgId, action, targetDate } = req.body;

        try {
            if (action === 'end_trial' || action === 'expire') {
                await authPool.query(
                    "UPDATE organizations SET account_status = 'expired', is_trial_active = FALSE WHERE id = $1",
                    [orgId]
                );
            } else if (action === 'extend_trial') {
                await authPool.query(
                    "UPDATE organizations SET trial_ends_at = $1, account_status = 'trial', is_trial_active = TRUE WHERE id = $2",
                    [targetDate, orgId]
                );
            } else if (action === 'activate' || action === 'extend_active') {
                await authPool.query(
                    "UPDATE organizations SET trial_ends_at = $1, account_status = 'active', is_trial_active = FALSE WHERE id = $2",
                    [targetDate, orgId]
                );
            } else if (action === 'unactivate') {
                await authPool.query(
                    "UPDATE organizations SET account_status = 'expired' WHERE id = $1",
                    [orgId]
                );
            }

            res.json({ success: true });
        } catch (err) {
            console.error('Status Update Error:', err);
            res.status(500).json({ error: 'Failed to update organization status.' });
        }
    });

    // POST: Password Override API
    router.post('/change-user-password', verifySuperAdmin, async (req, res) => {
        const { userId, newPassword } = req.body;

        try {
            const passwordHash = await bcrypt.hash(newPassword, 10);
            await authPool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, userId]);
            res.json({ success: true });
        } catch (err) {
            console.error('Password Override Error:', err);
            res.status(500).json({ error: 'Failed to update password.' });
        }
    });

    return router;
};