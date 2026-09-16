const express = require('express');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;

// 1. Configure PostgreSQL Pool for Neon DB
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Required for Neon DB secure SSL connection
    }
});

// Test Database Connection on startup
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error connecting to Neon PostgreSQL Database:', err.stack);
    }
    console.log('Successfully connected to Neon PostgreSQL Database.');
    release();
});

// 2. Configure View Engine & Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static assets (CSS, JS, images)
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 3. Dynamic Landing Page Route
app.get('/', async (req, res) => {
    try {
        // Fetch landing page content concurrently from Neon DB
        const contentQuery = pool.query(
            'SELECT * FROM public_landing_content WHERE is_active = TRUE LIMIT 1;'
        );
        const videosQuery = pool.query(
            'SELECT * FROM landing_videos WHERE is_active = TRUE ORDER BY display_order ASC;'
        );
        const modulesQuery = pool.query(
            'SELECT * FROM landing_module_showcase WHERE is_active = TRUE ORDER BY display_order ASC;'
        );
        const plansQuery = pool.query(
            'SELECT * FROM landing_pricing_plans WHERE is_active = TRUE ORDER BY display_order ASC;'
        );

        const [contentResult, videosResult, modulesResult, plansResult] = await Promise.all([
            contentQuery,
            videosQuery,
            modulesQuery,
            plansQuery
        ]);

        // Fallback default values if database tables have no rows yet
        const content = contentResult.rows[0] || {
            hero_title: 'All-In-One E-Commerce Operations & Profitability Platform',
            hero_subtitle: 'Streamline your inventory, resolve courier delivery issues, log monthly expenses, and track real-time net profits in one dynamic ecosystem.',
            cta_button_text: 'Start 14-Day Free Trial',
            cta_button_link: '/signup',
            detailed_about: 'Managing an e-commerce brand involves endless spreadsheets, fragmented delivery tracking, and manual calculation of ad spend versus COGS. EcoSuite Ops brings your whole business under one unified digital ecosystem.',
            section_features: [
                'Zero Manual Data Entry',
                'Isolated Enterprise Security per Module',
                'Real-Time Net Profit Analytics',
                'Role-Based Team Access Control'
            ]
        };

        const videos = videosResult.rows.length > 0 ? videosResult.rows : [
            {
                title: 'Ecosystem Overview & Central Shell',
                description: 'A complete walkthrough showing how microservices connect under one dynamic hub with role-based access.',
                youtube_video_id: 'dQw4w9WgXcQ'
            }
        ];

        // Render master EJS template and supply dynamic data
        res.render('landing', {
            content,
            videos,
            modules: modulesResult.rows || [],
            plans: plansResult.rows || []
        });

    } catch (err) {
        console.error('Error fetching landing page data:', err);
        res.status(500).send('Internal Server Error: Unable to load landing page.');
    }
});

// 4. Global Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

// 5. Start Server on Port 3002
app.listen(PORT, () => {
    console.log(`===================================================`);
    console.log(`EcoSuite Ops Ecosystem Landing Page Running`);
    console.log(`URL: http://localhost:${PORT}`);
    console.log(`===================================================`);
});