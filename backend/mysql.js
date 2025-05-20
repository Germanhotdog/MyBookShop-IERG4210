const express = require('express');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const sharp = require('sharp');
const sanitizeHtml = require('sanitize-html'); // For output sanitization
const helmet = require('helmet'); // For CSP and other headers
const app = express();
const https = require('https');
const fs = require('fs');
const bcrypt = require('bcrypt');
const session = require('express-session'); // Add express-session
const csrf = require('csurf');
var bodyParser = require('body-parser');
var busboyBodyParser = require('busboy-body-parser');
var crypto = require('crypto');
const nodemailer = require('nodemailer');

const dotenv = require('dotenv');
dotenv.config({ path: './secret.env' }); // Specify the path to secret.env
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const connection = mysql.createConnection({
    //if mysql.js is now in EC2, change to 'localhost'
    host: 'localhost',
    user: 'test',
    password: 'test',
    database: 'MYBOOKSHOP'
});

const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|gif|png/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        } else {
            cb('Error: Only JPG, GIF, or PNG files allowed!');
        }
    }
});


//if mysql.js is now in EC2, change to 'localhost'
const MySQLStore = require('express-mysql-session')(session);
const sessionStore = new MySQLStore({
    //if mysql.js is now in EC2, change to 'localhost'
    host: 'localhost',
    user: 'test',
    password: 'test',
    database: 'MYBOOKSHOP'
});

// Session middleware configuration
app.use(
    session({
        name: 'authToken', // Cookie name
        secret: 'secretkeyforMyBookShop', // Replace with a strong secret (store in environment variable in production)
        store: sessionStore,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true, // Prevent client-side JavaScript access
            secure: true, // Only send over HTTPS
            maxAge: 24 * 60 * 60 * 1000, // 1 day (in milliseconds, < 3 days)
            sameSite: 'strict', // Prevent CSRF by restricting cross-site requests
        },
    })
);

//Strip webhook
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const stripeSessionID = session.id;
        const orderID = session.metadata.orderID;

        if (!orderID) {
            console.error('OrderID not found in session metadata');
            return res.status(400).send('OrderID not found');
        }

        const checkTransactionSql = 'SELECT * FROM transactions WHERE stripeSessionID = ?';
        connection.query(checkTransactionSql, [stripeSessionID], (err, results) => {
            if (err) {
                console.error('Error checking transaction:', err);
                return res.status(500).send('Database error');
            }

            if (results.length > 0) {
                console.log(`Transaction for Stripe session ${stripeSessionID} already processed`);
                return res.status(200).send('Transaction already processed');
            }

            const getOrderSql = 'SELECT * FROM orders WHERE orderID = ?';
            connection.query(getOrderSql, [orderID], (err, orders) => {
                if (err) {
                    console.error('Error fetching order:', err);
                    return res.status(500).send('Database error');
                }

                if (orders.length === 0) {
                    console.error(`Order not found for orderID ${orderID}`);
                    return res.status(404).send('Order not found');
                }

                const order = orders[0];
                const cartItems = JSON.parse(order.cartItems);
                const totalPrice = order.totalPrice;
                const currency = order.currency;
                const storedDigest = order.digest;
                const salt = order.salt; // Retrieve the stored salt

                const merchantEmail = 'merchant@example.com';
                const digestComponents = [
                    currency,
                    merchantEmail,
                    salt,
                    ...cartItems.map(item => `${item.pid}:${item.quantity}:${item.price}`),
                    totalPrice.toFixed(2)
                ];
                const digestString = digestComponents.join('|');
                console.log('Regenerated digest components:', digestString);

                const regeneratedDigest = crypto.createHash('sha256').update(digestString).digest('hex');
                console.log('Regenerated digest:', regeneratedDigest);

                if (regeneratedDigest !== storedDigest) {
                    console.error('Digest validation failed');
                    return res.status(400).send('Digest validation failed');
                }

                const insertTransactionSql = `
                    INSERT INTO transactions (orderID, stripeSessionID, totalPrice, currency, cartItems, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                `;
                const transactionValues = [
                    orderID,
                    stripeSessionID,
                    totalPrice,
                    currency,
                    JSON.stringify(cartItems),
                    'completed'
                ];

                connection.query(insertTransactionSql, transactionValues, (err, result) => {
                    if (err) {
                        console.error('Error saving transaction:', err);
                        return res.status(500).send('Database error');
                    }

                    console.log('Transaction saved:', result.insertId);
                    res.status(200).send('Webhook processed successfully');
                });
            });
        });
    } else {
        res.status(200).send('Event type not handled');
    }
});

app.use(cors({
    origin: 'https://s13.ierg4210.ie.cuhk.edu.hk', // Allow requests from this origin
    credentials: true // Allow cookies to be sent
}));
//parse multipart/form-data    

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({
extended: true
}));

// parse application/json
app.use(bodyParser.json());


//parse multipart/form-data    
app.use(busboyBodyParser());

app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(helmet()); // Adds security headers including CSP

// Custom CSP configuration
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://js.stripe.com"],
            connectSrc: ["'self'", "https://api.stripe.com"],
            frameSrc: ["https://js.stripe.com"], 
            styleSrc: ["'self'", "https://s13.ierg4210.ie.cuhk.edu.hk", "https://js.stripe.com", "'unsafe-inline'"], 
            imgSrc: ["'self'", "data:", "https://s13.ierg4210.ie.cuhk.edu.hk", "https://*.stripe.com"], 
            objectSrc: ["'none'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: [],
        }
    })
);

app.use(helmet.frameguard({ action: 'deny' })); // Sets X-Frame-Options: DENY
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true })); // Sets Strict-Transport-Security
app.use(helmet.noSniff()); // Sets X-Content-Type-Options: nosniff
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' })); // Sets Referrer-Policy

// Configure csurf middleware
const csrfProtection = csrf({ cookie: false });
app.use((req, res, next) => {
     if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
         return next();
     }
    console.log(`${req.method} ${req.path} - req.body:`, req.body);
    console.log(`${req.method} ${req.path} - req.file:`, req.file);
    console.log(`${req.method} ${req.path} - Session CSRF token:`, req.session.csrfToken);
    console.log(`${req.method} ${req.path} - CSRF token from body:`, req.body._csrf);
    console.log(`${req.method} ${req.path} - CSRF token match:`, req.session.csrfToken === req.body._csrf);
     csrfProtection(req, res, next);
 });

// Input validation and sanitization functions
const sanitizeInput = (input) => sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} });
const validateNumber = (input) => !isNaN(input) && Number(input) >= 0;
const validateInteger = (input) => Number.isInteger(Number(input)) && Number(input) >= 0;

app.get('/admin',csrfProtection, (req, res) => {
    // Check if the user is authenticated and an admin
    if (!req.session.user || !req.session.user.is_admin) {
        return res.status(403).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
            </head>
            <body>
                <h1>Access Denied</h1>
                <p>You must be an admin to access this page.</p>
                <p><a href="https://s13.ierg4210.ie.cuhk.edu.hk/login">Login</a></p>
            </body>
            </html>
        `);
    }
    // Fetch categories
    connection.query('SELECT * FROM categories', (err, categories) => {
        if (err) {
            console.error('Error fetching categories:', err);
            return res.status(500).send('Database error');
        }

        // Fetch products
        connection.query('SELECT * FROM products', (err, products) => {
            if (err) {
                console.error('Error fetching products:', err);
                return res.status(500).send('Database error');
            }

            // Fetch orders
            connection.query('SELECT * FROM orders', (err, orders) => {
                if (err) {
                    console.error('Error fetching orders:', err);
                    return res.status(500).send('Database error');
                }

                // Fetch transactions
                connection.query('SELECT * FROM transactions', (err, transactions) => {
                    if (err) {
                        console.error('Error fetching transactions:', err);
                        return res.status(500).send('Database error');
                    }

                    // Merge orders with transaction data
                    const ordersWithTransactions = orders.map(order => {
                        const transaction = transactions.find(t => t.orderID === order.orderID);
                        return {
                            orderID: order.orderID,
                            username: order.username,
                            cartItems: JSON.parse(order.cartItems),
                            currency: order.currency,
                            totalPrice: order.totalPrice,
                            orderCreatedAt: order.createdAt,
                            transactionID: transaction ? transaction.transactionID : null,
                            status: transaction ? transaction.status : null,
                            transactionCreatedAt: transaction ? transaction.createdAt : null
                        };
                    });

                    // Use the existing CSRF token from the session, or generate a new one if missing
                    const csrfToken = req.session.csrfToken;
                    const userWithCsrf = {
                        ...req.session.user,
                        csrfToken: csrfToken
                    };
                    res.send(generateAdminPage(categories, products,userWithCsrf, ordersWithTransactions));
                });
            });
        });
    });
});

// Register page (GET)
app.get('/register', csrfProtection, (req, res) => {
    const csrfToken = req.csrfToken();
    console.log(`csrfToken in Register: ${csrfToken}`);
    
    // Render the register page with the CSRF token
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Register - MyBookShop</title>
            <link rel="stylesheet" href="/login.css">
        </head>
        <body>
            <header>
                <nav>
                    <div class="icon">
                        <a href="/">MyBookShop <img src="/image/icon.png" alt="Icon"></a>
                    </div>
                    <div class="navbar-list">
                        <ul>
                            <li><a href="/">Home</a></li>
                            <li><a href="#">About Us</a></li>
                            <li><a href="/login">Login</a></li>
                        </ul>
                    </div>
                </nav>
            </header>

            <div class="register-container">
                <h2>Register for MyBookShop</h2>
                <form id="register-form" action="/register" method="POST">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required maxlength="50">
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required maxlength="255">
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required minlength="8">
                    </div>
                    <button type="submit">Register</button>
                    <p>Already have an account? <a href="/login">Login here</a></p>
                </form>
                <p id="error-message" style="color: red; display: none;"></p>
            </div>

            <script src="/register.js"></script>
        </body>
        </html>
    `);
});

//register
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await hashPassword(password);
        const sql = 'INSERT INTO user (username, email, password, is_admin) VALUES (?, ?, ?, ?)';
        connection.query(sql, [username, email, hashedPassword, false], (err) => {
            if (err) {
                console.error('Query Error:', err);
                return res.status(500).send('Database error: ' + err.message);
            }
            res.redirect('/login');
        });
    } catch (err) {
        res.status(500).send('Error hashing password: ' + err.message);
    }
});

// Function to hash password (same as above)
const hashPassword = async (password) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    return await bcrypt.hash(password, salt);
};

const rateLimit = require('express-rate-limit');

// Login route (AJAX) rateLimit with 15 minutes, Limit to 100 requests per window
app.post('/login',rateLimit({windowMs: 15 * 60 * 1000, max: 100 }),csrfProtection, async (req, res) => {
    console.log('POST /login - Session:', req.session);
    console.log('POST /login - Session CSRF token:', req.session.csrfToken);
    console.log('POST /login - Body:', req.body);
    console.log('POST /login - CSRF token from body:', req.body._csrf);

    const { email, password, _csrf } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: `Email${email} and password${password} are required` });
    }

    try {
        connection.query('SELECT * FROM user WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error('Query Error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            if (results.length === 0) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            const user = results[0];
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }
            // Regenerate session to prevent session fixation
            req.session.regenerate((err) => {
                if (err) {
                    console.error('Session regeneration error:', err);
                    return res.status(500).json({ message: 'Server error' });
                }

                // Store user info in the session
                req.session.user = {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    is_admin: user.is_admin
                };
		
		const newCsrfToken = req.csrfToken();
                req.session.csrfToken = newCsrfToken; // Explicitly store in session
                console.log('POST /login - New CSRF token after regeneration:', newCsrfToken);
		    
                res.json({
                    username: user.username,
                    is_admin: user.is_admin
                });
            });
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Logout route
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.clearCookie('auth_token'); // Clear the session cookie
        res.json({ message: 'Logged out successfully' });
    });
});

// Product API
app.get('/api/products', (req, res) => {
    const catid = req.query.catid;
    const sql = catid ? 'SELECT * FROM products WHERE catid = ?' : 'SELECT * FROM products';
    if (catid && !validateInteger(catid)) {
        return res.status(400).json({ error: 'Invalid category ID' });
    }
    connection.query(sql, [catid], (err, products) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(products);
    });
});

// Fetch product by name
app.get('/api/product/:pid', (req, res) => {
    const productId = sanitizeInput(req.params.pid);
    if (!validateInteger(productId)) {
        return res.status(400).json({ error: 'Invalid product ID' });
    }
    connection.query(
        'SELECT * FROM products WHERE pid = ?',
        [productId],
        (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (results.length === 0) return res.status(404).json({ error: 'Product not found' });
            res.json(results[0]);
        }
    );
});
//Categories API
app.get('/api/categories', (req, res) => {
    connection.query('SELECT * FROM categories', (err, categories) => {
        if (err) {
            console.error('Query Error:', err);
            res.status(500).json({ error: 'Database error' });
            return;
        }
        res.json(categories);
    });
});

//Categories API with specific categories
app.get('/api/categories/:catid', (req, res) => {
    const catid = sanitizeInput(req.params.catid);
    if (!validateInteger(catid)) {
        return res.status(400).json({ error: 'Invalid category ID' });
    }
    connection.query('SELECT * FROM categories WHERE catid = ?', [catid], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(404).json({ error: 'Category not found' });
        res.json(results[0]);
    });
});

// Middleware to check if the user is an admin
const isAdmin = (req, res, next) => {
    if (!req.session.user || !req.session.user.is_admin) {
        return res.status(403).send('Access denied: Admin privileges required');
    }
    next();
};

function generateLoginPage(csrfToken, user, orders = []) {
    const escapeHtml = (unsafe) => unsafe.replace(/[&<>"']/g, (char) => {
        const escapeMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return escapeMap[char] || char;
    });

    if (user) {
        // Logged-in view with order history
        return `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Login - MyBookShop</title>
                <link rel="stylesheet" href="/login.css">
                <style>
                    .order-history { margin: 20px 0; }
                    .order-item { border: 1px solid #ccc; padding: 10px; margin: 5px 0; }
                    .product-list { margin-left: 20px; }
                </style>
            </head>
            <body>
                <header>
                    <nav>
                        <div class="icon">
                            <a href="/">MyBookShop <img src="/image/icon.png" alt="Icon"></a>
                        </div>
                        <div class="navbar-list">
                            <ul>
                                <li><a href="/">Home</a></li>
                                <li><a href="#">About Us</a></li>
                                <li><a href="/change-password">Change Password</a></li>
                            </ul>
                        </div>
                    </nav>
                </header>

                <div class="logout-container">
                    <h2>You are logged in as ${escapeHtml(user.username)}</h2>
                    <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">
                    <button id="logout-button-main">Logout</button>
                    <button type="button" id="reset-password-button">Reset Password</button>
                    <button type="button" id="login-button">Login</button>
                    <button type="button" id="register-button">Register</button>
                </div>

                <div class="order-history">
                    <h3>Your Recent Orders (Last 5)</h3>
                    ${orders.length === 0 ? '<p>No recent orders found.</p>' : orders.map(order => `
                        <div class="order-item">
                            <p><strong>Order ID:</strong> ${escapeHtml(String(order.orderID))}</p>
                            <p><strong>Cart Items:</strong></p>
                            <div class="product-list">
                                ${(order.cartItems && order.cartItems.length > 0) ? order.cartItems.map(item => `
                                    <p>
                                        Product Name: ${escapeHtml(item.name)} | 
                                        Quantity: ${escapeHtml(String(item.quantity))} | 
                                        Price: $${escapeHtml(String(item.price.toFixed(2)))}
                                    </p>
                                `).join('') : '<p>No items</p>'}
                            </div>
                            <p><strong>Currency:</strong> ${escapeHtml(order.currency)}</p>
                            <p><strong>Total Price:</strong> $${escapeHtml(String(order.totalPrice.toFixed(2)))}</p>
                            <p><strong>Status:</strong> ${order.status ? escapeHtml(order.status) : 'Pending'}</p>
                            <p><strong>Order Date:</strong> ${escapeHtml(new Date(order.orderCreatedAt).toLocaleString())}</p>
                        </div>
                    `).join('')}
                </div>

                <script src="/login.js"></script>
            </body>
            </html>
        `;
    } else {
        // Logged-out view
        return `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Login - MyBookShop</title>
                <link rel="stylesheet" href="/login.css">
            </head>
            <body>
                <header>
                    <nav>
                        <div class="icon">
                            <a href="/">MyBookShop <img src="/image/icon.png" alt="Icon"></a>
                        </div>
                        <div class="navbar-list">
                            <ul>
                                <li><a href="/">Home</a></li>
                                <li><a href="#">About Us</a></li>
                                <li><a href="/login">Login</a></li>
                            </ul>
                        </div>
                    </nav>
                </header>

                <div class="login-container">
                    <h2>Login to MyBookShop</h2>
                    <form id="login-form">
                        <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">
                        <div class="form-group">
                            <label for="email">Email:</label>
                            <input type="email" id="email" name="email" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <button type="submit">Login</button>
                        <a href="/register">Register</a>
                        <a href="/recover-password">Recover Password</a>
                    </form>
                    <p id="error-message" style="color: red; display: none;"></p>
                </div>

                <script src="/login.js"></script>
            </body>
            </html>
        `;
    }
}

// Login page
app.get('/login',csrfProtection, (req, res) => {
    // Generate CiSRF token
    //const csrfToken = req.csrfToken ? req.csrfToken() : '';
    console.log(`csrfToken in Login: ${req.session.csrfToken}`);

    const forceLoginView = req.query.view === 'login';

    const csrfToken = req.session.csrfToken || req.csrfToken();
    if(req.session.user && !forceLoginView){
        // Step 1: Fetch the user's most recent 5 orders with transaction status
        const query = `
            SELECT 
                o.orderID,
                o.username,
                o.cartItems,
                o.currency,
                o.totalPrice,
                o.createdAt AS orderCreatedAt,
                t.transactionID,
                t.status,
                t.createdAt AS transactionCreatedAt
            FROM orders o
            LEFT JOIN transactions t ON o.orderID = t.orderID
            WHERE o.username = ?
            ORDER BY o.createdAt DESC
            LIMIT 5
        `;
        connection.query(query, [req.session.user.username], (err, ordersWithTransactions) => {
            if (err) {
                console.error('Error fetching orders for user:', err);
                return res.status(500).send('Database error');
            }

            // Step 2: Extract all unique product IDs from cartItems across all orders
            const allProductIds = new Set();
            ordersWithTransactions.forEach(order => {
                const cartItems = JSON.parse(order.cartItems || '[]');
                cartItems.forEach(item => {
                    if (item.pid) {
                        allProductIds.add(item.pid);
                    }
                });
            });

            // Step 3: Fetch product names for all product IDs
            if (allProductIds.size > 0) {
                const productQuery = `SELECT pid, name FROM products WHERE pid IN (${Array.from(allProductIds).map(() => '?').join(',')})`;
                connection.query(productQuery, Array.from(allProductIds), (err, products) => {
                    if (err) {
                        console.error('Error fetching product names:', err);
                        return res.status(500).send('Database error');
                    }

                    // Create a map of pid to product name
                    const productMap = new Map(products.map(product => [product.pid, product.name]));

                    // Step 4: Process orders and replace pid with product name in cartItems
                    const processedOrders = ordersWithTransactions.map(order => {
                        const cartItems = JSON.parse(order.cartItems || '[]').map(item => ({
                            name: productMap.get(item.pid) || 'Unknown Product',
                            quantity: item.quantity,
                            price: item.price
                        }));
                        return {
                            orderID: order.orderID,
                            username: order.username,
                            cartItems: cartItems,
                            currency: order.currency,
                            totalPrice: order.totalPrice,
                            orderCreatedAt: order.orderCreatedAt,
                            transactionID: order.transactionID,
                            status: order.status,
                            transactionCreatedAt: order.transactionCreatedAt
                        };
                    });

                    // Step 5: Render the page using generateLoginPage
                    const html = generateLoginPage(csrfToken, req.session.user, processedOrders);
                    res.send(html);
                });
            } else {
                // If there are no product IDs (empty orders), render without product names
                const processedOrders = ordersWithTransactions.map(order => ({
                    orderID: order.orderID,
                    username: order.username,
                    cartItems: [],
                    currency: order.currency,
                    totalPrice: order.totalPrice,
                    orderCreatedAt: order.orderCreatedAt,
                    transactionID: order.transactionID,
                    status: order.status,
                    transactionCreatedAt: order.transactionCreatedAt
                }));

                const html = generateLoginPage(csrfToken, req.session.user, processedOrders);
                res.send(html);
            }
        });
    }
    else{
        // Render the logged-out view using generateLoginPage
        const html = generateLoginPage(csrfToken, null);
        res.send(html);
    }
});

app.get('/change-password',csrfProtection, (req, res) => {

    const csrfToken = req.csrfToken();
    console.log('GET /change-password - CSRF token:', csrfToken);

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Change Password - MyBookShop</title>
            <link rel="stylesheet" href="/login.css">
        </head>
        <body>
            <header>
                <nav>
                    <div class="icon">
                        <a href="/">MyBookShop <img src="/image/icon.png" alt="Icon"></a>
                    </div>
                    <div class="navbar-list">
                        <ul>
                            <li><a href="/">Home</a></li>
                            <li><a href="#">About Us</a></li>
                            <li><a href="/logout">Logout</a></li>
                        </ul>
                    </div>
                </nav>
            </header>

            <div class="change-password-container">
                <h2>Change Password</h2>
                <form id="change-password-form" method="POST" action="/change-password">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <div class="form-group">
                        <label for="current-password">Current Password:</label>
                        <input type="password" id="current-password" name="currentPassword" required>
                    </div>
                    <div class="form-group">
                        <label for="new-password">New Password:</label>
                        <input type="password" id="new-password" name="newPassword" required>
                    </div>
                    <div class="form-group">
                        <label for="confirm-password">Confirm New Password:</label>
                        <input type="password" id="confirm-password" name="confirmPassword" required>
                    </div>
                    <button type="submit">Change Password</button>
                </form>
                <p id="error-message" style="color: red; display: none;"></p>
            </div>

            <script src="/login.js"></script>
        </body>
        </html>
    `);
});

app.post('/change-password', async (req, res) => {
    // Check if the user is logged in
    if (!req.session.user) {
        return res.status(401).json({ message: 'You must be logged in to change your password' });
    }

    const { currentPassword, newPassword, confirmPassword, _csrf } = req.body;

    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: 'New password and confirmation do not match' });
    }

    if (newPassword.length < 8) {
        return res.status(400).json({ message: 'New password must be at least 8 characters long' });
    }

    try {
        // Fetch the user from the database
        const [user] = await new Promise((resolve, reject) => {
            connection.query('SELECT * FROM user WHERE id = ?', [req.session.user.id], (err, results) => {
                if (err) return reject(err);
                resolve(results);
            });
        });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Validate the current password
        const passwordMatch = await bcrypt.compare(currentPassword, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update the password in the database
        await new Promise((resolve, reject) => {
            connection.query('UPDATE user SET password = ? WHERE id = ?', [hashedNewPassword, req.session.user.id], (err) => {
                if (err) return reject(err);
                resolve();
            });
        });

        // Destroy the session to log out the user
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destruction error:', err);
                return res.status(500).json({ message: 'Failed to log out after password change' });
            }

            res.clearCookie('auth_token');
            res.json({ message: 'Password changed successfully. You have been logged out.' });
            });
        } catch (err) {
            console.error('Change password error:', err);
            res.status(500).json({ message: 'Server error' });
        }
    });

app.get('/checkout', csrfProtection, (req, res) => {
    const csrfToken = req.session.csrfToken || req.csrfToken();
    console.log('GET /change-password - CSRF token:', csrfToken);


    // Fetch categories for the navigation bar
    connection.query('SELECT * FROM categories', (err, categories) => {
        if (err) {
            console.error('Error fetching categories:', err);
            return res.status(500).send('Database error');
        }

        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta http-equiv="Content-Security-Policy" content="
                    script-src 'self' https://js.stripe.com;
                    connect-src 'self' https://api.stripe.com;
                    frame-src https://js.stripe.com;
                    style-src 'self' https://js.stripe.com 'unsafe-inline';
                    img-src 'self' https://*.stripe.com;
                ">

                <link rel="stylesheet" href="/checkout.css">
                <title>Checkout</title>
                <!-- Include Stripe.js -->
                <script src="https://js.stripe.com/v3/"></script>
            </head>
            <body>
                <h1>Checkout</h1>
                <form id="checkout-form">
                    <div id="checkout-items"></div>
                    <div id="error-message" class="error"></div>
                    <button type="submit" id="place-order-btn">Place Order</button>
                    <!-- Hidden CSRF token (optional, if still needed for other purposes) -->
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                </form>
                <script src="/checkout.js"></script>
            </body>
            </html>
        `);
    });
});

app.get('/success', (req, res) => {
    // Clear the cart in localStorage (client-side)
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Payment Successful</title>
        </head>
        <body>
            <h1>Payment Successful</h1>
            <p>Thank you for your purchase!</p>
            <a href="/">Return to Home</a>
            <script>
                // Clear the cart
                localStorage.removeItem('shoppingCart');
            </script>
        </body>
        </html>
    `);
});

// Route to create a Stripe Checkout session
app.post('/create-checkout-session',csrfProtection, async (req, res) => {
    try {
        const cartData = req.body.cart; // Cart data sent from the client
        console.log('Received cart data:', cartData);
        if (!Array.isArray(cartData) || cartData.length === 0) {
            return res.status(400).json({ error: 'Cart is empty or invalid' });
        }

        // Fetch product details from the database
        const productIds = cartData.map(item => parseInt(item.pid)); // Convert to integer
        const placeholders = productIds.map(() => '?').join(',');
        const sql = `SELECT pid, name, price FROM products WHERE pid IN (${placeholders})`;
        
        connection.query(sql, productIds, (err, results) => {
            if (err) {
                console.error('Error fetching products:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            console.log('Fetched products:', results);

            // Validate quantities and map cart items
            const validatedCartItems = cartData.map(cartItem => {
                const pid = parseInt(cartItem.pid);
                const quantity = parseInt(cartItem.quantity);

                // Ensure quantity is a positive number
                if (!Number.isInteger(quantity) || quantity <= 0) {
                    console.warn(`Invalid quantity for pid ${pid}: ${quantity}`);
                    return null;
                }

                const product = results.find(p => p.pid === pid);
                if (!product) {
                    console.warn(`Product not found for pid ${pid}`);
                    return null;
                }

                return {
                    pid: pid,
                    quantity: quantity,
                    price: parseFloat(product.price)
                };
            }).filter(item => item !== null);

            if (validatedCartItems.length === 0) {
                console.error('No valid items in cart after validation');
                return res.status(400).json({ error: 'No valid items in cart' });
            }

            // Calculate total price
            const totalPrice = validatedCartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
            console.log('Total price:', totalPrice);

            // Generate digest
            const currency = 'hkd'; // From your previous setup
            const merchantEmail = 'merchant@example.com'; // Replace with your merchant email
            const salt = crypto.randomBytes(16).toString('hex'); // Random salt

            // Prepare digest components with delimiter '|'
            const digestComponents = [
                currency,
                merchantEmail,
                salt,
                ...validatedCartItems.map(item => `${item.pid}:${item.quantity}:${item.price}`),
                totalPrice.toFixed(2)
            ];
            const digestString = digestComponents.join('|');
            console.log('Digest components:', digestString);

            // Generate SHA-256 hash
            const digest = crypto.createHash('sha256').update(digestString).digest('hex');
            console.log('Generated digest:', digest);

            // Get username (or 'guest' if not logged in)
            const username = req.session.user ? req.session.user.username : 'guest';
            console.log('Username:', username);

            // Store order in the database
            const orderSql = `
                INSERT INTO orders (username, cartItems, currency, totalPrice, digest, salt)
                VALUES (?, ?, ?, ?, ?, ?)
            `;
            const orderValues = [
                username,
                JSON.stringify(validatedCartItems), // Store cart items as JSON
                currency,
                totalPrice,
                digest,
                salt
            ];

            //Insert data to "orders" Database and Pass data to Stripe
            connection.query(orderSql, orderValues, (err, result) => {
                if (err) {
                    console.error('Error inserting order:', err);
                    return res.status(500).json({ error: 'Failed to store order' });
                }

                const orderID = result.insertId;
                console.log('Inserted orderID:', orderID);

                // Create Stripe Checkout session
                const lineItems = validatedCartItems.map(item => ({
                    price_data: {
                        currency: currency,
                        product_data: {
                            name: results.find(p => p.pid === item.pid).name,
                        },
                        unit_amount: Math.round(item.price * 100),
                    },
                    quantity: item.quantity,
                }));

                stripe.checkout.sessions.create({
                    payment_method_types: ['card'],
                    line_items: lineItems,
                    mode: 'payment',
                    success_url: 'https://s13.ierg4210.ie.cuhk.edu.hk/success',
                    cancel_url: 'https://s13.ierg4210.ie.cuhk.edu.hk/checkout',
                    metadata: {
                        orderID: orderID.toString() // Include orderID in metadata
                    }
                }).then(session => {
                    console.log('Stripe session created:', session);
                    // Return session ID, orderID, and digest
                    res.json({
                        id: session.id,
                        orderID: orderID,
                        digest: digest
                    });
                }).catch(err => {
                    console.error('Error creating Stripe session:', err.message);
                    res.status(500).json({ error: 'Failed to create checkout session: ' + err.message });
                });
            });
        });
    } catch (err) {
        console.error('Error in /create-checkout-session:', err);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

// Configure Nodemailer (replace with your email service credentials)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'jackyjai1026@gmail.com', 
        pass: 'otvnirogsyvjtler'     
    }
});

// Utility function to generate a random nonce
function generateNonce() {
    return crypto.randomBytes(32).toString('hex'); // 64-character hex string
}

// GET /recover-password - Display password recovery form
app.get('/recover-password', csrfProtection, (req, res) => {
    const csrfToken = req.csrfToken();

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Recover Password - MyBookShop</title>
            <link rel="stylesheet" href="/login.css">
        </head>
        <body>
            <header>
                <nav>
                    <div class="icon">
                        <a href="/">MyBookShop <img src="/image/icon.png" alt="Icon"></a>
                    </div>
                    <div class="navbar-list">
                        <ul>
                            <li><a href="/">Home</a></li>
                            <li><a href="#">About Us</a></li>
                            <li><a href="/login">Login</a></li>
                        </ul>
                    </div>
                </nav>
            </header>

            <div class="recover-password-container">
                <h2>Recover Your Password</h2>
                <form id="recover-password-form" method="POST" action="/recover-password">
                    <input type="hidden" name="_csrf" value="${csrfToken}">
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <button type="submit">Request Password Reset</button>
                    <p>Remembered your password? <a href="/login">Login here</a></p>
                </form>
                <p id="recover-error-message" style="color: red; display: none;"></p>
                <p id="recover-success-message" style="color: green; display: none;"></p>
            </div>

            <script src="/login.js"></script>
        </body>
        </html>
    `);
});

// POST /recover-password - Handle password recovery request
app.post('/recover-password', csrfProtection, (req, res) => {
    const { email } = req.body;

    // Step 1: Validate email input
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: 'Please enter a valid email address' });
    }

    // Step 2: Check if the email exists in the user table
    const checkUserSql = 'SELECT * FROM user WHERE email = ?';
    connection.query(checkUserSql, [email], (err, users) => {
        if (err) {
            console.error('Error checking user:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        // Step 3: Always return a generic success message for security (don't reveal if email exists)
        // But only proceed with email sending if the user exists
        if (users.length > 0) {
            // Step 4: Generate a nonce and set expiration (1 hour from now)
            const nonce = generateNonce();
            const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour expiry

            // Step 5: Store the nonce in the password_reset_tokens table
            const insertTokenSql = 'INSERT INTO password_reset_tokens (email, nonce, expires_at) VALUES (?, ?, ?)';
            connection.query(insertTokenSql, [email, nonce, expiresAt], (err) => {
                if (err) {
                    console.error('Error storing reset token:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                // Step 6: Send the recovery email
                const resetLink = `https://s13.ierg4210.ie.cuhk.edu.hk/reset-password/${nonce}`;
                const mailOptions = {
                    from: 'jackyjai1026@gmail.com',
                    to: email,
                    subject: 'MyBookShop Password Recovery Request',
                    html: `
                        <h2>Password Recovery Request</h2>
                        <p>You have requested to recover your password for MyBookShop.</p>
                        <p>Please click the link below to reset your password (valid for 1 hour):</p>
                        <p><a href="${resetLink}">${resetLink}</a></p>
                        <p>If you did not request this, please ignore this email or contact support.</p>
                    `
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending email:', error);
                        return res.status(500).json({ message: 'Error sending email' });
                    }

                    console.log('Password recovery email sent:', info.response);
                    res.json({ message: 'If an account exists with that email, a password reset link has been sent.' });
                });
            });
        } else {
            // Even if the email doesn't exist, return the same message for security
            res.json({ message: 'If an account exists with that email, a password reset link has been sent.' });
        }
    });
});

// GET /reset-password/:nonce - Display password reset form
app.get('/reset-password/:nonce', csrfProtection, (req, res) => {
    const { nonce } = req.params;
    const currentTime = new Date();

    // Step 1: Validate the nonce
    const checkTokenSql = 'SELECT * FROM password_reset_tokens WHERE nonce = ? AND expires_at > ? AND used = FALSE';
    connection.query(checkTokenSql, [nonce, currentTime], (err, tokens) => {
        if (err) {
            console.error('Error checking reset token:', err);
            return res.status(500).send('Database error');
        }

        if (tokens.length === 0) {
            return res.status(400).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Invalid Reset Link - MyBookShop</title>
                    <link rel="stylesheet" href="/login.css">
                </head>
                <body>
                    <header>
                        <nav>
                            <div class="icon">
                                <a href="/">MyBookShop <img src="/image/icon.png" alt="Icon"></a>
                            </div>
                            <div class="navbar-list">
                                <ul>
                                    <li><a href="/">Home</a></li>
                                    <li><a href="#">About Us</a></li>
                                    <li><a href="/logout">Logout</a></li>
                                </ul>
                            </div>
                        </nav>
                    </header>
                    <div class="reset-password-container">
                        <h2>Invalid or Expired Link</h2>
                        <p>The password reset link is invalid or has expired. Please request a new one.</p>
                        <p><a href="/change-password">Request New Link</a></p>
                    </div>
                </body>
                </html>
            `);
        }

        const email = tokens[0].email;
        const csrfToken = req.csrfToken();

        // Step 2: Display the reset form
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Password - MyBookShop</title>
                <link rel="stylesheet" href="/login.css">
            </head>
            <body>
                <header>
                    <nav>
                        <div class="icon">
                            <a href="/">MyBookShop <img src="/image/icon.png" alt="Icon"></a>
                        </div>
                        <div class="navbar-list">
                            <ul>
                                <li><a href="/">Home</a></li>
                                <li><a href="#">About Us</a></li>
                                <li><a href="/logout">Logout</a></li>
                            </ul>
                        </div>
                    </nav>
                </header>

                <div class="reset-password-container">
                    <h2>Reset Your Password</h2>
                    <form id="reset-password-form" method="POST" action="/reset-password/${nonce}">
                        <input type="hidden" name="_csrf" value="${csrfToken}">
                        <input type="hidden" name="email" value="${email}">
                        <div class="form-group">
                            <label for="new-password">New Password:</label>
                            <input type="password" id="new-password" name="newPassword" required>
                        </div>
                        <div class="form-group">
                            <label for="confirm-password">Confirm New Password:</label>
                            <input type="password" id="confirm-password" name="confirmPassword" required>
                        </div>
                        <button type="submit">Reset Password</button>
                    </form>
                    <p id="reset-error-message" style="color: red; display: none;"></p>
                </div>

                <script src="/login.js"></script>
            </body>
            </html>
        `);
    });
});

// POST /reset-password/:nonce - Process password reset
app.post('/reset-password/:nonce', csrfProtection, async (req, res) => {
    const { nonce } = req.params;
    const { email, newPassword, confirmPassword } = req.body;
    const currentTime = new Date();

    // Step 1: Validate the nonce
    const checkTokenSql = 'SELECT * FROM password_reset_tokens WHERE nonce = ? AND email = ? AND expires_at > ? AND used = FALSE';
    connection.query(checkTokenSql, [nonce, email, currentTime], async (err, tokens) => {
        if (err) {
            console.error('Error checking reset token:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (tokens.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired reset link' });
        }

        // Step 2: Validate passwords
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'New password and confirmation do not match' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ message: 'New password must be at least 8 characters long' });
        }

        try {
            // Step 3: Hash the new password
            const hashedPassword = await hashPassword(newPassword);

            // Step 4: Update the user's password
            const updatePasswordSql = 'UPDATE user SET password = ? WHERE email = ?';
            connection.query(updatePasswordSql, [hashedPassword, email], (err) => {
                if (err) {
                    console.error('Error updating password:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                // Step 5: Mark the token as used
                const markTokenUsedSql = 'UPDATE password_reset_tokens SET used = TRUE WHERE nonce = ?';
                connection.query(markTokenUsedSql, [nonce], (err) => {
                    if (err) {
                        console.error('Error marking token as used:', err);
                        return res.status(500).json({ message: 'Database error' });
                    }

                    // Step 6: Destroy the session (if any) and redirect to login
                    if (req.session) {
                        req.session.destroy((err) => {
                            if (err) {
                                console.error('Error destroying session:', err);
                            }
                            res.json({ message: 'Password reset successfully. Please log in with your new password.' });
                        });
                    } else {
                        res.json({ message: 'Password reset successfully. Please log in with your new password.' });
                    }
                });
            });
        } catch (err) {
            console.error('Error hashing password:', err);
            res.status(500).json({ message: 'Error hashing password' });
        }
    });
});


// Add category
app.post('/add-category', isAdmin, (req, res) => {

    const { name } = req.body;
    const sanitizedName = sanitizeInput(name);
    if (!sanitizedName || sanitizedName.length > 255) {
        return res.status(400).send('Invalid category name');
    }
    connection.query('INSERT INTO categories (name) VALUES (?)', [name], (err) => {
        if (err) {
            console.error('Query Error:', err);
            return res.status(500).send('Database error: ' + err.message);
        }
        res.redirect('/admin');
    });
});

// Edit category
app.post('/edit-category/:catid', isAdmin, (req, res) => {
    const { name } = req.body;
    const catid = sanitizeInput(req.params.catid);
    const sanitizedName = sanitizeInput(name);
    if (!validateInteger(catid) || !sanitizedName || sanitizedName.length > 255) {
        return res.status(400).send('Invalid category ID or name');
    }
    connection.query('UPDATE categories SET name = ? WHERE catid = ?', [name, catid], (err) => {
        if (err) {
            console.error('Query Error:', err);
            return res.status(500).send('Database error: ' + err.message);
        }
        res.redirect('/admin');
    });
});

// Delete category
app.post('/delete-category/:catid', isAdmin, (req, res) => {
    const catid = sanitizeInput(req.params.catid);
    if (!validateInteger(catid)) {
        return res.status(400).send('Invalid category ID');
    }
    connection.query('DELETE FROM categories WHERE catid = ?', [catid], (err) => {
        if (err) {
            console.error('Query Error:', err);
            return res.status(500).send('Database error: ' + err.message);
        }
        res.redirect('/admin');
    });
});


// Add product with image resizing
app.post('/add-product', isAdmin, csrfProtection, async (req, res) => {
    console.log('POST /add-product - req.body:', req.body);
    console.log('POST /add-product - req.files:', req.files);
    console.log('POST /add-product - Session CSRF token:', req.session.csrfToken);
    console.log('POST /add-product - CSRF token from body:', req.body._csrf);
    console.log('POST /add-product - CSRF token match:', req.session.csrfToken === req.body._csrf);

    const { name, price, description, author, publisher, catid } = req.body;
    const sanitizedName = sanitizeInput(name);
    const sanitizedPrice = sanitizeInput(price);
    const sanitizedDesc = sanitizeInput(description);
    const sanitizedAuthor = sanitizeInput(author);
    const sanitizedPublisher = sanitizeInput(publisher);
    const sanitizedCatid = sanitizeInput(catid);

    if (!sanitizedName || sanitizedName.length > 255 ||
        !validateNumber(sanitizedPrice) || Number(sanitizedPrice) > 10000 ||
        (sanitizedDesc && sanitizedDesc.length > 1000) ||
        !sanitizedAuthor || sanitizedAuthor.length > 255 ||
        !sanitizedPublisher || sanitizedPublisher.length > 255 ||
        !validateInteger(sanitizedCatid)) {
        return res.status(400).send('Invalid product data');
    }

    // Check if an image was uploaded
    if (!req.files || !req.files.image) {
        return res.status(400).send('Error: Image is required');
    }

    const imageFile = req.files.image;
    const filetypes = /jpeg|jpg|gif|png/;
    const extname = filetypes.test(path.extname(imageFile.name).toLowerCase());
    const mimetype = filetypes.test(imageFile.mimetype);
    if (!extname || !mimetype) {
        return res.status(400).send('Only JPG, GIF, or PNG files are allowed');
    }

    // Generate new filenames for resized and thumbnail images
    const timestamp = Date.now();
    const originalPath = path.join(__dirname, 'uploads', `${timestamp}-${imageFile.name}`);
    const resizedPath = path.join(__dirname, 'uploads', `resized-${timestamp}-${imageFile.name}`);
    const thumbPath = path.join(__dirname, 'uploads', `thumb-${timestamp}-${imageFile.name}`);

    try {
        // Save the file to disk using the Buffer from req.files.image.data
        await fs.promises.writeFile(originalPath, imageFile.data);

        // Resize the image using sharp
        await sharp(originalPath)
            .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
            .toFile(resizedPath);
        await sharp(originalPath)
            .resize(150, 150, { fit: 'cover' })
            .toFile(thumbPath);

        const image = `/uploads/resized-${timestamp}-${imageFile.name}`;
        const sql = 'INSERT INTO products (name, price, description, author, publisher, image, catid) VALUES (?, ?, ?, ?, ?, ?, ?)';
        connection.query(sql, [sanitizedName, sanitizedPrice, sanitizedDesc, sanitizedAuthor, sanitizedPublisher, image, sanitizedCatid], (err) => {
            if (err) {
                console.error('Query Error:', err);
                return res.status(500).send('Database error: ' + err.message);
            }
            res.redirect('/admin');
        });
    } catch (error) {
        console.error('Image processing error:', error);
        return res.status(500).send('Error processing image: ' + error.message);
    }
});

// Edit product
app.post('/edit-product/:pid', isAdmin, csrfProtection, async (req, res) => {

    const pid = sanitizeInput(req.params.pid);
    const { name, price, description, author, publisher, catid } = req.body;
    const sanitizedName = sanitizeInput(name);
    const sanitizedPrice = sanitizeInput(price);
    const sanitizedDesc = sanitizeInput(description);
    const sanitizedAuthor = sanitizeInput(author);
    const sanitizedPublisher = sanitizeInput(publisher);
    const sanitizedCatid = sanitizeInput(catid);

    if (!validateInteger(pid) ||
        !sanitizedName || sanitizedName.length > 255 ||
        !validateNumber(sanitizedPrice) || Number(sanitizedPrice) > 10000 ||
        (sanitizedDesc && sanitizedDesc.length > 1000) ||
        !sanitizedAuthor || sanitizedAuthor.length > 255 ||
        !sanitizedPublisher || sanitizedPublisher.length > 255 ||
        !validateInteger(sanitizedCatid)) {
        return res.status(400).send('Invalid product data');
    }

    let sql = 'UPDATE products SET name = ?, price = ?, description = ?, author = ?, publisher = ?, catid = ?';
    let values = [sanitizedName, sanitizedPrice, sanitizedDesc, sanitizedAuthor, sanitizedPublisher, sanitizedCatid];

    if (req.files && req.files.image) {
        const imageFile = req.files.image;
        const filetypes = /jpeg|jpg|gif|png/;
        const extname = filetypes.test(path.extname(imageFile.name).toLowerCase());
        const mimetype = filetypes.test(imageFile.mimetype);
        if (!extname || !mimetype) {
            return res.status(400).send('Only JPG, GIF, or PNG files are allowed');
        }

        const timestamp = Date.now();
        const originalPath = path.join(__dirname, 'uploads', `${timestamp}-${imageFile.name}`);
        const resizedPath = path.join(__dirname, 'uploads', `resized-${timestamp}-${imageFile.name}`);
        const thumbPath = path.join(__dirname, 'uploads', `thumb-${timestamp}-${imageFile.name}`);

        try {
            // Save the file to disk using the Buffer from req.files.image.data
            await fs.promises.writeFile(originalPath, imageFile.data);

            // Resize the image using sharp
            await sharp(originalPath)
                .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
                .toFile(resizedPath);
            await sharp(originalPath)
                .resize(150, 150, { fit: 'cover' })
                .toFile(thumbPath);

            sql += ', image = ?';
            values.push(`/uploads/resized-${timestamp}-${imageFile.name}`);
        } catch (error) {
            console.error('Image processing error:', error);
            return res.status(500).send('Error processing image: ' + error.message);
        }
    }

    sql += ' WHERE pid = ?';
    values.push(pid);
    connection.query(sql, values, (err) => {
        if (err) {
            console.error('Query Error:', err);
            return res.status(500).send('Database error: ' + err.message);
        }
        res.redirect('/admin');
    });
});

// Delete product
app.post('/delete-product/:pid', isAdmin, (req, res) => {
    const pid = sanitizeInput(req.params.pid);
    if (!validateInteger(pid)) {
        return res.status(400).send('Invalid product ID');
    }
    connection.query('DELETE FROM products WHERE pid = ?', [pid], (err) => {
        if (err) {
            console.error('Query Error:', err);
            return res.status(500).send('Database error: ' + err.message);
        }
        res.redirect('/admin');
    });
});

try {
    const server = https.createServer({
        key: fs.readFileSync('privkey.pem'),
        cert: fs.readFileSync('fullchain.pem')
    }, app);

    server.listen(3000, () => {
        console.log('Server running on HTTPS port 3000');
    });

    server.on('error', (err) => {
        console.error('HTTPS Server Error:', err);
    });
} catch (err) {
    console.error('Failed to start HTTPS server:', err);
    process.exit(1);
}
function generateAdminPage(categories, products, user, ordersWithTransactions) {
    const escapeHtml = (unsafe) => sanitizeHtml(unsafe, { allowedTags: [], allowedAttributes: {} });
    try {
        console.log('Generating admin page for user:', user);
        return `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel</title>
            <link rel="stylesheet" href="/styles.css">
            <style>
                .section { margin: 20px 0; }
                form { margin: 10px 0; }
                .category-item, .product-item { border: 1px solid #ccc; padding: 10px; margin: 5px 0; }
                .error { color: red; }
            </style>
        </head>
        <body>
            <h1>Admin Panel</h1>
            <h2>By Kwan Chun Kit</h2>
            <p>Logged in as: ${escapeHtml(user.username)} | <button id="logout-button">Logout</button></p>

            <div class="section">
                <h2>Manage Orders</h2>
                ${ordersWithTransactions.length === 0 ? '<p>No orders found.</p>' : ordersWithTransactions.map(order => `
                    <div class="order-item">
                        <p><strong>Order ID:</strong> ${escapeHtml(String(order.orderID))}</p>
                        <p><strong>Transaction ID:</strong> ${order.transactionID ? escapeHtml(String(order.transactionID)) : 'N/A'}</p>
                        <p><strong>Username:</strong> ${escapeHtml(order.username)}</p>
                        <p><strong>Cart Items:</strong></p>
                        <div class="product-list">
                            ${order.cartItems.map(item => `
                                <p>
                                    Product ID: ${escapeHtml(String(item.pid))} | 
                                    Quantity: ${escapeHtml(String(item.quantity))} | 
                                    Price: $${escapeHtml(String(item.price.toFixed(2)))}
                                </p>
                            `).join('')}
                        </div>
                        <p><strong>Currency:</strong> ${escapeHtml(order.currency)}</p>
                        <p><strong>Total Price:</strong> $${escapeHtml(String(order.totalPrice.toFixed(2)))}</p>
                        <p><strong>Status:</strong> ${order.status ? escapeHtml(order.status) : 'Pending'}</p>
                        <p><strong>Order Created At:</strong> ${escapeHtml(new Date(order.orderCreatedAt).toLocaleString())}</p>
                        ${order.transactionCreatedAt ? `<p><strong>Transaction Created At:</strong> ${escapeHtml(new Date(order.transactionCreatedAt).toLocaleString())}</p>` : ''}
                    </div>
                `).join('')}
            </div>

            <div class="section">
                <h2>Add Category</h2>
                <form action="/add-category" method="POST" onsubmit="return validateForm(this)">
                    <input type="hidden" name="_csrf" value="${user.csrfToken}">
                    <label>Name: <input type="text" name="name" required maxlength="255" pattern="[^<>"']+"></label><br>
                    <button type="submit">Add Category</button>
                </form>
            </div>

            <div class="section">
                <h2>Manage Categories</h2>
                ${categories.map(cat => `
                    <div class="category-item">
                        <form action="/edit-category/${escapeHtml(String(cat.catid))}" method="POST" onsubmit="return validateForm(this)">
                            <input type="hidden" name="_csrf" value="${user.csrfToken}">    
                            <label>Name: <input type="text" name="name" value="${escapeHtml(cat.name)}" required maxlength="255" pattern="[^<>"']+"></label>
                            <button type="submit">Update</button>
                        </form>
                        <form action="/delete-category/${escapeHtml(String(cat.catid))}" method="POST">
                            <input type="hidden" name="_csrf" value="${user.csrfToken}">
                            <button type="submit">Delete</button>
                        </form>
                    </div>
                `).join('')}
            </div>

            <div class="section">
                <h2>Add Product</h2>
                <form action="/add-product" method="POST" enctype="multipart/form-data" onsubmit="return validateForm(this)">
                    <input type="hidden" name="_csrf" value="${user.csrfToken}">
                    <label>Name: <input type="text" name="name" required maxlength="255" pattern="[^<>"']+"></label><br>
                    <label>Price: <input type="number" name="price" required min="0" max="10000" step="0.01"></label><br>
                    <label>Description: <textarea name="description" maxlength="1000"></textarea></label><br>
                    <label>Author: <input type="text" name="author" required maxlength="255" pattern="[^<>"']+"></label><br>
                    <label>Publisher: <input type="text" name="publisher" required maxlength="255" pattern="[^<>"']+"></label><br>
                    <label>Category: 
                        <select name="catid" required>
                            ${categories.map(cat => `<option value="${escapeHtml(String(cat.catid))}">${escapeHtml(cat.name)}</option>`).join('')}
                        </select>
                    </label><br>
                    <label>Image: <input type="file" name="image" accept=".jpg,.gif,.png" required></label><br>
                    <button type="submit">Add Product</button>
                </form>
            </div>

            <div class="section">
                <h2>Manage Products</h2>
                ${products.map(p => `
                    <div class="product-item">
                        <form action="/edit-product/${escapeHtml(String(p.pid))}" method="POST" enctype="multipart/form-data" onsubmit="return validateForm(this)">
                            <input type="hidden" name="_csrf" value="${user.csrfToken}">
                            <label>Name: <input type="text" name="name" value="${escapeHtml(p.name)}" required maxlength="255" pattern="[^<>"']+"></label>
                            <label>Price: <input type="number" name="price" value="${escapeHtml(String(p.price))}" required min="0" max="10000" step="0.01"></label>
                            <label>Description: <textarea name="description" maxlength="1000">${escapeHtml(p.description || '')}</textarea></label>
                            <label>Author: <input type="text" name="author" value="${escapeHtml(p.author || '')}" required maxlength="255" pattern="[^<>"']+"></label>
                            <label>Publisher: <input type="text" name="publisher" value="${escapeHtml(p.publisher || '')}" required maxlength="255" pattern="[^<>"']+"></label>
                            <label>Category: 
                                <select name="catid" required>
                                    ${categories.map(cat => `<option value="${escapeHtml(String(cat.catid))}" ${cat.catid === p.catid ? 'selected' : ''}>${escapeHtml(cat.name)}</option>`).join('')}
                                </select>
                            </label>
                            <label>Image: <input type="file" name="image" accept=".jpg,.gif,.png"></label>
                            ${p.image ? `<img src="${escapeHtml(p.image.replace('resized-', 'thumb-'))}" width="50">` : 'No image'}
                            <button type="submit">Update</button>
                        </form>
                        <form action="/delete-product/${escapeHtml(String(p.pid))}" method="POST">
                            <input type="hidden" name="_csrf" value="${user.csrfToken}">
                            <button type="submit">Delete</button>
                        </form>
                    </div>
                `).join('')}
            </div>

            <script src="/admin.js"></script>
        </body>
        </html>
        `;
    } catch (err) {
        console.error('Error in generateAdminPage:', err);
        throw err;
    }
}
