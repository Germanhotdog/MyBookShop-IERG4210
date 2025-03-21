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

const connection = mysql.createConnection({
    //if mysql.js is now in EC2, change to 'localhost'
    host: '54.165.208.37',
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
}).single('image');

//if mysql.js is now in EC2, change to 'localhost'
const MySQLStore = require('express-mysql-session')(session);
const sessionStore = new MySQLStore({
    //if mysql.js is now in EC2, change to 'localhost'
    host: '54.165.208.37',
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
app.use(cors({
    origin: 'https://s13.ierg4210.ie.cuhk.edu.hk', // Allow requests from this origin
    credentials: true // Allow cookies to be sent
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(helmet()); // Adds security headers including CSP

// Custom CSP configuration
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        }
    })
);

// Input validation and sanitization functions
const sanitizeInput = (input) => sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} });
const validateNumber = (input) => !isNaN(input) && Number(input) >= 0;
const validateInteger = (input) => Number.isInteger(Number(input)) && Number(input) >= 0;

app.get('/admin', (req, res) => {
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
    connection.query('SELECT * FROM categories', (err, categories) => {
        if (err) throw err;
        connection.query('SELECT * FROM products', (err, products) => {
            if (err) throw err;
            res.send(generateAdminPage(categories, products,req.session.user));
        });
    });
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

// Login route (AJAX) rateLimit with 15 minutes, Limit to 5 requests per window
app.post('/login',rateLimit({windowMs: 15 * 60 * 1000, max: 5 }), async (req, res) => {
    const { email, password } = req.body;
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

// Login page
app.get('/login', (req, res) => {
    res.send(`
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
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit">Login</button>
                </form>
                <p id="error-message" style="color: red; display: none;"></p>
            </div>

            <script src="/login.js"></script>
        </body>
        </html>
    `);
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
app.post('/add-product', isAdmin, async (req, res) => {
    upload(req, res, async (err) => {
        if (err) {
            return res.send(`Error: ${err}`);
        }
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

        if (!req.file) {
            return res.send('Error: Image is required');
        }

        const originalPath = path.join(__dirname, 'uploads', req.file.filename);
        const resizedPath = path.join(__dirname, 'uploads', `resized-${req.file.filename}`);
        const thumbPath = path.join(__dirname, 'uploads', `thumb-${req.file.filename}`);

        try {
            await sharp(originalPath)
                .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
                .toFile(resizedPath);
            await sharp(originalPath)
                .resize(150, 150, { fit: 'cover' })
                .toFile(thumbPath);

            const image = `/uploads/resized-${req.file.filename}`;
            const sql = 'INSERT INTO products (name, price, description, author, publisher, image, catid) VALUES (?, ?, ?, ?, ?, ?, ?)';
            connection.query(sql, [sanitizedName, sanitizedPrice, sanitizedDesc, sanitizedAuthor, sanitizedPublisher, image, sanitizedCatid], (err) => {
                if (err) {
                    console.error('Query Error:', err);
                    return res.send('Database error: ' + err.message);
                }
                res.redirect('/admin');
            });
        } catch (error) {
            console.error('Image processing error:', error);
            res.send('Error processing image: ' + error.message);
        }
    });
});

// Edit product
app.post('/edit-product/:pid', isAdmin, async (req, res) => {
    upload(req, res, async (err) => {
        if (err) {
            return res.send(`Error: ${err}`);
        }
        const { name, price, description, author, publisher, catid } = req.body;
        const pid = sanitizeInput(req.params.pid);
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

        if (req.file) {
            const originalPath = path.join(__dirname, 'uploads', req.file.filename);
            const resizedPath = path.join(__dirname, 'uploads', `resized-${req.file.filename}`);
            const thumbPath = path.join(__dirname, 'uploads', `thumb-${req.file.filename}`);

            try {
                await sharp(originalPath)
                    .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
                    .toFile(resizedPath);
                await sharp(originalPath)
                    .resize(150, 150, { fit: 'cover' })
                    .toFile(thumbPath);

                sql += ', image = ?';
                values.push(`/uploads/resized-${req.file.filename}`);
            } catch (error) {
                console.error('Image processing error:', error);
                return res.send('Error processing image: ' + error.message);
            }
        }

        sql += ' WHERE pid = ?';
        values.push(pid);
        connection.query(sql, values, (err) => {
            if (err) {
                console.error('Query Error:', err);
                return res.send('Database error: ' + err.message);
            }
            res.redirect('/admin');
        });
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

function generateAdminPage(categories, products, user) {
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
            <script>
                function validateForm(form) {
                    const inputs = form.querySelectorAll('input, textarea, select');
                    for (let input of inputs) {
                        if (input.name === 'name' || input.name === 'author' || input.name === 'publisher') {
                            if (!input.value || input.value.length > 255 || /[<>&"']/.test(input.value)) {
                                alert('Text fields must be non-empty, max 255 chars, no HTML');
                                return false;
                            }
                        }
                        if (input.name === 'price') {
                            const val = parseFloat(input.value);
                            if (isNaN(val) || val < 0 || val > 10000) {
                                alert('Price must be a number between 0 and 10000');
                                return false;
                            }
                        }
                        if (input.name === 'description' && input.value.length > 1000) {
                            alert('Description max 1000 chars');
                            return false;
                        }
                        if (input.name === 'catid' && !/^\d+$/.test(input.value)) {
                            alert('Category must be a valid ID');
                            return false;
                        }
                    }
                    return true;
                }

                function logout() {
                    fetch('/logout', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include'
                    })
                    .then(response => response.json())
                    .then(data => {
                        alert(data.message);
                        window.location.href = '/login';
                    })
                    .catch(err => {
                        console.error('Logout error:', err);
                        alert('Logout failed');
                    });
                }
            </script>
        </head>
        <body>
            <h1>Admin Panel</h1>
            <h2>By Kwan Chun Kit</h2>
            <p>Logged in as: ${escapeHtml(user.username)} | <button onclick="logout()">Logout</button></p>

            <div class="section">
                <h2>Add Category</h2>
                <form action="/add-category" method="POST" onsubmit="return validateForm(this)">
                    <label>Name: <input type="text" name="name" required maxlength="255" pattern="[^<>"']+"></label><br>
                    <button type="submit">Add Category</button>
                </form>
            </div>

            <div class="section">
                <h2>Manage Categories</h2>
                ${categories.map(cat => `
                    <div class="category-item">
                        <form action="/edit-category/${escapeHtml(String(cat.catid))}" method="POST" onsubmit="return validateForm(this)">
                            <label>Name: <input type="text" name="name" value="${escapeHtml(cat.name)}" required maxlength="255" pattern="[^<>"']+"></label>
                            <button type="submit">Update</button>
                        </form>
                        <form action="/delete-category/${escapeHtml(String(cat.catid))}" method="POST">
                            <button type="submit">Delete</button>
                        </form>
                    </div>
                `).join('')}
            </div>

            <div class="section">
                <h2>Add Product</h2>
                <form action="/add-product" method="POST" enctype="multipart/form-data" onsubmit="return validateForm(this)">
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
                            <button type="submit">Delete</button>
                        </form>
                    </div>
                `).join('')}
            </div>
        </body>
        </html>
        `;
    } catch (err) {
        console.error('Error in generateAdminPage:', err);
        throw err; // Re-throw to be caught by the /admin route
    }
}