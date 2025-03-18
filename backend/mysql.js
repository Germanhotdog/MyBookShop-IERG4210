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

app.use(cors());
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
    connection.query('SELECT * FROM categories', (err, categories) => {
        if (err) throw err;
        connection.query('SELECT * FROM products', (err, products) => {
            if (err) throw err;
            res.send(generateAdminPage(categories, products));
        });
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

// Add category
app.post('/add-category', (req, res) => {
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
app.post('/edit-category/:catid', (req, res) => {
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
app.post('/delete-category/:catid', (req, res) => {
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
app.post('/add-product', async (req, res) => {
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
app.post('/edit-product/:pid', async (req, res) => {
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
app.post('/delete-product/:pid', (req, res) => {
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

// Updated generateAdminPage with client-side restrictions and output sanitization
function generateAdminPage(categories, products) {
    const escapeHtml = (unsafe) => sanitizeHtml(unsafe, { allowedTags: [], allowedAttributes: {} });
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
        </script>
    </head>
    <body>
        <h1>Admin Panel</h1>

        <div class="section">
            <h2>Add Category</h2>
            <form action="/add-category" method="POST" onsubmit="return validateForm(this)">
                <label>Name: <input type="text" name="name" required maxlength="255" pattern="[^<>&quot;']+"></label><br>
                <button type="submit">Add Category</button>
            </form>
        </div>

        <div class="section">
            <h2>Manage Categories</h2>
            ${categories.map(cat => `
                <div class="category-item">
                    <form action="/edit-category/${escapeHtml(String(cat.catid))}" method="POST" onsubmit="return validateForm(this)">
                        <label>Name: <input type="text" name="name" value="${escapeHtml(cat.name)}" required maxlength="255" pattern="[^<>&quot;']+"></label>
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
                <label>Name: <input type="text" name="name" required maxlength="255" pattern="[^<>&quot;']+"></label><br>
                <label>Price: <input type="number" name="price" required min="0" max="10000" step="0.01"></label><br>
                <label>Description: <textarea name="description" maxlength="1000"></textarea></label><br>
                <label>Author: <input type="text" name="author" required maxlength="255" pattern="[^<>&quot;']+"></label><br>
                <label>Publisher: <input type="text" name="publisher" required maxlength="255" pattern="[^<>&quot;']+"></label><br>
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
                        <label>Name: <input type="text" name="name" value="${escapeHtml(p.name)}" required maxlength="255" pattern="[^<>&quot;']+"></label>
                        <label>Price: <input type="number" name="price" value="${escapeHtml(String(p.price))}" required min="0" max="10000" step="0.01"></label>
                        <label>Description: <textarea name="description" maxlength="1000">${escapeHtml(p.description || '')}</textarea></label>
                        <label>Author: <input type="text" name="author" value="${escapeHtml(p.author || '')}" required maxlength="255" pattern="[^<>&quot;']+"></label>
                        <label>Publisher: <input type="text" name="publisher" value="${escapeHtml(p.publisher || '')}" required maxlength="255" pattern="[^<>&quot;']+"></label>
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
}