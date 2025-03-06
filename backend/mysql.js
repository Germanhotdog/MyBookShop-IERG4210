const express = require('express');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const app = express();

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

app.get('/admin', (req, res) => {
    connection.query('SELECT * FROM categories', (err, categories) => {
        if (err) throw err;
        connection.query('SELECT * FROM products', (err, products) => {
            if (err) throw err;
            res.send(generateAdminPage(categories, products));
        });
    });
});

//Product API (and also by catid)
app.get('/api/products', (req, res) => {
    const catid = req.query.catid;
    const sql = catid ? 'SELECT * FROM products WHERE catid = ?' : 'SELECT * FROM products';
    connection.query(sql, [catid], (err, products) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(products);
    });
});

// Fetch product by name
app.get('/api/product/:pid', (req, res) => {
    const productId = req.params.pid;
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
    const catid = req.params.catid;
    connection.query('SELECT * FROM categories WHERE catid = ?', [catid], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(404).json({ error: 'Category not found' });
        res.json(results[0]);
    });
});

// Add category
app.post('/add-category', (req, res) => {
    const { name } = req.body;
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
    const catid = req.params.catid;
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
    const catid = req.params.catid;
    connection.query('DELETE FROM categories WHERE catid = ?', [catid], (err) => {
        if (err) {
            console.error('Query Error:', err);
            return res.status(500).send('Database error: ' + err.message);
        }
        res.redirect('/admin');
    });
});

//Chinese books API
app.get('/api/chinesebooks', (req, res) => {
    connection.query('SELECT * FROM products WHERE catid = 1', (err, products) => {
        if (err) {
            console.error('Query Error:', err);
            res.status(500).json({ error: 'Database error' });
            return;
        }
        res.json(products);
    });
});

//English books API
app.get('/api/englishbooks', (req, res) => {
    connection.query('SELECT * FROM products WHERE catid = 2', (err, products) => {
        if (err) {
            console.error('Query Error:', err);
            res.status(500).json({ error: 'Database error' });
            return;
        }
        res.json(products);
    });
});

//Magazines API
app.get('/api/magazines', (req, res) => {
    connection.query('SELECT * FROM products WHERE catid = 3', (err, products) => {
        if (err) {
            console.error('Query Error:', err);
            res.status(500).json({ error: 'Database error' });
            return;
        }
        res.json(products);
    });
});

app.post('/add-product', (req, res) => {
    upload(req, res, (err) => {
        if (err) {
            res.send(`Error: ${err}`);
            return;
        }
        const { name, price, description, author, publisher, catid } = req.body; 
        const image = req.file ? `/uploads/${req.file.filename}` : null;
        const sql = 'INSERT INTO products (name, price, description, author, publisher, image, catid) VALUES (?, ?, ?, ?, ?, ?, ?)';
        connection.query(sql, [name, price, description, author, publisher, image, catid], (err) => {
            if (err) {
                console.error('Query Error:', err);
                res.send('Database error: ' + err.message);
                return;
            }
            res.redirect('/admin');
        });
    });
});

app.post('/edit-product/:pid', (req, res) => {
    upload(req, res, (err) => {
        if (err) {
            res.send(`Error: ${err}`);
            return;
        }
        const { name, price, description, author, publisher, catid } = req.body; 
        const pid = req.params.pid;
        let sql = 'UPDATE products SET name = ?, price = ?, description = ?, author = ?, publisher = ?, catid = ?';
        let values = [name, price, description, author, publisher, catid];
        if (req.file) {
            sql += ', image = ?';
            values.push(`/uploads/${req.file.filename}`);
        }
        sql += ' WHERE pid = ?';
        values.push(pid);
        connection.query(sql, values, (err) => {
            if (err) {
                console.error('Query Error:', err);
                res.send('Database error: ' + err.message);
                return;
            }
            res.redirect('/admin');
        });
    });
});

app.post('/delete-product/:pid', (req, res) => {
    const pid = req.params.pid;
    connection.query('DELETE FROM products WHERE pid = ?', [pid], (err) => {
        if (err) {
            console.error('Query Error:', err);
            res.send('Database error: ' + err.message);
            return;
        }
        res.redirect('/admin');
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});

function generateAdminPage(categories, products) {
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
        </style>
    </head>
    <body>
        <h1>Admin Panel</h1>

        <div class="section">
            <h2>Add Category</h2>
            <form action="/add-category" method="POST">
                <label>Name: <input type="text" name="name" required></label><br>
                <button type="submit">Add Category</button>
            </form>
        </div>

        <div class="section">
            <h2>Manage Categories</h2>
            ${categories.map(cat => `
                <div class="category-item">
                    <form action="/edit-category/${cat.catid}" method="POST">
                        <label>Name: <input type="text" name="name" value="${cat.name}" required></label>
                        <button type="submit">Update</button>
                    </form>
                    <form action="/delete-category/${cat.catid}" method="POST">
                        <button type="submit">Delete</button>
                    </form>
                </div>
            `).join('')}
        </div>

        <div class="section">
            <h2>Add Product</h2>
            <form action="/add-product" method="POST" enctype="multipart/form-data">
                <label>Name: <input type="text" name="name" required></label><br>
                <label>Price: <input type="number" step="0.01" name="price" required></label><br>
                <label>Description: <textarea name="description"></textarea></label><br>
                <label>Author: <input type="text" name="author" required></label><br>
                <label>Publisher: <input type="text" name="publisher" required></label><br>
                <label>Category: 
                    <select name="catid" required>
                        ${categories.map(cat => `<option value="${cat.catid}">${cat.name}</option>`).join('')}
                    </select>
                </label><br>
                <label>Image: <input type="file" name="image" accept=".jpg,.gif,.png"></label><br>
                <button type="submit">Add Product</button>
            </form>
        </div>

        <div class="section">
            <h2>Manage Products</h2>
            ${products.map(p => `
                <div class="product-item">
                    <form action="/edit-product/${p.pid}" method="POST" enctype="multipart/form-data">
                        <label>Name: <input type="text" name="name" value="${p.name}" required></label>
                        <label>Price: <input type="number" step="0.01" name="price" value="${p.price}" required></label>
                        <label>Description: <textarea name="description">${p.description || ''}</textarea></label>
                        <label>Author: <input type="text" name="author" value="${p.author || ''}" required></label>
                        <label>Publisher: <input type="text" name="publisher" value="${p.publisher || ''}" required></label>
                        <label>Category: 
                            <select name="catid" required>
                                ${categories.map(cat => `<option value="${cat.catid}" ${cat.catid === p.catid ? 'selected' : ''}>${cat.name}</option>`).join('')}
                            </select>
                        </label>
                        <label>Image: <input type="file" name="image" accept=".jpg,.gif,.png"></label>
                        ${p.image ? `<img src="${p.image}" width="50">` : 'No image'}
                        <button type="submit">Update</button>
                    </form>
                    <form action="/delete-product/${p.pid}" method="POST">
                        <button type="submit">Delete</button>
                    </form>
                </div>
            `).join('')}
        </div>
    </body>
    </html>
    `;
}