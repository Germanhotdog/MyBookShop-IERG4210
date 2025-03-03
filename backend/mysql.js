const express = require('express');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const app = express();

const connection = mysql.createConnection({
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
app.use(express.static('frontend'));
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

//Product API
app.get('/api/products', (req, res) => {
    connection.query('SELECT * FROM products', (err, products) => {
        if (err) {
            console.error('Query Error:', err);
            res.status(500).json({ error: 'Database error' });
            return;
        }
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

////Magazines API
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
    console.log('Server running on http://localhost:3000');
});

function generateAdminPage(categories, products) {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
        <h1>Admin Panel</h1>
        
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

        <h2>Manage Products</h2>
        ${products.map(p => `
            <div>
                <form action="/edit-product/${p.pid}" method="POST" enctype="multipart/form-data">
                    <input type="text" name="name" value="${p.name}" required>
                    <input type="number" step="0.01" name="price" value="${p.price}" required>
                    <textarea name="description">${p.description || ''}</textarea>
                    <input type="text" name="author" value="${p.author || ''}" required>
                    <input type="text" name="publisher" value="${p.publisher || ''}" required>
                    <select name="catid" required>
                        ${categories.map(cat => `<option value="${cat.catid}" ${cat.catid === p.catid ? 'selected' : ''}>${cat.name}</option>`).join('')}
                    </select>
                    <input type="file" name="image" accept=".jpg,.gif,.png">
                    ${p.image ? `<img src="${p.image}" width="50">` : 'No image'}
                    <button type="submit">Update</button>
                </form>
                <form action="/delete-product/${p.pid}" method="POST">
                    <button type="submit">Delete</button>
                </form>
            </div>
        `).join('')}
    </body>
    </html>
    `;
}