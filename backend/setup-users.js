const mysql = require('mysql');
const bcrypt = require('bcrypt');

// MySQL connection
const connection = mysql.createConnection({
    host: '54.165.208.37',
    user: 'test',
    password: 'test',
    database: 'MYBOOKSHOP'
});

connection.connect(err => {
    if (err) {
        console.error('MySQL connection failed:', err);
        process.exit(1);
    }
    console.log('Connected to MySQL');
});

// Function to hash a password
const hashPassword = async (password) => {
    const saltRounds = 10; // Number of salt rounds (higher = more secure but slower)
    try {
        const salt = await bcrypt.genSalt(saltRounds);
        const hash = await bcrypt.hash(password, salt);
        return hash;
    } catch (err) {
        throw new Error('Error hashing password: ' + err.message);
    }
};

// Function to insert a user
const insertUser = async (username, email, password, isAdmin) => {
    try {
        const hashedPassword = await hashPassword(password);
        const sql = 'INSERT INTO user (username, email, password, is_admin) VALUES (?, ?, ?, ?)';
        connection.query(sql, [username, email, hashedPassword, isAdmin], (err, result) => {
            if (err) {
                console.error('Error inserting user:', err);
                return;
            }
            console.log(`Inserted user: ${username} (Admin: ${isAdmin})`);
        });
    } catch (err) {
        console.error(err.message);
    }
};

// Insert users
const setupUsers = async () => {
    try {
        // Admin user
        await insertUser('admin', 'admin@example.com', 'test_admin', true);
        // Normal user
        await insertUser('user1', 'user@example.com', 'test', false);
    } catch (err) {
        console.error('Error setting up users:', err);
    } finally {
        connection.end(() => {
            console.log('MySQL connection closed');
        });
    }
};

// Run the setup
setupUsers();