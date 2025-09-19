const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require("crypto");
const speakeasy = require('speakeasy');

const dbPath = path.resolve(__dirname, 'database.db');

// Hashing functions
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.createHash("sha3-512").update(salt + password).digest("hex");
  return { salt, hash };
}

function verifyPassword(storedSalt, storedHash, passwordToCheck) {
  const hashToCheck = crypto.createHash("sha3-512").update(storedSalt + passwordToCheck).digest("hex");
  return hashToCheck === storedHash;
}

// Encryption function for 2FA secret
function encryptSecret(secret) {
  const key = crypto.scryptSync("supersecretkey", "salt", 32); // Ensure correct key length
  const iv = Buffer.alloc(16, 0); // 16-byte IV for AES-256-CBC
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(secret, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

// Database operations
const dbinit = () => {
  const db = new sqlite3.Database(dbPath);

  // Create tables with better approach to ensure they exist
  db.serialize(() => {
    // User table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      salt TEXT NOT NULL,
      twoFactorSecret TEXT NOT NULL
    )`);

    // WebAuthn credentials table - Recreating with proper constraints
    db.run(`CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      credentialID TEXT NOT NULL,
      publicKey TEXT NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (username) REFERENCES users(username),
      UNIQUE(username, credentialID)
    )`);
  });

  return db;
};

const authenticate = ({ username, password }) => {
  const db = dbinit();
  return new Promise((resolve, reject) => {
    // Using parameterized query to prevent SQL injection
    const sql = 'SELECT * FROM users WHERE username = ?';

    db.all(sql, [username], (err, rows) => {
      db.close();
      if (err) return reject(err);

      if (rows.length === 0) return resolve([]);

      const user = rows[0];
      if (verifyPassword(user.salt, user.password, password)) {
        resolve([user]);
      } else {
        resolve([]);
      }
    });
  });
};

const signup = ({ username, password, twoFactorSecret }) => {
  const db = dbinit();
  const { salt, hash } = hashPassword(password);
  const encryptedSecret = encryptSecret(twoFactorSecret);

  return new Promise((resolve, reject) => {
    // Using parameterized query to prevent SQL injection
    const sql = 'INSERT INTO users (username, password, salt, twoFactorSecret) VALUES (?, ?, ?, ?)';

    db.run(sql, [username, hash, salt, encryptedSecret], function (err) {
      db.close();
      if (err) return reject(err);
      resolve(true);
    });
  });
};

// WebAuthn specific functions
const getUserByUsername = (username) => {
  const db = dbinit();
  return new Promise((resolve, reject) => {
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.get(sql, [username], (err, row) => {
      if (err) {
        db.close();
        return reject(err);
      }

      // If user doesn't exist, create a new one for passkey-only authentication
      if (!row) {
        const { salt, hash } = hashPassword("passkey-only-" + Math.random()); // Generate a random password
        const twoFactorSecret = speakeasy.generateSecret({ length: 20 }).base32;
        const encryptedSecret = encryptSecret(twoFactorSecret);

        const insertSql = 'INSERT INTO users (username, password, salt, twoFactorSecret) VALUES (?, ?, ?, ?)';
        db.run(insertSql, [username, hash, salt, encryptedSecret], function (err) {
          db.close();
          if (err) return reject(err);

          // Return the newly created user
          resolve({
            id: this.lastID,
            username: username,
            // Don't include password/salt in the result
          });
        });
      } else {
        db.close();
        resolve(row);
      }
    });
  });
};

const saveWebAuthnCredential = ({ username, credentialID, publicKey, counter = 0 }) => {
  const db = dbinit();
  return new Promise((resolve, reject) => {
    // Using REPLACE INTO instead of INSERT to handle duplicates gracefully
    const sql = 'REPLACE INTO webauthn_credentials (username, credentialID, publicKey, counter) VALUES (?, ?, ?, ?)';
    db.run(sql, [username, credentialID, publicKey, counter], function (err) {
      db.close();
      if (err) return reject(err);
      resolve({ id: this.lastID });
    });
  });
};

const getWebAuthnCredential = (username) => {
  const db = dbinit();
  return new Promise((resolve, reject) => {
    const sql = 'SELECT * FROM webauthn_credentials WHERE username = ?';
    db.all(sql, [username], (err, rows) => {
      db.close();
      if (err) return reject(err);
      resolve(rows);
    });
  });
};

const updateWebAuthnCounter = (credentialID, counter) => {
  const db = dbinit();
  return new Promise((resolve, reject) => {
    const sql = 'UPDATE webauthn_credentials SET counter = ? WHERE credentialID = ?';
    db.run(sql, [counter, credentialID], function (err) {
      db.close();
      if (err) return reject(err);
      resolve({ changes: this.changes });
    });
  });
};

module.exports = {
  authenticate,
  signup,
  getUserByUsername,
  saveWebAuthnCredential,
  getWebAuthnCredential,
  updateWebAuthnCounter
};
