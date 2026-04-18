// Copyright (c) 2026 Kantoshi Miyamura
//
//! Simplified SQLite database for local development
//! NO external database required - just a simple file

use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Create or open SQLite database file
    pub fn new(db_path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;

        // Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        // Create tables if they don't exist
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                address TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                reputation_score REAL DEFAULT 1.0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(address) REFERENCES users(address)
            );

            CREATE TABLE IF NOT EXISTS wallets (
                address TEXT PRIMARY KEY,
                seed_phrase TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );"
        )?;

        Ok(Database {
            conn: Mutex::new(conn),
        })
    }

    /// Create a new user account with email and password
    pub fn create_user(
        &self,
        address: &str,
        email: &str,
        password_hash: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO users (address, email, password_hash, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![address, email, password_hash, now, now],
        )?;

        Ok(())
    }

    /// Verify user password
    pub fn verify_password(
        &self,
        email: &str,
        password_hash: &str,
    ) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();

        let address: Option<String> = conn
            .query_row(
                "SELECT address FROM users WHERE email = ? AND password_hash = ?",
                params![email, password_hash],
                |row| row.get(0),
            )
            .optional()?;

        Ok(address)
    }

    /// Save wallet information (seed phrase, private key)
    pub fn save_wallet(
        &self,
        address: &str,
        seed_phrase: &str,
        private_key: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT OR REPLACE INTO wallets (address, seed_phrase, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![address, seed_phrase, private_key, now],
        )?;

        Ok(())
    }

    /// Get wallet information (seed phrase, private key)
    pub fn get_wallet(&self, address: &str) -> anyhow::Result<Option<(String, String)>> {
        let conn = self.conn.lock().unwrap();

        let result: Option<(String, String)> = conn
            .query_row(
                "SELECT seed_phrase, private_key FROM wallets WHERE address = ?",
                params![address],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        Ok(result)
    }

    /// Create session after successful login
    pub fn create_session(
        &self,
        session_id: &str,
        address: &str,
        token_hash: &str,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        conn.execute(
            "INSERT INTO sessions (id, address, token_hash, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session_id, address, token_hash, now, expires_at],
        )?;

        Ok(())
    }

    /// Validate session token
    pub fn get_user_from_session(&self, session_id: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();

        let address: Option<String> = conn
            .query_row(
                "SELECT address FROM sessions WHERE id = ? AND expires_at > ?",
                params![session_id, now],
                |row| row.get(0),
            )
            .optional()?;

        Ok(address)
    }

    /// Get user balance/reputation
    pub fn get_user_balance(&self, address: &str) -> anyhow::Result<f64> {
        let conn = self.conn.lock().unwrap();

        let balance: f64 = conn
            .query_row(
                "SELECT reputation_score FROM users WHERE address = ?",
                params![address],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        Ok(balance)
    }
}
