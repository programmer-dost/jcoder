import db from "../db";

/**
 * Initialize refresh tokens table
 */
export function initializeRefreshTokensTable(): void {
  try {
    // Create refresh_tokens table if it doesn't exist
    db.exec(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `);

    // Create index for faster lookups
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash 
      ON refresh_tokens (token_hash)
    `);

    // Create index for cleanup operations
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires 
      ON refresh_tokens (expires_at)
    `);

    // Create index for user-based operations
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user 
      ON refresh_tokens (user_id)
    `);

    console.log("Refresh tokens table initialized successfully");
  } catch (error) {
    console.error("Error initializing refresh tokens table:", error);
    throw error;
  }
}

/**
 * Check if refresh tokens table exists
 */
export function checkRefreshTokensTable(): boolean {
  try {
    const result = db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name='refresh_tokens'
    `).get();

    return !!result;
  } catch (error) {
    console.error("Error checking refresh tokens table:", error);
    return false;
  }
}