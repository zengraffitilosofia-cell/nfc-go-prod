require('dotenv').config();
const Database = require('better-sqlite3');
const path = require('path');

const dbPath = process.env.DATABASE_PATH || './nfcgo.db';
const db = new Database(path.resolve(dbPath));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Creación inicial (instalaciones nuevas) ───────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS businesses (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL,
    slug                TEXT    NOT NULL UNIQUE,
    logo_url            TEXT,
    reward_text         TEXT    NOT NULL,
    active              INTEGER NOT NULL DEFAULT 1,
    validator_username  TEXT    UNIQUE,
    validator_password  TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS nfc_tags (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tag_code      TEXT    NOT NULL UNIQUE,
    business_id   INTEGER NOT NULL REFERENCES businesses(id),
    discount_code TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'active'
                          CHECK(status IN ('active','claimed','disabled','redeemed')),
    claimed_at    DATETIME,
    redeemed_at   DATETIME,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_nfc_tags_tag_code ON nfc_tags(tag_code);
  CREATE INDEX IF NOT EXISTS idx_nfc_tags_business  ON nfc_tags(business_id);
`);

// ── Migraciones para bases de datos existentes ────────────────────────────────

// businesses: añadir columnas de credenciales si no existen
const bizCols = db.prepare(`PRAGMA table_info(businesses)`).all().map(c => c.name);
if (!bizCols.includes('validator_username')) {
  db.exec(`ALTER TABLE businesses ADD COLUMN validator_username TEXT UNIQUE`);
}
if (!bizCols.includes('validator_password')) {
  db.exec(`ALTER TABLE businesses ADD COLUMN validator_password TEXT`);
}

// nfc_tags: añadir redeemed_at y actualizar CHECK constraint para incluir 'redeemed'
const tagCols = db.prepare(`PRAGMA table_info(nfc_tags)`).all().map(c => c.name);
if (!tagCols.includes('redeemed_at')) {
  // Recrear la tabla con el nuevo esquema (única forma de modificar CHECK en SQLite)
  db.pragma('foreign_keys = OFF');
  db.exec(`
    DROP TABLE IF EXISTS nfc_tags_migration_tmp;

    CREATE TABLE nfc_tags_migration_tmp (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      tag_code      TEXT    NOT NULL UNIQUE,
      business_id   INTEGER NOT NULL REFERENCES businesses(id),
      discount_code TEXT    NOT NULL,
      status        TEXT    NOT NULL DEFAULT 'active'
                            CHECK(status IN ('active','claimed','disabled','redeemed')),
      claimed_at    DATETIME,
      redeemed_at   DATETIME,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    INSERT INTO nfc_tags_migration_tmp
      (id, tag_code, business_id, discount_code, status, claimed_at, redeemed_at, created_at)
    SELECT id, tag_code, business_id, discount_code, status, claimed_at, NULL, created_at
    FROM nfc_tags;

    DROP TABLE nfc_tags;
    ALTER TABLE nfc_tags_migration_tmp RENAME TO nfc_tags;

    CREATE INDEX IF NOT EXISTS idx_nfc_tags_tag_code ON nfc_tags(tag_code);
    CREATE INDEX IF NOT EXISTS idx_nfc_tags_business  ON nfc_tags(business_id);
  `);
  db.pragma('foreign_keys = ON');
}

module.exports = db;
