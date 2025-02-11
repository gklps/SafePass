package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// User data structure for wallet management
type User struct {
	DID        string // IPFS hash (simulated)
	PublicKey  *secp256k1.PublicKey
	PrivateKey string
	// ChildPath int
	Mnemonic string
	Port     int
}

// sqlite database: manages tables for user data and jwt tokens
var db *sql.DB

// EnsureTableColumns ensures the required columns exist in the given table
func EnsureTableColumns(tableName string, requiredColumns map[string]string) error {
	query := fmt.Sprintf("PRAGMA table_info(%s);", tableName)
	rows, err := db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to get table info for %s: %v", tableName, err)
	}
	defer rows.Close()

	existingColumns := make(map[string]bool)
	var name, columnType string
	var cid, notnull, pk int
	var dfltValue sql.NullString

	for rows.Next() {
		if err := rows.Scan(&cid, &name, &columnType, &notnull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("error scanning table info for %s: %v", tableName, err)
		}
		existingColumns[name] = true
	}

	for column, colType := range requiredColumns {
		if !existingColumns[column] {
			alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s;", tableName, column, colType)
			_, err := db.Exec(alterQuery)
			if err != nil {
				return fmt.Errorf("failed to add column %s to table %s: %v", column, tableName, err)
			}
			log.Printf("Added missing column %s to table %s", column, tableName)
		}
	}
	return nil
}

// GenerateSecretKey generates a random base64-encoded secret key
func GenerateSecretKey() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// UpdateWalletUsersSecretKeys ensures all walletUsers have a secret_key
func UpdateWalletUsersSecretKeys() error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %v", err)
	}
	rows, err := tx.Query("SELECT id FROM walletUsers WHERE secret_key IS NULL OR secret_key = ''")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to fetch walletUsers without secret_key: %v", err)
	}
	defer rows.Close()

	stmt, err := tx.Prepare("UPDATE walletUsers SET secret_key = ? WHERE id = ?")
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to prepare update statement: %v", err)
	}
	defer stmt.Close()

	var id int
	for rows.Next() {
		if err := rows.Scan(&id); err != nil {
			tx.Rollback()
			return fmt.Errorf("error scanning walletUsers: %v", err)
		}
		secretKey, err := GenerateSecretKey()
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to generate secret key: %v", err)
		}
		_, err = tx.Exec("UPDATE walletUsers SET secret_key = ? WHERE id = ?", secretKey, id)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to update secret_key for walletUser %d: %v", id, err)
		}
		log.Printf("Updated secret_key for walletUser %d", id)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

// initiate database
func InitDatabase() (*sql.DB, error) {
	var err error
	db, err = sql.Open("sqlite3", "./wallet.db?_journal_mode=WAL&cache_size=-200000&temp_store=MEMORY&locking_mode=EXCLUSIVE")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Create tables if they do not exist
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT UNIQUE NOT NULL,
		public_key BLOB NOT NULL,
		private_key BLOB NOT NULL,
		mnemonic TEXT NOT NULL,
		port INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS jwt_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT NOT NULL,
		token TEXT NOT NULL,
		issued_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		FOREIGN KEY (did) REFERENCES users(did)
	);

	CREATE TABLE IF NOT EXISTS walletUsers (
    id INTEGER PRIMARY KEY,
    email TEXT,
    password TEXT,
	secret_key TEXT,
    name TEXT,
    did TEXT
	)


	`)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	err = EnsureTableColumns("walletUsers", map[string]string{
		"secret_key": "TEXT",
	})
	if err != nil {
		log.Fatal("Failed to ensure walletUsers columns:", err)
	}

	// Update missing secret_keys
	err = UpdateWalletUsersSecretKeys()
	if err != nil {
		log.Fatal("Failed to update walletUsers secret keys:", err)
	}
	// Optimize database performance
	db.Exec("PRAGMA analyze;")
	db.Exec("PRAGMA vacuum;")
	return db, nil
}

// insert user data
func InsertUser(did, publicKey, privateKey, mnemonic string, port int) error {
	if db == nil {
		log.Println("Database connection is nil")
	}

	query := `INSERT INTO users (did, public_key, private_key, mnemonic, port) VALUES (?, ?, ?, ?, ?)`
	_, err := db.Exec(query, did, publicKey, privateKey, mnemonic, port)
	return err
}

// fetch user data from user DID
func GetUserByDID(did string) (*User, error) {
	if db == nil {
		log.Println("Database connection is nil")
	}

	query := `SELECT public_key, private_key, mnemonic, port FROM users WHERE did = ?`
	row := db.QueryRow(query, did)

	var publicKey, privateKey, mnemonic string
	var port int
	err := row.Scan(&publicKey, &privateKey, &mnemonic, &port)
	if err != nil {
		return nil, err
	}

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}

	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	return &User{
		DID:        did,
		PublicKey:  pubKey,
		PrivateKey: privateKey,
		Mnemonic:   mnemonic,
		Port:       port,
	}, nil
}
