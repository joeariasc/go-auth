package db

import (
	"database/sql"
	"errors"
	"github.com/joeariasc/go-auth/internal/db/entity"
	"log"
	// needed for SQLite driver
	_ "github.com/mattn/go-sqlite3"
)

const create string = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL,
    description TEXT NOT NULL,
    fingerprint TEXT NULLABLE,
    secret TEXT NOT NULL
);
`

const defaultFile string = "users.sqlite"

type Connection struct {
	DB *sql.DB
}

var ErrIDNotFound = errors.New("id not found")
var ErrUsernameNotFound = errors.New("username not found")

func NewConnection() (*Connection, error) {
	db, err := sql.Open("sqlite3", defaultFile)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(create); err != nil {
		return nil, err
	}
	return &Connection{
		DB: db,
	}, nil
}

func (c *Connection) Insert(user *entity.User) (int, error) {
	query := `INSERT INTO users (username, created_at, description, fingerprint, secret) VALUES (?, ?, ?, ?, ?)`

	res, err := c.DB.Exec(
		query,
		user.Username, user.CreatedAt, user.Description, user.Fingerprint, user.Secret)
	if err != nil {
		return 0, err
	}

	var id int64
	if id, err = res.LastInsertId(); err != nil {
		return 0, err
	}
	log.Printf("Added %v as %d", user, id)
	return int(id), nil
}

func (c *Connection) SetFingerprint(username string, fingerprint string) error {
	log.Printf("Getting info for %v", username)

	row := c.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username=?", username)

	var count int

	if err := row.Scan(&count); err != nil {
		return err
	}

	if count == 0 {
		return ErrIDNotFound
	}

	query := `UPDATE users SET fingerprint=? WHERE username=?`

	_, err := c.DB.Exec(query, fingerprint, username)
	return err
}

func (c *Connection) GetUser(username string) (*entity.User, error) {
	log.Printf("Getting info for %v", username)

	query := `SELECT * FROM users WHERE username=?`

	row := c.DB.QueryRow(query, username)

	// Parse row into Interval struct
	user := entity.User{}

	//var createdAt time.Time
	if err := row.Scan(&user.Id, &user.Username, &user.CreatedAt, &user.Description, &user.Fingerprint, &user.Secret); errors.Is(err, sql.ErrNoRows) {
		return &entity.User{}, ErrUsernameNotFound
	}
	return &user, nil
}

func (c *Connection) Retrieve(id int) (*entity.User, error) {
	log.Printf("Getting %d", id)

	// Query DB row based on ID
	row := c.DB.QueryRow("SELECT id, username created_at FROM users WHERE id=?", id)

	// Parse row into Interval struct
	user := entity.User{}

	//var createdAt time.Time
	if err := row.Scan(&user.Id, &user.Username, &user.CreatedAt, &user.Description, &user.Fingerprint, &user.Secret); errors.Is(err, sql.ErrNoRows) {
		log.Printf("Id not found")
		return &entity.User{}, ErrIDNotFound
	}
	return &user, nil
}

func (c *Connection) List(offset int) ([]*entity.User, error) {
	log.Printf("Getting list from offset %d\n", offset)

	// Query DB row based on ID
	rows, err := c.DB.Query("SELECT * FROM users WHERE ID > ? ORDER BY id DESC LIMIT 100", offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []*entity.User
	for rows.Next() {
		u := entity.User{}
		err = rows.Scan(&u.Id, &u.Username, &u.CreatedAt, &u.Description, &u.Fingerprint, &u.Secret)
		if err != nil {
			return nil, err
		}
		data = append(data, &u)
	}
	return data, nil
}
