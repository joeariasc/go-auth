package db

import (
	"database/sql"
	"errors"
	"log"

	"github.com/joeariasc/go-auth/internal/db/entity"
	_ "github.com/lib/pq"
)

const create string = `
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL, 
    description TEXT NOT NULL,
    fingerprint TEXT NULL,
    secret TEXT NOT NULL
);
`

type Connection struct {
	DB *sql.DB
}

var ErrIDNotFound = errors.New("id not found")
var ErrUsernameNotFound = errors.New("username not found")

func NewConnection(stringConn string) (*Connection, error) {
	db, err := sql.Open("postgres", stringConn)
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
	query := `INSERT INTO users (username, created_at, description, fingerprint, secret) VALUES ($1, $2, $3, $4, $5) RETURNING id`

	var id int

	err := c.DB.QueryRow(query, user.Username, user.CreatedAt, user.Description, user.Fingerprint, user.Secret).Scan(&id)

	if err != nil {
		log.Printf("Unable to execute the query. %v", err)
		return 0, err
	}

	log.Printf("Added %v as %d", user, id)
	return id, nil
}

func (c *Connection) SetFingerprint(username string, fingerprint string) (entity.User, error) {
	user := entity.User{}

	query := `SELECT * FROM users WHERE username=$1`

	row := c.DB.QueryRow(query, username)

	err := row.Scan(&user.Id, &user.Username, &user.CreatedAt, &user.Description, &user.Fingerprint, &user.Secret)

	if errors.Is(err, sql.ErrNoRows) {
		return entity.User{}, ErrUsernameNotFound
	}

	if err != nil {
		return entity.User{}, err
	}

	query = `UPDATE users SET fingerprint=$1 WHERE username=$2`
	_, err = c.DB.Exec(query, fingerprint, user.Username)
	if err != nil {
		return entity.User{}, err
	}
	return user, nil
}

func (c *Connection) GetUser(username string) (*entity.User, error) {
	log.Printf("Getting info for %v", username)

	user := entity.User{}

	query := `SELECT * FROM users WHERE username=$1`

	row := c.DB.QueryRow(query, username)

	err := row.Scan(&user.Id, &user.Username, &user.CreatedAt, &user.Description, &user.Fingerprint, &user.Secret)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUsernameNotFound
	}

	return &user, err
}

func (c *Connection) Retrieve(id int) (*entity.User, error) {
	log.Printf("Getting info for id: %v", id)

	user := entity.User{}

	query := `SELECT * FROM users WHERE id=$1`

	row := c.DB.QueryRow(query, id)

	err := row.Scan(&user.Id, &user.Username, &user.CreatedAt, &user.Description, &user.Fingerprint, &user.Secret)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUsernameNotFound
	}

	return &user, err
}
