package db

import (
	"time"

	"bytes"
	"encoding/gob"

	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/bbolt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var (
	bucket = []byte("users")
)

type Client struct {
	db     *bolt.DB
	logger *logrus.Entry
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Dir      string `json:"dir"`
}

type DB interface {
	GetUser(userName string) (*User, error)
	PutUser(user *User) error
}

func NewClient(path string, log *logrus.Logger) (*Client, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Error opening boltdb")
	}

	return &Client{
		db:     db,
		logger: log.WithField("package", "db"),
	}, nil
}

func (c *Client) GetUser(userName string) (*User, error) {
	logger := c.logger.WithFields(logrus.Fields{"function": "GetUser", "userName": userName})
	logger.Info("Looking up user")
	var u *User
	err := c.db.View(func(tx *bolt.Tx) error {
		var err error
		b := tx.Bucket(bucket)
		if b == nil {
			return fmt.Errorf("no users")
		}
		k := []byte(userName)
		u, err = Decode(b.Get(k))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "Error getting user")
	}
	return u, nil
}

func (c *Client) PutUser(user *User) error {
	logger := c.logger.WithFields(logrus.Fields{"function": "PutUser", "userName": user.Username, "dir": user.Dir})
	logger.Info("Saving user")
	// Set the password to the hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "Error hashing password")
	}
	user.Password = string(hashedPassword[:])
	// Update the record
	err = c.db.Update(func(tx *bolt.Tx) error {
		users, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return errors.Wrap(err, "error creating bucket")
		}
		enc, err := user.Encode()
		if err != nil {
			return err
		}
		return users.Put([]byte(user.Username), enc)
	})
	if err != nil {
		return errors.Wrap(err, "error saving user")
	}
	return nil
}

func (c *Client) DeleteUser(userName string) error {
	logger := c.logger.WithFields(logrus.Fields{"function": "DeleteUser", "userName": userName})
	logger.Info("Saving user")
	err := c.db.Update(func(tx *bolt.Tx) error {
		users := tx.Bucket(bucket)
		return users.Delete([]byte(userName))
	})
	if err != nil {
		return errors.Wrap(err, "Error deleting user")
	}
	return nil
}

func (c *Client) GetUsers() ([]*User, error) {
	logger := c.logger.WithField("function", "GetUsers")
	logger.Info("Getting user list")
	users := make([]*User, 0)
	err := c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			user, err := Decode(v)
			if err != nil {
				return errors.Wrap(err, "Error decoding user")
			}
			users = append(users, user)
		}
		return nil
	})
	return users, err
}

func (p *User) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(p); err != nil {
		return nil, errors.Wrap(err, "Error encoding user")
	}
	return buf.Bytes(), nil
}

func Decode(user []byte) (*User, error) {
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	u := &User{}
	buf := bytes.NewBuffer(user)
	if err := gob.NewDecoder(buf).Decode(u); err != nil {
		return nil, errors.Wrap(err, "Error decoding user")
	}
	return u, nil
}
