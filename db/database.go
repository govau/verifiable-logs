package db

import (
	"errors"
	"sync"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
	"github.com/jackc/pgx"
)

// Return a database object, using the CloudFoundry environment data
func postgresCredsFromCF() (map[string]interface{}, error) {
	appEnv, err := cfenv.Current()
	if err != nil {
		return nil, err
	}

	dbEnv, err := appEnv.Services.WithTag("postgres")
	if err != nil {
		return nil, err
	}

	if len(dbEnv) != 1 {
		return nil, errors.New("expecting 1 database")
	}

	return dbEnv[0].Credentials, nil
}

type DBInitter struct {
	InitSQL            string
	PreparedStatements map[string]string
	OtherStatements    func(*pgx.Conn) error

	// Clearly this won't stop other instances in a race condition, but should at least stop ourselves from hammering ourselves unnecessarily
	runMutex   sync.Mutex
	runAlready bool
}

func (dbi *DBInitter) ensureInitDone(c *pgx.Conn) error {
	dbi.runMutex.Lock()
	defer dbi.runMutex.Unlock()

	if dbi.runAlready {
		return nil
	}

	_, err := c.Exec(dbi.InitSQL)
	if err != nil {
		return err
	}

	dbi.runAlready = true
	return nil
}

func (dbi *DBInitter) AfterConnect(c *pgx.Conn) error {
	if dbi.InitSQL != "" {
		err := dbi.ensureInitDone(c)
		if err != nil {
			return err
		}
	}

	if dbi.OtherStatements != nil {
		err := dbi.OtherStatements(c)
		if err != nil {
			return err
		}
	}

	if dbi.PreparedStatements != nil {
		for n, sql := range dbi.PreparedStatements {
			_, err := c.Prepare(n, sql)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

/*
	# Sample database update commands

    ALTER TABLE cert_store ADD COLUMN IF NOT EXISTS jurisdiction text;
    ALTER TABLE cert_store ADD COLUMN IF NOT EXISTS cdn text;
	ALTER TABLE cert_store ADD COLUMN IF NOT EXISTS discovered timestamptz NOT NULL DEFAULT now();
	ALTER TABLE monitored_logs ADD COLUMN IF NOT EXISTS connect_url text;
*/

func GetPGXPool(maxConns int) (*pgx.ConnPool, error) {
	creds, err := postgresCredsFromCF()
	if err != nil {
		return nil, err
	}

	return pgx.NewConnPool(pgx.ConnPoolConfig{
		MaxConnections: maxConns,
		ConnConfig: pgx.ConnConfig{
			Database: creds["name"].(string),
			User:     creds["username"].(string),
			Password: creds["password"].(string),
			Host:     creds["host"].(string),
			Port:     uint16(creds["port"].(float64)),
		},
		AfterConnect: (&DBInitter{
			InitSQL: `
				CREATE TABLE IF NOT EXISTS key_value (
					id             text                     PRIMARY KEY,
					last_completed timestamp with time zone NOT NULL DEFAULT TIMESTAMP 'EPOCH',
					next_scheduled timestamp with time zone NOT NULL DEFAULT TIMESTAMP 'EPOCH'
				);
				`,
		}).AfterConnect,
	})
}
