package pgx

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lborres/kuta"
)

type Adapter struct {
	pool *pgxpool.Pool
}

var _ kuta.AuthStorage = (*Adapter)(nil)

func New(pool *pgxpool.Pool) *Adapter {
	return &Adapter{
		pool: pool,
	}
}
