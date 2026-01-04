package pgx

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lborres/kuta"
)

func (a *Adapter) CreateAccount(acc *kuta.Account) error {
	ctx := context.Background()

	query := `INSERT INTO public.accounts (id, user_id, provider_id, account_id, password, access_token, refresh_token, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	          RETURNING created_at, updated_at`

	var createdAt, updatedAt time.Time
	err := a.pool.QueryRow(ctx, query,
		acc.ID, acc.UserID, acc.ProviderID, acc.AccountID, acc.Password, acc.AccessToken, acc.RefreshToken, acc.ExpiresAt,
	).Scan(&createdAt, &updatedAt)

	if err != nil {
		return err
	}

	acc.CreatedAt = createdAt
	acc.UpdatedAt = updatedAt
	return nil
}

func (a *Adapter) GetAccountByID(id string) (*kuta.Account, error) {
	ctx := context.Background()
	query := `SELECT id, user_id, provider_id, account_id, password, access_token, refresh_token, expires_at, created_at, updated_at
	          FROM public.accounts WHERE id = $1`

	acc := &kuta.Account{}
	err := a.pool.QueryRow(ctx, query, id).Scan(
		&acc.ID, &acc.UserID, &acc.ProviderID, &acc.AccountID, &acc.Password, &acc.AccessToken, &acc.RefreshToken, &acc.ExpiresAt, &acc.CreatedAt, &acc.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, kuta.ErrUserNotFound
		}
		return nil, err
	}

	return acc, nil
}

func (a *Adapter) GetAccountByUserAndProvider(userID, providerID string) ([]*kuta.Account, error) {
	ctx := context.Background()
	query := `SELECT id, user_id, provider_id, account_id, password, access_token, refresh_token, expires_at, created_at, updated_at
	          FROM public.accounts WHERE user_id = $1 AND provider_id = $2`

	rows, err := a.pool.Query(ctx, query, userID, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*kuta.Account
	for rows.Next() {
		acc := &kuta.Account{}
		err := rows.Scan(
			&acc.ID, &acc.UserID, &acc.ProviderID, &acc.AccountID, &acc.Password, &acc.AccessToken, &acc.RefreshToken, &acc.ExpiresAt, &acc.CreatedAt, &acc.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return accounts, nil
}

func (a *Adapter) UpdateAccount(acc *kuta.Account) error {
	ctx := context.Background()
	query := `UPDATE public.accounts SET account_id = $1, password = $2, access_token = $3, refresh_token = $4, expires_at = $5, updated_at = now()
	          WHERE id = $6 RETURNING updated_at`

	var updatedAt time.Time
	err := a.pool.QueryRow(ctx, query,
		acc.AccountID, acc.Password, acc.AccessToken, acc.RefreshToken, acc.ExpiresAt, acc.ID,
	).Scan(&updatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return kuta.ErrUserNotFound
		}
		return err
	}

	acc.UpdatedAt = updatedAt
	return nil
}

func (a *Adapter) DeleteAccount(id string) error {
	ctx := context.Background()
	_, err := a.pool.Exec(ctx, `DELETE FROM public.accounts WHERE id = $1`, id)
	if err != nil {
		return err
	}
	return nil
}
