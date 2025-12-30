package pgx

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lborres/kuta"
)

func (a *Adapter) CreateUser(user *kuta.User) error {
	ctx := context.Background()

	query := `INSERT INTO public.users (email, email_verified, name, image) VALUES ($1, $2, $3, $4) RETURNING id, created_at, updated_at`
	var id string
	var createdAt, updatedAt time.Time

	err := a.pool.QueryRow(ctx, query, user.Email, user.EmailVerified, user.Name, user.Image).Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		return err
	}

	user.ID = id
	user.CreatedAt = createdAt
	user.UpdatedAt = updatedAt
	return nil
}

func (a *Adapter) GetUserByID(id string) (*kuta.User, error) {
	ctx := context.Background()
	q := `SELECT id, email, email_verified, name, image, created_at, updated_at FROM public.users WHERE id = $1`

	user := &kuta.User{}
	var image *string
	err := a.pool.QueryRow(ctx, q, id).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.Name, &image, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, kuta.ErrUserNotFound
		}
		return nil, err
	}
	user.Image = image
	return user, nil
}

func (a *Adapter) GetUserByEmail(email string) (*kuta.User, error) {
	ctx := context.Background()
	q := `SELECT id, email, email_verified, name, image, created_at, updated_at FROM public.users WHERE email = $1`

	user := &kuta.User{}
	var image *string
	err := a.pool.QueryRow(ctx, q, email).Scan(&user.ID, &user.Email, &user.EmailVerified, &user.Name, &image, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, kuta.ErrUserNotFound
		}
		return nil, err
	}
	user.Image = image
	return user, nil
}

func (a *Adapter) UpdateUser(user *kuta.User) error {
	ctx := context.Background()
	q := `UPDATE public.users SET email = $1, email_verified = $2, name = $3, image = $4, updated_at = now() WHERE id = $5 RETURNING updated_at`
	var updatedAt time.Time
	err := a.pool.QueryRow(ctx, q, user.Email, user.EmailVerified, user.Name, user.Image, user.ID).Scan(&updatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return kuta.ErrUserNotFound
		}
		return err
	}
	user.UpdatedAt = updatedAt
	return nil
}

func (a *Adapter) DeleteUser(id string) error {
	ctx := context.Background()
	_, err := a.pool.Exec(ctx, `DELETE FROM public.users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	return nil
}
