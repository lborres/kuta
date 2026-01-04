package pgx

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lborres/kuta"
)

func (a *Adapter) CreateSession(session *kuta.Session) error {
	ctx := context.Background()

	query := `INSERT INTO public.sessions (id, user_id, token_hash, ip_address, user_agent, expires_at) 
	          VALUES ($1, $2, $3, $4, $5, $6) 
	          RETURNING created_at, updated_at`

	var createdAt, updatedAt time.Time
	err := a.pool.QueryRow(ctx, query,
		session.ID, session.UserID, session.TokenHash, session.IPAddress, session.UserAgent, session.ExpiresAt,
	).Scan(&createdAt, &updatedAt)

	if err != nil {
		return err
	}

	session.CreatedAt = createdAt
	session.UpdatedAt = updatedAt
	return nil
}

func (a *Adapter) GetSessionByHash(tokenHash string) (*kuta.Session, error) {
	ctx := context.Background()
	query := `SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at, updated_at 
	          FROM public.sessions WHERE token_hash = $1`

	session := &kuta.Session{}
	err := a.pool.QueryRow(ctx, query, tokenHash).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.IPAddress, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, kuta.ErrSessionNotFound
		}
		return nil, err
	}

	return session, nil
}

func (a *Adapter) GetSessionByID(id string) (*kuta.Session, error) {
	ctx := context.Background()
	query := `SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at, updated_at 
	          FROM public.sessions WHERE id = $1`

	session := &kuta.Session{}
	err := a.pool.QueryRow(ctx, query, id).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.IPAddress, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, kuta.ErrSessionNotFound
		}
		return nil, err
	}

	return session, nil
}

func (a *Adapter) GetUserSessions(userID string) ([]*kuta.Session, error) {
	ctx := context.Background()
	query := `SELECT id, user_id, token_hash, ip_address, user_agent, expires_at, created_at, updated_at 
	          FROM public.sessions WHERE user_id = $1 ORDER BY created_at DESC`

	rows, err := a.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*kuta.Session
	for rows.Next() {
		session := &kuta.Session{}
		err := rows.Scan(
			&session.ID, &session.UserID, &session.TokenHash, &session.IPAddress, &session.UserAgent, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

func (a *Adapter) UpdateSession(session *kuta.Session) error {
	ctx := context.Background()
	query := `UPDATE public.sessions SET token_hash = $1, ip_address = $2, user_agent = $3, expires_at = $4, updated_at = now() 
	          WHERE id = $5 RETURNING updated_at`

	var updatedAt time.Time
	err := a.pool.QueryRow(ctx, query,
		session.TokenHash, session.IPAddress, session.UserAgent, session.ExpiresAt, session.ID,
	).Scan(&updatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			return kuta.ErrSessionNotFound
		}
		return err
	}

	session.UpdatedAt = updatedAt
	return nil
}

func (a *Adapter) DeleteSessionByID(id string) error {
	ctx := context.Background()
	_, err := a.pool.Exec(ctx, `DELETE FROM public.sessions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	return nil
}

func (a *Adapter) DeleteSessionByHash(tokenHash string) error {
	ctx := context.Background()
	_, err := a.pool.Exec(ctx, `DELETE FROM public.sessions WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return err
	}
	return nil
}

func (a *Adapter) DeleteUserSessions(userID string) (int, error) {
	ctx := context.Background()
	tag, err := a.pool.Exec(ctx, `DELETE FROM public.sessions WHERE user_id = $1`, userID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (a *Adapter) DeleteExpiredSessions() (int, error) {
	ctx := context.Background()
	tag, err := a.pool.Exec(ctx, `DELETE FROM public.sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
