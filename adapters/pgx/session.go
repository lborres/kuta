package pgx

import "github.com/lborres/kuta"

func (a Adapter) CreateSession(session *kuta.Session) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) GetSessionByHash(tokenHash string) (*kuta.Session, error) {
	return nil, kuta.ErrNotImplemented
}

func (a *Adapter) GetSessionByID(id string) (*kuta.Session, error) {
	return nil, kuta.ErrNotImplemented
}

func (a *Adapter) GetUserSessions(userID string) ([]*kuta.Session, error) {
	return nil, kuta.ErrNotImplemented
}

func (a *Adapter) UpdateSession(session *kuta.Session) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) DeleteSessionByID(id string) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) DeleteSessionByHash(tokenHash string) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) DeleteUserSessions(userID string) (int, error) {
	return 200, kuta.ErrNotImplemented
}

func (a *Adapter) DeleteExpiredSessions() (int, error) {
	return 200, kuta.ErrNotImplemented
}
