package pgx

import "github.com/lborres/kuta"

func (a *Adapter) CreateUser(u *kuta.User) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) GetUserByID(id string) (*kuta.User, error) {
	return nil, kuta.ErrNotImplemented
}

func (a *Adapter) GetUserByEmail(email string) (*kuta.User, error) {
	return nil, kuta.ErrNotImplemented
}

func (a *Adapter) UpdateUser(u *kuta.User) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) DeleteUser(id string) error {
	return kuta.ErrNotImplemented
}
