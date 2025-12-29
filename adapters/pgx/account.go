package pgx

import "github.com/lborres/kuta"

func (a *Adapter) CreateAccount(acc *kuta.Account) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) GetAccountByID(id string) (*kuta.Account, error) {
	return nil, kuta.ErrNotImplemented
}
func (a *Adapter) GetAccountByUserAndProvider(userID, providerID string) ([]*kuta.Account, error) {
	return nil, kuta.ErrNotImplemented
}

func (a *Adapter) UpdateAccount(acc *kuta.Account) error {
	return kuta.ErrNotImplemented
}

func (a *Adapter) DeleteAccount(id string) error {
	return kuta.ErrNotImplemented
}
