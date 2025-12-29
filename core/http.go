package core

type HTTPAdapter interface {
	RegisterRoutes(k *Kuta) error
}
