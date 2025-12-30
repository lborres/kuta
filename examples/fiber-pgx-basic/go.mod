module github.com/lborres/kuta/examples/fiber-pgx-basic

go 1.25.4

require (
	github.com/gofiber/fiber/v3 v3.0.0-rc.3
	github.com/jackc/pgx/v5 v5.8.0
	github.com/lborres/kuta v0.0.0-20251125222108-97304e95aeb3
	github.com/lborres/kuta/adapters/fiber v0.0.0-20251229222642-7575aa11a0ea
	github.com/lborres/kuta/adapters/pgx v0.0.0-20251229222642-7575aa11a0ea
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/gofiber/schema v1.6.0 // indirect
	github.com/gofiber/utils/v2 v2.0.0-rc.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.68.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

replace github.com/lborres/kuta => ../..
