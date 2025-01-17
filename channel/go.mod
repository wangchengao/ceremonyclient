module source.quilibrium.com/quilibrium/monorepo/channel

go 1.20

// A necessary hack until source.quilibrium.com is open to all
replace source.quilibrium.com/quilibrium/monorepo/nekryptology => ../nekryptology

require github.com/stretchr/testify v1.9.0

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/consensys/gnark-crypto v0.5.3 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect

)

require (
	github.com/cloudflare/circl v1.3.3
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.24.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	source.quilibrium.com/quilibrium/monorepo/nekryptology v0.0.0-00010101000000-000000000000 // indirect
)
