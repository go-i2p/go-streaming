module github.com/go-i2p/go-streaming

go 1.24.4

require (
	github.com/armon/circbuf v0.0.0-20190214190532-5111143e8da2
	github.com/go-i2p/go-i2cp v0.0.0-20251122234906-2cbce9c9070d
	github.com/rs/zerolog v1.34.0
	github.com/stretchr/testify v1.11.1
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-i2p/common v0.0.6 // indirect
	github.com/go-i2p/crypto v0.0.5 // indirect
	github.com/go-i2p/logger v0.0.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/samber/lo v1.51.0 // indirect
	github.com/samber/oops v1.19.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.step.sm/crypto v0.67.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Use local go-i2cp with exported SessionCallbacks
replace github.com/go-i2p/go-i2cp => ../go-i2cp
