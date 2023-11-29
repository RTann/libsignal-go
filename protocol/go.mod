module github.com/RTann/libsignal-go/protocol

go 1.20

require (
	filippo.io/edwards25519 v1.0.0
	github.com/golang/glog v1.2.0
	github.com/google/uuid v1.4.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.15.0
	golang.org/x/tools v0.16.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.14.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace filippo.io/edwards25519 => github.com/RTann/edwards25519 v0.0.0-20230216062325-3c460db4d075
