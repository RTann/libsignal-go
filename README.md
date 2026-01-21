# libsignal-go

A pure Go implementation of https://github.com/signalapp/libsignal.

This repository is meant to be broken down into different
APIs similar to the source repository.

Only libsignal-protocol is implemented at this time.

This repository is still under development, so users should expect
breaking changes.

## How to Use

### Protocol

#### Session

```go
package main

import (
	"context"
	"crypto/rand"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/session"
)

// Alice creates a session with Bob and sends a message.
// Error handing is ignored in this example, but should otherwise not be ignored.
func main() {
	aliceIdentityKeyPair, _ := identity.GenerateKeyPair(rand.Reader)
	aliceBaseKeyPair, _ := curve.GenerateKeyPair(rand.Reader)

	var bobIdentity     identity.Key
	var bobSignedPreKey curve.PublicKey
	var bobEphemeralKey curve.PublicKey

	aliceParams := &ratchet.AliceParameters{
		OurIdentityKeyPair: aliceIdentityKeyPair,
		OurBaseKeyPair:     aliceBaseKeyPair,
		TheirIdentityKey:   bobIdentity,
		TheirSignedPreKey:  bobSignedPreKey,
		TheirOneTimePreKey: nil,
		TheirRatchetKey:    bobEphemeralKey,
	}
	aliceRecord, _ := session.InitializeAliceSessionRecord(rand.Reader, aliceParams)

	registrationID := uint32(1)
	bobAddress := address.Address{
		Name:     "+15555555555",
		DeviceID: 1,
	}

	// Alice creates a session to talk to Bob.
	aliceSession := &session.Session{
		RemoteAddress:    bobAddress,
		SessionStore:     session.NewInMemStore(),
		IdentityKeyStore: identity.NewInMemStore(aliceIdentityKeyPair, registrationID),
	}
	_ = aliceSession.SessionStore.Store(context.Background(), bobAddress, aliceRecord)
	// Write a nice encrypted message to Bob.
	plaintext := []byte("Hello, Bob!")
	aliceCiphertext, _ := aliceSession.EncryptMessage(context.Background(), plaintext)

	// Alice sends her encrypted message to Bob.
}
```

```go
package main

import (
	"context"
	"crypto/rand"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/session"
)

// Bob creates a session with Alice and receives a message.
// Error handing is ignored in this example, but should otherwise not be ignored.
func main() {
	keyPair, _ := identity.GenerateKeyPair(rand.Reader)
	registrationID := uint32(1)
    aliceAddress := address.Address{
        Name:     "+15555555556",
        DeviceID: 1,
    }
	
    // Bob creates a session to talk to Alice.
    bobSession := &session.Session{
        RemoteAddress:    aliceAddress,
        SessionStore:     session.NewInMemStore(),
        IdentityKeyStore: identity.NewInMemStore(keyPair, registrationID),
    }
	
	var ciphertext []byte
	// Bob receives Alice's message and stores it in ciphertext.

	plaintext, _ := bobSession.DecryptMessage(context.Background(), rand.Reader, ciphertext)
	
	// Alice sends her encrypted message to Bob.
}
```

#### Group Session

```go

```

## Roadmap

1. Implement post-quantum cryptography support.
1. Implement sealed sender support.
1. Add and refactor tests.
1. Implement other APIs available in the source repository.
