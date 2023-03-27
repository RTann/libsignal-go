// Package session implements a protocol session.
package session

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/golang/glog"

	"github.com/RTann/libsignal-go/protocol/address"
	"github.com/RTann/libsignal-go/protocol/curve"
	"github.com/RTann/libsignal-go/protocol/direction"
	v1 "github.com/RTann/libsignal-go/protocol/generated/v1"
	"github.com/RTann/libsignal-go/protocol/identity"
	"github.com/RTann/libsignal-go/protocol/message"
	"github.com/RTann/libsignal-go/protocol/perrors"
	"github.com/RTann/libsignal-go/protocol/prekey"
	"github.com/RTann/libsignal-go/protocol/ratchet"
)

// Session represents a protocol session with another user.
type Session struct {
	RemoteAddress     address.Address
	SessionStore      Store
	PreKeyStore       prekey.Store
	SignedPreKeyStore prekey.SignedStore
	IdentityKeyStore  identity.Store
}

// ProcessPreKey processes a pre-key message to initialize a "Bob" session
// after receiving a message from "Alice".
//
// This method returns the one-time pre-key used by "Alice" when sending the initial message,
// if one was used.
func (s *Session) ProcessPreKey(ctx context.Context, record *Record, message *message.PreKey) (*prekey.ID, error) {
	theirIdentityKey := message.IdentityKey()

	trusted, err := s.IdentityKeyStore.IsTrustedIdentity(ctx, s.RemoteAddress, theirIdentityKey, direction.Receiving)
	if err != nil {
		return nil, err
	}
	if !trusted {
		return nil, perrors.ErrUntrustedIdentity(s.RemoteAddress)
	}

	unsignedPreKeyID, err := s.processPreKeyV3(ctx, record, message)
	if err != nil {
		return nil, err
	}

	_, err = s.IdentityKeyStore.Store(ctx, s.RemoteAddress, theirIdentityKey)
	if err != nil {
		return nil, err
	}

	return unsignedPreKeyID, nil
}

func (s *Session) processPreKeyV3(ctx context.Context, record *Record, message *message.PreKey) (*prekey.ID, error) {
	exists, err := record.HasSessionState(uint32(message.Version()), message.BaseKey().Bytes())
	if err != nil {
		return nil, err
	}
	if exists {
		// We've already set up a session for this V3 message, letting bundled message fall through.
		return nil, nil
	}

	var ourSignedPreKeyPair *curve.KeyPair
	ourSignedPreKeyRecord, exists, err := s.SignedPreKeyStore.Load(ctx, message.SignedPreKeyID())
	if err != nil {
		return nil, err
	}
	if exists {
		ourSignedPreKeyPair, err = ourSignedPreKeyRecord.KeyPair()
		if err != nil {
			return nil, err
		}
	}

	var ourOneTimePreKeyPair *curve.KeyPair
	if message.PreKeyID() == nil {
		glog.Warningf("processing PreKey message from %s which had no one-time pre-key", s.RemoteAddress)
	} else {
		glog.Infof("processing PreKey message from %s", s.RemoteAddress)

		ourOneTimePreKeyRecord, exists, err := s.PreKeyStore.Load(ctx, *message.PreKeyID())
		if err != nil {
			return nil, err
		}
		if exists {
			ourOneTimePreKeyPair, err = ourOneTimePreKeyRecord.KeyPair()
			if err != nil {
				return nil, err
			}
		}
	}

	session, err := initializeBobSession(&ratchet.BobParameters{
		OurIdentityKeyPair:   s.IdentityKeyStore.KeyPair(ctx),
		OurSignedPreKeyPair:  ourSignedPreKeyPair,
		OurOneTimePreKeyPair: ourOneTimePreKeyPair,
		OurRatchetKeyPair:    ourSignedPreKeyPair,
		TheirIdentityKey:     message.IdentityKey(),
		TheirBaseKey:         message.BaseKey(),
	})

	session.SetLocalRegistrationID(s.IdentityKeyStore.LocalRegistrationID(ctx))
	session.SetRemoteRegistrationID(message.RegistrationID())
	session.SetAliceBaseKey(message.BaseKey().Bytes())

	record.PromoteState(session)

	return message.PreKeyID(), nil
}

// ProcessPreKeyBundle processes a pre-key bundle to initialize an "Alice" session
// to send encrypted messages to some "Bob" user identified by the pre-key bundle.
func (s *Session) ProcessPreKeyBundle(ctx context.Context, random io.Reader, bundle *prekey.Bundle) error {
	theirIdentityKey := bundle.IdentityKey

	trusted, err := s.IdentityKeyStore.IsTrustedIdentity(ctx, s.RemoteAddress, theirIdentityKey, direction.Sending)
	if err != nil {
		return err
	}
	if !trusted {
		return errors.New("untrusted identity")
	}

	ok, err := theirIdentityKey.PublicKey().VerifySignature(bundle.SignedPreKeySignature, bundle.SignedPreKeyPublic.Bytes())
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("signature validation failed")
	}

	record, exists, err := s.SessionStore.Load(ctx, s.RemoteAddress)
	if err != nil {
		return err
	}
	if !exists {
		record = NewRecord(nil)
	}

	ourBaseKeyPair, err := curve.GenerateKeyPair(random)
	if err != nil {
		return err
	}
	theirSignedPreKey := bundle.SignedPreKeyPublic
	theirOneTimePreKey := bundle.PreKeyPublic
	ourIdentityKeyPair := s.IdentityKeyStore.KeyPair(ctx)

	session, err := initializeAliceSession(random, &ratchet.AliceParameters{
		OurIdentityKeyPair: ourIdentityKeyPair,
		OurBaseKeyPair:     ourBaseKeyPair,
		TheirIdentityKey:   theirIdentityKey,
		TheirSignedPreKey:  theirSignedPreKey,
		TheirOneTimePreKey: theirOneTimePreKey,
		TheirRatchetKey:    theirSignedPreKey,
	})
	if err != nil {
		return err
	}

	theirOneTimePreKeyID := bundle.PreKeyID
	preKeyString := "<none>"
	if theirOneTimePreKeyID != nil {
		preKeyString = theirOneTimePreKeyID.String()
	}
	glog.Infof("set_unacknowledged_pre_key_message for: %s with preKeyId: %s", s.RemoteAddress, preKeyString)

	session.SetUnacknowledgedPreKeyMessage(theirOneTimePreKeyID, bundle.SignedPreKeyID, ourBaseKeyPair.PublicKey())

	session.SetLocalRegistrationID(s.IdentityKeyStore.LocalRegistrationID(ctx))
	session.SetRemoteRegistrationID(bundle.RegistrationID)
	session.SetAliceBaseKey(ourBaseKeyPair.PublicKey().Bytes())

	_, err = s.IdentityKeyStore.Store(ctx, s.RemoteAddress, theirIdentityKey)
	if err != nil {
		return err
	}

	record.PromoteState(session)

	err = s.SessionStore.Store(ctx, s.RemoteAddress, record)
	if err != nil {
		return err
	}

	return nil
}

func InitializeAliceSessionRecord(random io.Reader, params *ratchet.AliceParameters) (*Record, error) {
	session, err := initializeAliceSession(random, params)
	if err != nil {
		return nil, err
	}

	return NewRecord(session), nil
}

func initializeAliceSession(random io.Reader, params *ratchet.AliceParameters) (*State, error) {
	localIdentity := params.OurIdentityKeyPair.IdentityKey()
	sendingRatchetKeyPair, err := curve.GenerateKeyPair(random)
	if err != nil {
		return nil, err
	}

	dh1, err := params.OurIdentityKeyPair.PrivateKey().Agreement(params.TheirSignedPreKey)
	if err != nil {
		return nil, err
	}

	ourBasePrivateKey := params.OurBaseKeyPair.PrivateKey()
	dh2, err := ourBasePrivateKey.Agreement(params.TheirIdentityKey.PublicKey())
	if err != nil {
		return nil, err
	}
	dh3, err := ourBasePrivateKey.Agreement(params.TheirSignedPreKey)
	if err != nil {
		return nil, err
	}

	// 32 * 5 = 160
	secrets := bytes.NewBuffer(make([]byte, 0, 160))
	secrets.Write(discontinuityBytes)
	secrets.Write(dh1)
	secrets.Write(dh2)
	secrets.Write(dh3)

	if params.TheirOneTimePreKey != nil {
		dh4, err := ourBasePrivateKey.Agreement(params.TheirOneTimePreKey)
		if err != nil {
			return nil, err
		}

		secrets.Write(dh4)
	}

	rootKey, chainKey, err := ratchet.DeriveKeys(secrets.Bytes())
	if err != nil {
		return nil, err
	}

	sendingChainRootKey, sendingChainChainKey, err := rootKey.CreateChain(sendingRatchetKeyPair.PrivateKey(), params.TheirRatchetKey)
	if err != nil {
		return nil, err
	}

	session := NewState(&v1.SessionStructure{
		SessionVersion:       message.CiphertextVersion,
		LocalIdentityPublic:  localIdentity.PublicKey().Bytes(),
		RemoteIdentityPublic: params.TheirIdentityKey.Bytes(),
		RootKey:              sendingChainRootKey.Bytes(),
	})
	session.AddReceiverChain(params.TheirRatchetKey, chainKey)
	session.SetSenderChain(sendingRatchetKeyPair, sendingChainChainKey)

	return session, nil
}

func InitializeBobSessionRecord(params *ratchet.BobParameters) (*Record, error) {
	session, err := initializeBobSession(params)
	if err != nil {
		return nil, err
	}

	return NewRecord(session), nil
}

func initializeBobSession(params *ratchet.BobParameters) (*State, error) {
	localIdentity := params.OurIdentityKeyPair.IdentityKey()

	dh1, err := params.OurSignedPreKeyPair.PrivateKey().Agreement(params.TheirIdentityKey.PublicKey())
	if err != nil {
		return nil, err
	}

	dh2, err := params.OurIdentityKeyPair.PrivateKey().Agreement(params.TheirBaseKey)
	if err != nil {
		return nil, err
	}

	dh3, err := params.OurSignedPreKeyPair.PrivateKey().Agreement(params.TheirBaseKey)
	if err != nil {
		return nil, err
	}

	// 32 * 5 = 160
	secrets := bytes.NewBuffer(make([]byte, 0, 160))
	secrets.Write(discontinuityBytes)
	secrets.Write(dh1)
	secrets.Write(dh2)
	secrets.Write(dh3)

	if params.OurOneTimePreKeyPair != nil {
		dh4, err := params.OurOneTimePreKeyPair.PrivateKey().Agreement(params.TheirBaseKey)
		if err != nil {
			return nil, err
		}

		secrets.Write(dh4)
	}

	rootKey, chainKey, err := ratchet.DeriveKeys(secrets.Bytes())

	session := NewState(&v1.SessionStructure{
		SessionVersion:       message.CiphertextVersion,
		LocalIdentityPublic:  localIdentity.PublicKey().Bytes(),
		RemoteIdentityPublic: params.TheirIdentityKey.Bytes(),
		RootKey:              rootKey.Bytes(),
	})
	session.SetSenderChain(params.OurRatchetKeyPair, chainKey)

	return session, nil
}
