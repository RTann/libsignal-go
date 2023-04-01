package session

import (
	"context"
	"io"

	v2 "github.com/RTann/libsignal-go/protocol/sealedsender/v2"
)

type SealedSenderSessionV2 struct {

}

func (s *SealedSenderSessionV2) EncryptMessage(ctx context.Context, rand io.Reader) ([]byte, error) {
	m := make([]byte, v2.MessageKeySize)
	_, err := io.ReadFull(rand, m)
	if err != nil {
		return nil, err
	}

	keys, err := v2.DeriveEphemeralKeys(m)
	if err != nil {
		return nil, err
	}


}
