// Package distribution defines a group distribution ID.
package distribution

import "github.com/google/uuid"

type ID struct {
	id uuid.UUID
}

func MustParse(id string) ID {
	distributionID := uuid.MustParse(id)

	return ID{
		id: distributionID,
	}
}

func Parse(id string) (ID, error) {
	distributionID, err := uuid.Parse(id)
	if err != nil {
		return ID{}, err
	}

	return ID{
		id: distributionID,
	}, nil
}

func ParseBytes(id []byte) (ID, error) {
	distributionID, err := uuid.ParseBytes(id)
	if err != nil {
		return ID{}, err
	}

	return ID{
		id: distributionID,
	}, nil
}

func (i ID) String() string {
	return i.id.String()
}
