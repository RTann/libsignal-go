package curve25519

import (
	"errors"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

var (
	one         = new(field.Element).One()
	negativeOne = new(field.Element).Negate(one)
)

// xtou converts an Edwards x-point to a Montgomery u-point.
func xtou(edX *edwards25519.Scalar) []byte {
	return new(edwards25519.Point).ScalarBaseMult(edX).BytesMontgomery()
}

// utoy converts a Montgomery u-point to an Edwards y-point.
func utoy(montU []byte, positive bool) ([]byte, error) {
	u, err := new(field.Element).SetBytes(montU)
	if err != nil {
		return nil, err
	}

	// y = (u - 1) / (u + 1)
	// See https://www.rfc-editor.org/rfc/rfc7748#section-4.1 for more information.

	// Based on the formula above, a valid u-point cannot be -1.
	// Equal returns 1 to mean "true".
	if u.Equal(negativeOne) == 1 {
		return nil, errors.New("invalid u-point")
	}

	uMinusOne := new(field.Element).Subtract(u, one)
	invUPlusOne := new(field.Element).Invert(new(field.Element).Add(u, one))

	y := new(field.Element).Multiply(uMinusOne, invUPlusOne).Bytes()
	var sign byte
	if !positive {
		sign = 0b1000_0000
	}
	y[31] ^= sign

	return y, nil
}
