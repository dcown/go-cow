package crypto

import (
	"encoding/asn1"
	"encoding/hex"
	"math/big"
)

// PointsToDER Convert an ECDSA signature (points R and S) to a byte array using ASN.1 DER encoding.
// This is a port of Bitcore's Key.rs2DER method.
func PointsToDER(r, s *big.Int) []byte {
	// Ensure MSB doesn't break big endian encoding in DER sigs
	prefixPoint := func(b []byte) []byte {
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			paddedBytes := make([]byte, len(b)+1)
			copy(paddedBytes[1:], b)
			b = paddedBytes
		}
		return b
	}

	rb := prefixPoint(r.Bytes())
	sb := prefixPoint(s.Bytes())

	// DER encoding:
	// 0x30 + z + 0x02 + len(rb) + rb + 0x02 + len(sb) + sb
	length := 2 + len(rb) + 2 + len(sb)

	der := append([]byte{0x30, byte(length), 0x02, byte(len(rb))}, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)

	encoded := make([]byte, hex.EncodedLen(len(der)))
	hex.Encode(encoded, der)

	return encoded
}

// PointsFromDER Get the R and S points from a DER encoded signature
// This should NOT be a hex encoded byte array
func PointsFromDER(der []byte) (R, S *big.Int, err error) {
	R, S = &big.Int{}, &big.Int{}

	data := asn1.RawValue{}
	if _, err = asn1.Unmarshal(der, &data); err != nil {
		return nil, nil, err
	}

	// The format of our DER string is 0x02 + rlen + r + 0x02 + slen + s
	rLen := data.Bytes[1] // The entire length of R + offset of 2 for 0x02 and rlen
	r := data.Bytes[2 : rLen+2]
	// Ignore the next 0x02 and slen bytes and just take the start of S to the end of the byte array
	s := data.Bytes[rLen+4:]

	R.SetBytes(r)
	S.SetBytes(s)

	return
}
