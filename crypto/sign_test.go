package crypto

import (
	"encoding/hex"
	"math/big"
	"testing"
)

type KeyRS struct {
	DER   string
	R     string // Base 16 encoded number
	S     string
	Error bool
}

func TestPointsToDER(t *testing.T) {
	data := []KeyRS{
		KeyRS{
			DER:   "3045022078611477d7824bc8e48a4aa242e8b7733ef0315e2127682533e175a371df6447022100f91beab703e13cf3622d5140af8ec341cc994bb23a98021acb260d0959f47ed2",
			R:     "78611477d7824bc8e48a4aa242e8b7733ef0315e2127682533e175a371df6447",
			S:     "00f91beab703e13cf3622d5140af8ec341cc994bb23a98021acb260d0959f47ed2",
			Error: false,
		},
		KeyRS{
			DER:   "3046022100aebe330b80993d10c8f6dd54787f458c18c5df438898f514efac3d6c51172af2022100e5fe2c1bb2156708f2ec3389a16e1308219e67e7ba2dd04653634c69f2b36e98",
			R:     "00aebe330b80993d10c8f6dd54787f458c18c5df438898f514efac3d6c51172af2",
			S:     "00e5fe2c1bb2156708f2ec3389a16e1308219e67e7ba2dd04653634c69f2b36e98",
			Error: false,
		},
	}
	for i := range data {
		var r, s big.Int
		R, _ := r.SetString(data[i].R, 16)
		S, _ := s.SetString(data[i].S, 16)

		gotDer := PointsToDER(R, S)
		decoded := make([]byte, hex.DecodedLen(len(gotDer)))
		hex.Decode(decoded, gotDer)
		der := hex.EncodeToString(decoded)
		if der != data[i].DER {
			t.Fatalf("Unexpected R/S from DER string.\nExpected %s \nGot %s", data[i].DER, der)
		}
	}
}

func TestPointsFromDER(t *testing.T) {
	data := []KeyRS{
		KeyRS{
			DER:   "3045022078611477d7824bc8e48a4aa242e8b7733ef0315e2127682533e175a371df6447022100f91beab703e13cf3622d5140af8ec341cc994bb23a98021acb260d0959f47ed2",
			R:     "78611477d7824bc8e48a4aa242e8b7733ef0315e2127682533e175a371df6447",
			S:     "00f91beab703e13cf3622d5140af8ec341cc994bb23a98021acb260d0959f47ed2",
			Error: false,
		},
		KeyRS{
			DER:   "3046022100aebe330b80993d10c8f6dd54787f458c18c5df438898f514efac3d6c51172af2022100e5fe2c1bb2156708f2ec3389a16e1308219e67e7ba2dd04653634c69f2b36e98",
			R:     "00aebe330b80993d10c8f6dd54787f458c18c5df438898f514efac3d6c51172af2",
			S:     "00e5fe2c1bb2156708f2ec3389a16e1308219e67e7ba2dd04653634c69f2b36e98",
			Error: false,
		},
	}

	for i := range data {
		var r, s big.Int
		R, _ := r.SetString(data[i].R, 16)
		S, _ := s.SetString(data[i].S, 16)

		der, _ := hex.DecodeString(data[i].DER)
		gotR, gotS, err := PointsFromDER(der)

		if data[i].Error == (err == nil) {
			t.Fatalf("Unexpected Error Occoured, KeyRS index: %d, err: %+v", i, err)
		}

		if gotR.Cmp(R) != 0 || gotS.Cmp(S) != 0 {
			t.Fatalf("Unexpected R/S from DER string.\nExpected %v, %v\nGot %v, %v", R, S, gotR, gotS)
		}
	}
}
