package samav2

import (
	"encoding/binary"

	"github.com/dumacp/smartcard/nxp/mifare"
)

//PKIGenerateKeyPair creates a pair of a public and prvate key
func (sam *samAv2) PKIGenerateKeyPair(pkiE []byte, pkiSET []byte,
	pkiKeyNo, pkiKeyNoCEK, pkikeVCEK, pkiRefNoKUC byte, pkiNLen int) ([]byte, error) {

	var resp []byte
	for _, v := range ApduPKIGenerateKeyPair(pkiE, pkiSET, pkiKeyNo, pkiKeyNoCEK, pkikeVCEK,
		pkiRefNoKUC, pkiNLen) {

		var err error
		resp, err = sam.Apdu(v)
		if err != nil {
			return nil, err
		}
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func ApduPKIGenerateKeyPair(pkiE []byte, pkiSET []byte,
	pkiKeyNo, pkiKeyNoCEK, pkikeVCEK, pkiRefNoKUC byte, pkiNLen int) [][]byte {

	apdus := make([][]byte, 0)
	apdu := make([]byte, 0)
	apducmd := []byte{0x80, 0x15}
	p1 := byte(0)
	if len(pkiE) > 0 {
		p1 = 0x01
	}

	p2 := byte(0)
	if 10+len(pkiE) > 255 {
		p2 = 0xAF
	}

	apducmd = append(apducmd, p1)
	apdu = append(apdu, apducmd...)
	apdu = append(apducmd, p2)
	apdu = append(apdu, byte(len(pkiE)+10))

	apdu = append(apdu, pkiKeyNo)
	apdu = append(apdu, pkiSET...)
	apdu = append(apdu, pkiKeyNoCEK)
	apdu = append(apdu, pkikeVCEK)
	apdu = append(apdu, pkiRefNoKUC)
	lenRSA := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenRSA, 256)
	apdu = append(apdu, lenRSA...)

	if 10+len(pkiE) <= 255 {
		apdu = append(apdu, pkiE...)
		apdus = append(apdus, apdu)
	} else {
		pkiECopy := make([]byte, len(pkiE))
		copy(pkiECopy, pkiE)

		apdu = append(apdu, pkiECopy[0:255-10]...)
		pkiECopy = pkiECopy[255-10:]
		apdus = append(apdus, apdu)
		for {

			nextapdu := make([]byte, 0)
			nextapdu = append(nextapdu, apducmd...)
			nextapdu = append(nextapdu, 0x00) // P2 = 0x00

			if len(pkiECopy) > 255 {
				nextapdu = append(nextapdu, byte(255))
				nextapdu = append(nextapdu, pkiECopy[0:255]...)
				pkiECopy = pkiECopy[255:]
				apdus = append(apdus, nextapdu)
			} else {
				nextapdu = append(nextapdu, byte(len(pkiECopy)))
				nextapdu = append(nextapdu, pkiECopy...)
				apdus = append(apdus, nextapdu)
				break
			}
		}
	}

	return apdus
}
