package samav2

import (
	"encoding/binary"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

//PKIGenerateKeyPair creates a pair of a public and prvate key
func (sam *samAv2) PKIGenerateKeyPair(pkiE []byte, pkiSET []byte,
	pkiKeyNo, pkiKeyNoCEK, pkikeVCEK, pkiRefNoKUC, pkiNLen int) ([]byte, error) {

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

//PKIExportPublicKey exports the public key part of a RSA key pair
func (sam *samAv2) PKIExportPublicKey(pkiKeyNo int) ([]byte, error) {

	resp, err := sam.Apdu(ApduPKIExportPublicKey(pkiKeyNo))
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func ApduPKIExportPublicKey(pkiKeyNo int) []byte {

	cmd := &smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x18,
		P1:  byte(pkiKeyNo),
		P2:  0x00,
		Le:  true,
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.PrefixApdu()...)

	if cmd.Le {
		apdu = append(apdu, 0x00)
	}

	return apdu
}

func ApduPKIGenerateKeyPair(pkiE []byte, pkiSET []byte,
	pkiKeyNo, pkiKeyNoCEK, pkikeVCEK, pkiRefNoKUC, pkiNLen int) [][]byte {

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

	apdu = append(apdu, byte(pkiKeyNo))
	apdu = append(apdu, pkiSET...)
	apdu = append(apdu, byte(pkiKeyNoCEK))
	apdu = append(apdu, byte(pkikeVCEK))
	apdu = append(apdu, byte(pkiRefNoKUC))
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

type HashingAlgorithm int

const (
	SHA1 HashingAlgorithm = iota
	SHA224
	RFU
	SHA256
)

func ApduPKIUpdateKeyEntries(hashing HashingAlgorithm, keyEntrysNo int,
	pkiKeyNoEnc, pkiKeyNoSign int, pkiEncKeyFrame, pkiSignature []byte) [][]byte {

	// cmd := &smartcard.ISO7816cmd{
	// 	CLA: 0x80,
	// 	INS: 0x18,
	// 	P1:  byte(hashing) | byte(keyEntrysNo<<2),
	// 	P2:  0x00,
	// 	Le:  true,
	// }

	// if len()

	// apdu := make([]byte, 0)
	// apdu = append(apdu, cmd.PrefixApdu()...)

	// if cmd.Le {
	// 	apdu = append(apdu, 0x00)
	// }

	return nil
}
