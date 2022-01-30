package samav2

import (
	"encoding/binary"

	"github.com/nmelo/smartcard"
	"github.com/nmelo/smartcard/nxp/mifare"
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

	response := make([]byte, 0)
	resp, err := sam.Apdu(ApduPKIExportPublicKey(pkiKeyNo))
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}
	response = append(response, resp[:len(resp)-2]...)
	for resp[len(resp)-1] == 0xAF {
		cmd := &smartcard.ISO7816cmd{
			CLA: 0x80,
			INS: 0x18,
			P1:  byte(pkiKeyNo),
			P2:  0x00,
			Le:  true,
		}
		apdu := cmd.PrefixApdu()
		if cmd.Le {
			apdu = append(apdu, 0x00)
		}
		resp, err = sam.Apdu(apdu)
		if err != nil {
			return nil, err
		}
		if err := mifare.VerifyResponseIso7816(resp); err != nil {
			return nil, err
		}
		response = append(response, resp[:len(resp)-2]...)
	}
	return response, nil
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
	data := make([]byte, 0)
	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x15,
		P1:  0x00,
		P2:  0x00,
		Le:  false,
	}
	p1 := byte(0)
	if len(pkiE) > 0 {
		p1 = 0x01
	}
	cmd.P1 = p1

	// data = append(data, byte(len(pkiE)+10))

	data = append(data, byte(pkiKeyNo))
	data = append(data, pkiSET...)
	data = append(data, byte(pkiKeyNoCEK))
	data = append(data, byte(pkikeVCEK))
	data = append(data, byte(pkiRefNoKUC))
	lenRSA := make([]byte, 2)
	binary.BigEndian.PutUint16(lenRSA, uint16(pkiNLen))
	data = append(data, lenRSA...)

	lenPKIe := make([]byte, 2)
	if len(pkiE) > 0 {
		binary.BigEndian.PutUint16(lenPKIe, uint16(len(pkiE)))
	} else {
		binary.BigEndian.PutUint16(lenPKIe, uint16(4))
	}
	data = append(data, lenPKIe...)
	if len(pkiE) > 0 {
		data = append(data, pkiE...)
	}

	if cmd.Le {
		data = append(data, 0x00)
	}

	chunks := make([][]byte, 0)
	chunkSize := 255
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(data) {
			end = len(data)
		}

		chunks = append(chunks, data[i:end])
	}

	for i, v := range chunks {
		if i < len(chunks)-1 {
			cmd.P2 = 0xAF
		} else {
			cmd.P2 = 0x00
		}
		apdu := cmd.PrefixApdu()
		apdu = append(apdu, byte(len(v)))
		apdu = append(apdu, v...)
		apdus = append(apdus, apdu)
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

func (sam *samAv2) PKIUpdateKeyEntries(hashing HashingAlgorithm, keyEntrysNo int,
	pkiKeyNoEnc, pkiKeyNoSign int, pkiEncKeyFrame, pkiSignature []byte) ([]byte, error) {

	apdus := ApduPKIUpdateKeyEntries(hashing, keyEntrysNo, pkiKeyNoEnc, pkiKeyNoSign, pkiEncKeyFrame, pkiSignature)
	var resp []byte
	for _, v := range apdus {
		var err error
		resp, err = sam.Apdu(v)
		if err != nil {
			return nil, err
		}
		if err := mifare.VerifyResponseIso7816(resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func ApduPKIUpdateKeyEntries(hashing HashingAlgorithm, keyEntrysNo int,
	pkiKeyNoEnc, pkiKeyNoSign int, pkiEncKeyFrame, pkiSignature []byte) [][]byte {

	apdus := make([][]byte, 0)

	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x1D,
		P1:  0x00,
		P2:  0x00,
		Le:  false,
	}
	p1 := byte(0)
	switch hashing {
	case SHA1:
		p1 = 0x00
	case SHA224:
		p1 = 0x01
	case SHA256:
		p1 = 0x03
	}

	p1 |= (byte(keyEntrysNo) << 2)

	cmd.P1 = p1

	data := make([]byte, 0)
	// data = append(data, byte(len(pkiEncKeyFrame)+len(pkiSignature)+2))

	data = append(data, byte(pkiKeyNoEnc))
	data = append(data, byte(pkiKeyNoSign))

	data = append(data, pkiEncKeyFrame...)
	data = append(data, pkiSignature...)
	if cmd.Le {
		data = append(data, 0x00)
	}

	chunks := make([][]byte, 0)
	chunkSize := 255
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(data) {
			end = len(data)
		}

		chunks = append(chunks, data[i:end])
	}

	for i, v := range chunks {
		if i < len(chunks)-1 {
			cmd.P2 = 0xAF
		} else {
			cmd.P2 = 0x00
		}
		if i != 0 {
			cmd.P1 = 0x00
		}
		apdu := cmd.PrefixApdu()
		apdu = append(apdu, byte(len(v)))
		apdu = append(apdu, v...)
		apdus = append(apdus, apdu)
	}

	return apdus
}

func ApduPKIImportKey(pkiKeyNo, pkiKeyNoCEK, pkiKeyVCEK, pkiRefNoKUC int,
	pkiSET, pkie, pkiN, pkip, pkiq, pkidP, pkidQ, pkiipq []byte,
) [][]byte {

	apdus := make([][]byte, 0)

	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x19,
		P1:  0x00,
		P2:  0x00,
		Le:  false,
	}
	p1 := byte(0)
	if len(pkiN)+len(pkie)+len(pkip)+len(pkiq)+len(pkidP)+len(pkidQ)+len(pkiipq) <= 0 {
		p1 = 0x01
	}

	cmd.P1 = p1

	data := make([]byte, 0)
	data = append(data, byte(pkiKeyNo))
	data = append(data, pkiSET...)
	data = append(data, byte(pkiKeyNoCEK))
	data = append(data, byte(pkiKeyVCEK))
	data = append(data, byte(pkiRefNoKUC))
	if len(pkiN) > 0 {
		pkiNLen := make([]byte, 2)
		binary.BigEndian.PutUint16(pkiNLen, uint16(len(pkiN)))
		data = append(data, pkiNLen...)
	}
	if len(pkie) > 0 {
		pkieLen := make([]byte, 2)
		binary.BigEndian.PutUint16(pkieLen, uint16(len(pkie)))
		data = append(data, pkieLen...)
	}
	if len(pkip) > 0 {
		pkipLen := make([]byte, 2)
		binary.BigEndian.PutUint16(pkipLen, uint16(len(pkip)))
		data = append(data, pkipLen...)
	}
	if len(pkiq) > 0 {
		pkiqLen := make([]byte, 2)
		binary.BigEndian.PutUint16(pkiqLen, uint16(len(pkiq)))
		data = append(data, pkiqLen...)
	}

	data = append(data, pkiN...)
	data = append(data, pkie...)
	data = append(data, pkip...)
	data = append(data, pkiq...)

	data = append(data, pkidP...)
	data = append(data, pkidQ...)
	data = append(data, pkiipq...)

	if cmd.Le {
		data = append(data, 0x00)
	}

	// log.Printf("len data: %d\n", len(data))

	chunks := make([][]byte, 0)
	chunkSize := 255
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize

		// necessary check to avoid slicing beyond
		// slice capacity
		if end > len(data) {
			end = len(data)
		}

		chunks = append(chunks, data[i:end])
	}

	for i, v := range chunks {
		if i < len(chunks)-1 {
			cmd.P2 = 0xAF
		} else {
			cmd.P2 = 0x00
		}
		if i != 0 {
			cmd.P1 = 0x00
		}
		// log.Printf("cmd: [% X], %d, len data: %d\n", cmd.PrefixApdu(), i, len(v))
		apdu := cmd.PrefixApdu()
		apdu = append(apdu, byte(len(v)))
		apdu = append(apdu, v...)
		apdus = append(apdus, apdu)
	}

	return apdus
}

func (sam *samAv2) PKIImportKey(pkiKeyNo, pkiKeyNoCEK, pkiKeyVCEK, pkiRefNoKUC int,
	pkiSET, pkie, pkiN, pkip, pkiq, pkidP, pkidQ, pkiipq []byte) ([]byte, error) {

	apdus := ApduPKIImportKey(pkiKeyNo, pkiKeyNoCEK, pkiKeyVCEK, pkiRefNoKUC,
		pkiSET, pkie, pkiN, pkip, pkiq, pkidP, pkidQ, pkiipq)
	var resp []byte
	for _, v := range apdus {
		var err error
		resp, err = sam.Apdu(v)
		if err != nil {
			return nil, err
		}
		if err := mifare.VerifyResponseIso7816(resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}
