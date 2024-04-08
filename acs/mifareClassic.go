package acs

import (
	"fmt"
	_ "fmt"

	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/pcsc"
)

// //Mifare Plus Interface
// type MifareClassic interface {
// 	pcsc.Card
// 	Auth(bNr, keyType int, key []byte) ([]byte, error)
// 	ReadBlocks(bNr, ext int) ([]byte, error)
// 	WriteBlock(bNr int, data []byte) ([]byte, error)
// }

type mifareClassic struct {
	pcsc.Card
}

// ConnectMclassic Create Mifare Plus Interface
func ConnectMclassic(r pcsc.Reader) (mifare.Classic, error) {

	c, err := r.ConnectCardPCSC()
	if err != nil {
		return nil, err
	}
	mc := &mifareClassic{
		Card: c,
	}
	return mc, nil
}

// MClassic Create Mifare Plus Interface
func MClassic(c pcsc.Card) (mifare.Classic, error) {

	mc := &mifareClassic{
		Card: c,
	}
	return mc, nil
}

func (mc *mifareClassic) Apdu(apdu []byte) ([]byte, error) {
	return mc.Card.Apdu(apdu)
}

func (mc *mifareClassic) valueop(valOp, bNr byte, value []byte) error {
	dataInv := make([]byte, len(value))
	for i := range value {
		dataInv[i] = value[len(value)-1-i]
	}

	aid := []byte{0xFF, 0xD7, 0x00, byte(bNr), 0x05, byte(valOp)}
	aid = append(aid, dataInv...)
	fmt.Printf("apdu: %X, %02X\n", aid, dataInv)
	response, err := mc.Card.Apdu(aid)
	if err != nil {
		return err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return err
	}
	return nil

}

func (mc *mifareClassic) Inc(bNr int, data []byte) error {

	return mc.valueop(0x01, byte(bNr), data)
}

func (mc *mifareClassic) Dec(bNr int, data []byte) error {
	return mc.valueop(0x02, byte(bNr), data)
}

func (mc *mifareClassic) Copy(bNr int, dstBnr int) error {
	panic("not implemented") // TODO: Implement
}

/**/

func (mc *mifareClassic) Auth(bNr, keyType int, key []byte) ([]byte, error) {
	aid := []byte{0xFF, 0x82, 0x00, 0x00, 0x06}
	aid = append(aid, key...)

	// fmt.Printf("%X\n", aid)

	response, err := mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	// if keyType == 0 {
	// 	aid = []byte{0xFF, 0x88, 0x00, byte(bNr), 0x60, 0x00}
	// } else {
	// 	aid = []byte{0xFF, 0x88, 0x00, byte(bNr), 0x61, 0x00}
	// }

	if keyType == 0 {
		aid = []byte{0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, byte(bNr), 0x60, 0x00}
	} else {
		aid = []byte{0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, byte(bNr), 0x61, 0x00}
	}

	// fmt.Printf("auth apdu: %X\n", aid)

	response, err = mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	return response, nil
}

func (mc *mifareClassic) ReadBlocks(bNr, ext int) ([]byte, error) {
	if ext%16 != 0 {
		ext = ext * 16
	}
	aid := []byte{0xFF, 0xB0, 0x00, byte(bNr), byte(ext)}
	response, err := mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	return response, nil
}

func (mc *mifareClassic) WriteBlock(bNr int, data []byte) ([]byte, error) {
	aid := []byte{0xFF, 0xD6, 0x00, byte(bNr), byte(len(data))}
	aid = append(aid, data...)
	response, err := mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	return response, nil
}
