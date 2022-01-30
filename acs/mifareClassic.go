package acs

import (
	_ "fmt"

	"github.com/nmelo/smartcard/nxp/mifare"
	"github.com/nmelo/smartcard/pcsc"
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

//ConnectMclassic Create Mifare Plus Interface
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

//MClassic Create Mifare Plus Interface
func MClassic(c pcsc.Card) (mifare.Classic, error) {

	mc := &mifareClassic{
		Card: c,
	}
	return mc, nil
}

/**/

func (mc *mifareClassic) Auth(bNr, keyType int, key []byte) ([]byte, error) {
	aid := []byte{0xFF, 0x82, 0x00, 0x00, 0x06}
	aid = append(aid, key...)

	response, err := mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	if keyType == 0 {
		aid = []byte{0xFF, 0x88, 0x00, byte(bNr), 0x60, 0x00}
	} else {
		aid = []byte{0xFF, 0x88, 0x00, byte(bNr), 0x61, 0x00}
	}

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
