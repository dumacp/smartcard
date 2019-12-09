package multiiso

import (
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

//commands
const (
	authentication string = "l"
	readblock      string = "rb"
	writeblock     string = "wb"
)

//response
const (
	Loginsucess          byte = 'L'
	Authenticationfailed byte = 'X'
	Generalfailure       byte = 'F'
	Notaginfield         byte = 'N'
	Operationmodefailure byte = 'O'
	Outofrange           byte = 'R'
)

type mifareClassic struct {
	smartcard.ICard
	Reader
}

//NewReaderMClassic Create Mifare Plus Interface
func NewReaderMClassic(r Reader) (mifare.Classic, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	mc := &mifareClassic{
		ICard:  c,
		Reader: r,
	}
	return mc, nil
}

/**/

func (mc *mifareClassic) Auth(bNr, keyType int, key []byte) ([]byte, error) {
	sector := bNr / 4
	cmd := []byte(authentication)

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(sector))
	if keyType != 0 {
		apdu = append(apdu, 0xBB)
	} else {
		apdu = append(apdu, 0xAA)
	}
	apdu = append(apdu, key...)

	return mc.Reader.Transmit(cmd, apdu)
}

func (mc *mifareClassic) ReadBlocks(bNr, ext int) ([]byte, error) {

	cmd := []byte(readblock)

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(bNr))
	return mc.Reader.Transmit(cmd, apdu)
}

func (mc *mifareClassic) WriteBlock(bNr int, data []byte) ([]byte, error) {

	cmd := []byte(writeblock)

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(bNr))
	apdu = append(apdu, data...)
	return mc.Reader.Transmit(cmd, apdu)
}
