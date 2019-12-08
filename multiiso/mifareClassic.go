package multiiso

import (
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

const (
	authentication string = "l"
)

type mifareClassic struct {
	smartcard.ICard
}

//ConnectMclassic Create Mifare Plus Interface
func ConnectMclassic(r smartcard.IReader) (mifare.Classic, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	mc := &mifareClassic{
		c,
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
	apdu = append(append, key...)

	return nil, nil
}

func (mc *mifareClassic) ReadBlocks(bNr, ext int) ([]byte, error) {

	return nil, nil
}

func (mc *mifareClassic) WriteBlock(bNr int, data []byte) ([]byte, error) {

	return nil, nil
}
