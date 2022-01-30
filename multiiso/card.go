/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package multiiso

import (
	"github.com/nmelo/smartcard"
)

//Card Interface
type Card interface {
	smartcard.ICard
	Switch1444_4() ([]byte, error)
	Switch1444_3() ([]byte, error)
}

type State int

const (
	CONNECTED State = iota
	DISCONNECTED
)

type SendMode int

const (
	APDU1443_4      SendMode = 0
	T1TransactionV2 SendMode = 1
	// T0TransactionV2 SendMode = 2
)

type card struct {
	uuid []byte
	ats  []byte
	sak  byte
	State
	reader   Reader
	modeSend SendMode
}

func (c *card) DisconnectCard() error {
	_, err := c.Apdu([]byte("q"))
	return err
}

//Primitive channel to send command
func (c *card) Apdu(apdu []byte) ([]byte, error) {
	if c.State != CONNECTED {
		return nil, smartcard.Error(smartcard.ErrComm)
	}
	switch c.modeSend {
	case APDU1443_4:
		return c.reader.SendAPDU1443_4(apdu)
	case T1TransactionV2:
		return c.reader.T1TransactionV2(apdu)
		// case T0TransactionV2:
		// 	return c.reader.T0TransactionV2(apdu)
	}
	response, err := c.reader.TransmitBinary([]byte{}, apdu)
	if err != nil {
		return response, err
	}
	return response[:], nil

}

//Get ATR of Card
func (c *card) ATR() ([]byte, error) {
	if c.State != CONNECTED {
		return nil, smartcard.Error(smartcard.ErrComm)
	}
	return nil, nil
}

//Get Data 0x00
func (c *card) UID() ([]byte, error) {
	uuid := c.uuid
	return uuid, nil
}

//Get Data 0x01
func (c *card) ATS() ([]byte, error) {
	ats := c.ats
	return ats, nil
}

func (c *card) Switch1444_4() ([]byte, error) {
	//apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}

	return nil, nil
}

func (c *card) Switch1444_3() ([]byte, error) {
	//apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	return nil, nil
}
