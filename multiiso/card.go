/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package multiiso

import (
	//"fmt"
	"errors"

	"github.com/dumacp/smartcard"
)

//Card Interface
type Card interface {
	smartcard.ICard
	DisconnectCard() error
	Switch1444_4() ([]byte, error)
	Switch1444_3() ([]byte, error)
}

type State int

const (
	CONNECTED State = iota
	DISCONNECTED
)

type card struct {
	Uuid []byte
	State
}

func (c *card) DisconnectCard() error {
	return nil
}

//Primitive channel to send command
func (c *card) Apdu(apdu []byte) ([]byte, error) {
	if c.State != CONNECTED {
		return nil, errors.New("Don't Connect to Card")
	}
	return nil, nil
}

//Get ATR of Card
func (c *card) ATR() ([]byte, error) {
	if c.State != CONNECTED {
		return nil, errors.New("Don't Connect to Card")
	}
	return nil, nil
}

//Get Data 0x00
func (c *card) UID() ([]byte, error) {
	aid := []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}
	return c.Apdu(aid)
}

//Get Data 0x01
func (c *card) ATS() ([]byte, error) {
	aid := []byte{0xFF, 0xCA, 0x01, 0x00, 0x00}
	return c.Apdu(aid)
}

func (c *card) Switch1444_4() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}
	return nil, nil
}

func (c *card) Switch1444_3() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	return nil, nil
}
