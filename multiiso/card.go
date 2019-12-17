/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package multiiso

import (
	"errors"
	"fmt"

	"github.com/dumacp/smartcard"
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

type card struct {
	uuid []byte
	ats  []byte
	State
	reader Reader
}

func (c *card) DisconnectCard() error {
	_, err := c.Apdu([]byte("q"))
	return err
}

//Primitive channel to send command
func (c *card) Apdu(apdu []byte) ([]byte, error) {
	if c.State != CONNECTED {
		return nil, fmt.Errorf("Don't Connect to Card")
	}
	return c.reader.TransmitBinary([]byte{}, apdu)
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
	return c.uuid, nil
}

//Get Data 0x01
func (c *card) ATS() ([]byte, error) {
	return c.ats, nil
}

func (c *card) Switch1444_4() ([]byte, error) {
	//apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}
	return nil, nil
}

func (c *card) Switch1444_3() ([]byte, error) {
	//apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	return nil, nil
}
