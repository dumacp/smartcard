/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package smartcard

import (
	//"fmt"
	"errors"
	"github.com/ebfe/scard"
)

//Card Interface
type Card interface {
	Apdu(apdu []byte)	([]byte, error)
	ATR()			([]byte, error)
	DisconnectCard()	error
	DiconnectResetCard()	error
	DisconnectUnpowerCard()	error
	DisconnectEjectCard()	error
}

type State int

const (
    CONNECTED	State = iota
    DISCONNECTED
)
type card struct {
	State	State
	*scard.Card
}

func (c *card) DisconnectCard() (error) {
	c.State = DISCONNECTED
	return c.Disconnect(0x00)
}

func (c *card) DiconnectResetCard() (error) {
	c.State = DISCONNECTED
	return c.Disconnect(0x01)
}

func (c *card) DisconnectUnpowerCard() (error) {
	c.State = DISCONNECTED
	return c.Disconnect(0x02)
}

func (c *card) DisconnectEjectCard() (error) {
	c.State = DISCONNECTED
	return c.Disconnect(0x03)
}

//Primitive channel to send command
func (c *card) Apdu(apdu []byte) ([]byte, error) {
	if c.State != CONNECTED {
		return nil, errors.New("Don't Connect to Card")
	}
	return c.Transmit(apdu)
}

func (c *card) ATR() ([]byte, error) {
	if c.State != CONNECTED {
		return nil, errors.New("Don't Connect to Card")
	}
	status, err := c.Status()
	if err != nil {
		return nil, err
	}
	return status.Atr, nil
}

