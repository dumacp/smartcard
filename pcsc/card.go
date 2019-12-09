/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package pcsc

import (
	//"fmt"
	"errors"

	"github.com/dumacp/smartcard"
	"github.com/ebfe/scard"
)

//Card Interface
type Card interface {
	smartcard.ICard
	ControlApdu(ioctl uint32, apdu []byte) ([]byte, error)
	DiconnectResetCard() error
	DisconnectUnpowerCard() error
	DisconnectEjectCard() error
	TransparentSessionStart() ([]byte, error)
	TransparentSessionStartOnly() ([]byte, error)
	TransparentSessionResetRF() ([]byte, error)
	TransparentSessionEnd() ([]byte, error)
	Switch1444_4() ([]byte, error)
	Switch1444_3() ([]byte, error)
}

type State int

const (
	CONNECTED State = iota
	CONNECTEDDirect
	DISCONNECTED
)

type card struct {
	State State
	*scard.Card
}

func (c *card) DisconnectCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(0x00)
}

func (c *card) DiconnectResetCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(0x01)
}

func (c *card) DisconnectUnpowerCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(0x02)
}

func (c *card) DisconnectEjectCard() error {
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

//Primitive channel to send command
func (c *card) ControlApdu(ioctl uint32, apdu []byte) ([]byte, error) {
	if c.State != CONNECTEDDirect {
		return nil, errors.New("Don't Connect to Card")
	}
	return c.Control(ioctl, apdu)
}

//Get ATR of Card
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

//Transparent Session (PCSC)
func (c *card) TransparentSessionStart() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x04, 0x81, 0x00, 0x84, 0x00}
	return c.Transmit(apdu)
}
func (c *card) TransparentSessionStartOnly() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x81, 0x00}
	return c.Transmit(apdu)
}
func (c *card) TransparentSessionResetRF() ([]byte, error) {
	apdu1 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x83, 0x00}
	resp, err := c.Transmit(apdu1)
	if err != nil {
		return nil, err
	}
	apdu2 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x84, 0x00}
	resp, err = c.Transmit(apdu2)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
func (c *card) TransparentSessionEnd() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x82, 0x00, 0x00}
	return c.Transmit(apdu)
}
func (c *card) Switch1444_4() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}
	return c.Transmit(apdu)
}
func (c *card) Switch1444_3() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	return c.Transmit(apdu)
}
