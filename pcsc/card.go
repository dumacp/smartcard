package pcsc

import (
	//"fmt"

	"fmt"

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

//DisconnectCard disconnect card from reader
func (c *card) DisconnectCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(0x00)
}

//DiconnectResetCard disconnect card from reader and reset reader
func (c *card) DiconnectResetCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(0x01)
}

//DisconnectUnpowerCard disconnect card from reader
func (c *card) DisconnectUnpowerCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(0x02)
}

//DisconnectEjectCard disconnect card from reader
func (c *card) DisconnectEjectCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(0x03)
}

//Primitive channel to send command
func (c *card) Apdu(apdu []byte) ([]byte, error) {
	if c.State != CONNECTED {
		return nil, fmt.Errorf("don't Connect to Card, %w", smartcard.ErrComm)
	}
	//log.Printf("APDU: [% X], len: %d", apdu, len(apdu))
	resp, err := c.Transmit(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	//log.Printf("Response: [% X], len: %d", resp, len(resp))
	result := make([]byte, len(resp))
	copy(result, resp)
	return result, nil
}

//Primitive channel to send command
func (c *card) ControlApdu(ioctl uint32, apdu []byte) ([]byte, error) {
	if c.State != CONNECTEDDirect {
		return nil, fmt.Errorf("don't Connect to Card, %w", smartcard.ErrComm)
	}
	resp, err := c.Control(ioctl, apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	result := make([]byte, len(resp))
	copy(result, resp)
	return result, nil
}

//Get ATR of Card
func (c *card) ATR() ([]byte, error) {
	if c.State != CONNECTED {
		return nil, fmt.Errorf("don't Connect to Card, %w", smartcard.ErrComm)
	}
	status, err := c.Status()
	if err != nil {
		return nil, smartcard.Error(err)
	}
	return status.Atr, nil
}

//Get Data 0x00
func (c *card) UID() ([]byte, error) {
	aid := []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}
	uid, err := c.Apdu(aid)
	if err != nil {
		return nil, err
	}
	return uid[:len(uid)-2], nil
}

//Get Data 0x01
func (c *card) ATS() ([]byte, error) {
	aid := []byte{0xFF, 0xCA, 0x01, 0x00, 0x00}
	return c.Apdu(aid)
}

//Transparent Session (PCSC)
func (c *card) TransparentSessionStart() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x04, 0x81, 0x00, 0x84, 0x00}
	resp, err := c.Transmit(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

//TransparentSessionStartOnly start transparent session to send APDU
func (c *card) TransparentSessionStartOnly() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x81, 0x00}
	resp, err := c.Transmit(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

//TransparentSessionResetRF start transparent session to send APDU
func (c *card) TransparentSessionResetRF() ([]byte, error) {
	apdu1 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x83, 0x00}
	resp, err := c.Transmit(apdu1)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	apdu2 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x84, 0x00}
	resp2, err := c.Transmit(apdu2)
	if err != nil {
		return resp2, smartcard.Error(err)
	}
	return resp2, nil
}

//TransparentSessionEnd finish transparent session
func (c *card) TransparentSessionEnd() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x82, 0x00, 0x00}
	resp, err := c.Transmit(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

//Switch1444_4 switch channel reader to send ISO 1444-4 APDU
func (c *card) Switch1444_4() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}
	resp, err := c.Transmit(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

//Switch1444_4 switch channel reader to send ISO 1444-3 APDU
func (c *card) Switch1444_3() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	resp, err := c.Transmit(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}
