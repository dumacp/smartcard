package pcsc

import (
	//"fmt"

	"fmt"

	"github.com/dumacp/smartcard"
	"github.com/ebfe/scard"
)

// Card Interface
type Card interface {
	smartcard.ICard
	ControlApdu(ioctl uint32, apdu []byte) ([]byte, error)
	EndTransaction() error
	EndTransactionResetCard() error
	DisconnectResetCard() error
	DisconnectUnpowerCard() error
	DisconnectEjectCard() error
	TransparentSessionStart() ([]byte, error)
	TransparentSessionStartOnly() ([]byte, error)
	TransparentSessionResetRF() ([]byte, error)
	TransparentSessionEnd() ([]byte, error)
	Switch1444_4() ([]byte, error)
	Switch1444_3() ([]byte, error)
}

// Connect state
type State int

const (
	CONNECTED State = iota
	CONNECTEDDirect
	DISCONNECTED
)

type Scard struct {
	State State
	*scard.Card
	sak byte
	atr []byte
}

// EndTransactionn End transaccion with card with disposition type LeaveCard
func (c *Scard) EndTransaction() error {
	c.State = DISCONNECTED
	return c.Card.EndTransaction(scard.LeaveCard)
}

// EndTransactionResetCard End transaccion with card with disposition type ResetCard
func (c *Scard) EndTransactionResetCard() error {
	c.State = DISCONNECTED
	return c.Card.EndTransaction(scard.ResetCard)
}

// DisconnectCard Disconnect card from context with card with disposition type LeaveCard
func (c *Scard) DisconnectCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(scard.LeaveCard)
}

// DiconnectResetCard Disconnect card from context with card with disposition type ResetCard
func (c *Scard) DisconnectResetCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(scard.ResetCard)
}

// DisconnectUnpowerCard Disconnect card from context with card with disposition type UnpowerCard
func (c *Scard) DisconnectUnpowerCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(scard.UnpowerCard)
}

// DisconnectEjectCard Disconnect card from context with card with disposition type EjectCard
func (c *Scard) DisconnectEjectCard() error {
	c.State = DISCONNECTED
	return c.Disconnect(scard.EjectCard)
}

// Apdu Primitive function (SCardTransmit) to send command to card
func (c *Scard) Apdu(apdu []byte) ([]byte, error) {
	if c.State != CONNECTED {
		return nil, fmt.Errorf("don't Connect to Card, %w", smartcard.ErrComm)
	}
	fmt.Printf("APDU: [% X], len: %d\n", apdu, len(apdu))
	resp, err := c.Transmit(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	fmt.Printf("Response: [% X], len: %d\n", resp, len(resp))
	result := make([]byte, len(resp))
	copy(result, resp)
	return result, nil
}

// ControlApdu Primitive function (SCardControl) to send command to card
func (c *Scard) ControlApdu(ioctl uint32, apdu []byte) ([]byte, error) {
	if c.State != CONNECTEDDirect {
		return nil, fmt.Errorf("don't Connect to Card, %w", smartcard.ErrComm)
	}
	fmt.Printf("control APDU: [% X], len: %d\n", apdu, len(apdu))
	resp, err := c.Control(ioctl, apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	fmt.Printf("Response: [% X], len: %d\n", resp, len(resp))
	result := make([]byte, len(resp))
	copy(result, resp)
	return result, nil
}

// ATR Get ATR from Card
func (c *Scard) ATR() ([]byte, error) {
	if c.State != CONNECTED {
		return nil, fmt.Errorf("don't Connect to Card, %w", smartcard.ErrComm)
	}
	status, err := c.Status()
	if err != nil {
		return nil, smartcard.Error(err)
	}
	c.atr = make([]byte, len(status.Atr))
	copy(c.atr, status.Atr)
	return c.atr, nil
}

// GetData GetData with param INS
func (c *Scard) GetData(ins byte) ([]byte, error) {
	aid := []byte{0xFF, 0xCA, ins, 0x00, 0x00}
	uid, err := c.Apdu(aid)
	if err != nil {
		return nil, err
	}
	return uid[:len(uid)-2], nil
}

// UID GetData with INS = 0x00
func (c *Scard) UID() ([]byte, error) {
	aid := []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}
	uid, err := c.Apdu(aid)
	if err != nil {
		return nil, err
	}
	return uid[:len(uid)-2], nil
}

// ATS GetData with INS = 0x01
func (c *Scard) ATS() ([]byte, error) {
	aid := []byte{0xFF, 0xCA, 0x01, 0x00, 0x00}
	return c.Apdu(aid)
}

func (c *Scard) SAK() byte {
	if len(c.atr) > 14 {
		return c.atr[14]
	}
	aid := []byte{0xFF, 0xCA, 0x00, 0x02, 0x00}
	resp, err := c.Apdu(aid)
	if err != nil {
		return 0xFF
	}
	if len(resp) < 3 || (resp[len(resp)-2] != 0x90 || resp[len(resp)-1] != 0x00) {
		/**
			if resp, err := c.ATR(); err == nil {
				if len(resp) > 14 {
					return resp[14]
				}
			}
		/**/
		return 0xFF
	}
	return resp[len(resp)-3]
}

// Transparent Session (PCSC)
func (c *Scard) TransparentSessionStart() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x04, 0x81, 0x00, 0x84, 0x00}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// TransparentSessionStartOnly start transparent session to send APDU
func (c *Scard) TransparentSessionStartOnly() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x81, 0x00}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// TransparentSessionResetRF start transparent session to send APDU
func (c *Scard) TransparentSessionResetRF() ([]byte, error) {
	apdu1 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x83, 0x00}
	resp, err := c.Apdu(apdu1)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	apdu2 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x84, 0x00}
	resp2, err := c.Apdu(apdu2)
	if err != nil {
		return resp2, smartcard.Error(err)
	}
	return resp2, nil
}

// TransparentSessionEnd finish transparent session
func (c *Scard) TransparentSessionEnd() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x82, 0x00, 0x00}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// Switch1444_4 switch channel reader to send ISO 1444-4 APDU
func (c *Scard) Switch1444_4() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// Switch1444_4 switch channel reader to send ISO 1444-3 APDU
func (c *Scard) Switch1444_3() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}
