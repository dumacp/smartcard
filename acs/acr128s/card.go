package acr128s

import (
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type Card struct {
	// smartcard.ICard
	reader *Reader
	ats    []byte
	uid    []byte
	atr    []byte
	sak    byte
}

func (c *Card) Apdu(apdu []byte) ([]byte, error) {
	return c.reader.Transmit(apdu)
}

func (c *Card) ATR() ([]byte, error) {

	return c.atr, nil
}

func (c *Card) UID() ([]byte, error) {
	return c.uid, nil
}

func (c *Card) SAK() byte {
	return c.sak
}

func (c *Card) GetData(data byte) ([]byte, error) {
	return c.reader.Transmit([]byte{0xFF, 0xCA, 0, data, 0})
}

func (c *Card) ATS() ([]byte, error) {
	resp, err := c.reader.Transmit([]byte{0xFF, 0xCA, 1, 0, 0})
	if err != nil {
		// if c.sak == 0xFF {
		// 	c.sak = 0x01
		// }
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		// if c.sak == 0xFF {
		// 	c.sak = 0x01
		// }
		return nil, err
	}

	return resp[:len(resp)-2], nil
}

// Transparent Session (PCSC)
func (c *Card) TransparentSessionStart() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x04, 0x81, 0x00, 0x84, 0x00}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// TransparentSessionStartOnly start transparent session to send APDU
func (c *Card) TransparentSessionStartOnly() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x81, 0x00}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// TransparentSessionResetRF start transparent session to send APDU
func (c *Card) TransparentSessionResetRF() ([]byte, error) {
	// apdu1 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x83, 0x00}
	// resp, err := c.Apdu(apdu1)
	// if err != nil {
	// 	return resp, smartcard.Error(err)
	// }
	apdu2 := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x84, 0x00}
	resp2, err := c.Apdu(apdu2)
	if err != nil {
		return resp2, smartcard.Error(err)
	}
	return resp2, nil
}

// TransparentSessionEnd finish transparent session
func (c *Card) TransparentSessionEnd() ([]byte, error) {
	apdu := []byte{0xFF, 0xC2, 0x00, 0x00, 0x02, 0x82, 0x00, 0x00}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// Switch1444_4 switch channel reader to send ISO 1444-4 APDU
func (c *Card) Switch1444_4() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

// Switch1444_4 switch channel reader to send ISO 1444-3 APDU
func (c *Card) Switch1444_3() ([]byte, error) {
	apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	resp, err := c.Apdu(apdu)
	if err != nil {
		return resp, smartcard.Error(err)
	}
	return resp, nil
}

func (c *Card) DisconnectCard() error {
	return nil
}

func (c *Card) DisconnectResetCard() error {
	return nil
}

func (c *Card) DisconnectEjectCard() error {
	return nil
}

func (c *Card) DisconnectUnpowerCard() error {
	return nil
}

func (c *Card) EndTransactionResetCard() error {
	return nil
}
