package acr128s

import (
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
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}

	return resp[:len(resp)-2], nil
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
