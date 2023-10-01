package clrc633

import (
	"bytes"

	"github.com/dumacp/smartcard"
)

type TagType int

const (
	TAG_TYPEA TagType = iota
	TAG_TYPEB
	SAM_T1
)

type Card struct {
	smartcard.ICard
	reader  *Reader
	ats     []byte
	uid     []byte
	atr     []byte
	key     []byte
	sak     byte
	typeTag TagType
}

func (c *Card) Apdu(apdu []byte) ([]byte, error) {
	return c.reader.Transceive(apdu)
}

func (c *Card) ApduWithoutResponse(apdu []byte) ([]byte, error) {
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

func (c *Card) ATS() ([]byte, error) {
	return c.ats, nil
}

func (c *Card) DisconnectCard() error {
	return nil
}

func (c *Card) MFLoadKey(key []byte) error {

	if len(c.key) > 0 && bytes.Equal(c.key, key) {
		return nil
	}
	c.key = key
	return c.reader.LoadKey(key)
}

func (c *Card) MFAuthent(keyType, block int) error {
	return c.reader.Auth(keyType, block, c.uid)
}
