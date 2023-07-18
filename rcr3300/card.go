package acr128s

import (
	"github.com/dumacp/smartcard"
)

type TagType int

const (
	TAG_TYPEA TagType = iota
	TAG_TYPEB
)

type Card struct {
	smartcard.ICard
	reader  *Reader
	ats     []byte
	uid     []byte
	atr     []byte
	typeTag TagType
}

func (c *Card) Apdu(apdu []byte) ([]byte, error) {
	switch c.typeTag {
	case TAG_TYPEB:
		return c.reader.TransmitB(apdu)
	default:
		return c.reader.TransmitA(apdu)
	}
}

func (c *Card) ATR() ([]byte, error) {

	return c.atr, nil
}

func (c *Card) UID() ([]byte, error) {
	return c.uid, nil
}

func (c *Card) ATS() ([]byte, error) {
	return c.ats, nil
}

func (c *Card) DisconnectCard() error {
	return nil
}
