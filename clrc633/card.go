package clrc633

import (
	"bytes"
	"fmt"

	"github.com/dumacp/smartcard"
)

type TagType int

const (
	TAG_TYPEA TagType = iota
	TAG_TYPEB
	SAM_T1
	TAG_TCL
)

type Card struct {
	smartcard.ICard
	reader      *Reader
	ats         []byte
	uid         []byte
	atr         []byte
	key         []byte
	sak         byte
	typeTag     TagType
	blocknumber byte
}

func (c *Card) blockNumber() byte {
	switch {
	case c.blocknumber&0x03 == 0x03:
		return 0x02
	case c.blocknumber&0x03 == 0x02:
		return 0x03
	}
	return 0x02
}

func (c *Card) Apdu(apdu []byte) ([]byte, error) {
	if c.typeTag == TAG_TCL {
		cmd := make([]byte, 0)
		cmd = append(cmd, c.blockNumber())

		cmd = append(cmd, apdu...)

		response, err := c.reader.Transceive(cmd)
		if err != nil {
			return nil, err
		}
		if response == nil || len(response) < 1 {
			return nil, smartcard.Error(fmt.Errorf("respuesta con error: [% X] ", response))
		}

		if (response[0] & 0x10) == 0x10 {
			listResponse := make([]byte, 0)
			listResponse = append(listResponse, response[1:]...)
			for (response[0] & 0x10) == 0x10 {
				c.blocknumber = response[0]
				frame := []byte{byte(0xA0 + c.blockNumber())}
				response, err = c.reader.Transceive(frame)
				if err != nil {
					return nil, err
				}
				listResponse = append(listResponse, response[2:]...)
			}
			return listResponse, nil
		}
		c.blocknumber = response[0]

		return response[1:], nil
	}
	return c.reader.Transceive(apdu)
}

func (c *Card) ApduWithoutResponse(apdu []byte) ([]byte, error) {
	if c.typeTag == TAG_TCL {
		return c.reader.Transmit(apdu)
	}
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
