/*
*
package to handle the communication of smartCard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	github.com/ebfe/sCard

/*
*/
package multiiso

import (
	"fmt"

	"github.com/dumacp/smartcard"
)

// Card Interface
type ICard interface {
	smartcard.ICard
	Switch1444_4() ([]byte, error)
	Switch1444_3() ([]byte, error)
}

type State int

const (
	CONNECTED State = iota
	DISCONNECTED
)

type SendMode int

const (
	APDU1443_4      SendMode = 0
	T1TransactionV2 SendMode = 1
	NA              SendMode = 2
	// T0TransactionV2 SendMode = 2
)

type Card struct {
	uuid []byte
	ats  []byte
	sak  byte
	State
	Reader   *Reader
	modeSend SendMode
}

func (c *Card) DisconnectCard() error {
	if c == nil {
		return nil
	}
	_, err := c.Apdu([]byte("q"))
	return err
}

func (c *Card) DisconnectResetCard() error {
	// if _, err := c.Apdu([]byte("q")); err != nil {
	// 	return err
	// }
	newcard, err := c.Reader.ConnectLegacyCard()
	if err != nil {
		return err
	}
	modesend := c.modeSend
	*c = *newcard
	c.modeSend = modesend
	return err
}

func (c *Card) EndTransactionResetCard() error {
	_, err := c.Apdu([]byte("q"))
	c.Reader.ConnectCard()
	return err
}

// Primitive channel to send command
func (c *Card) Apdu(apdu []byte) ([]byte, error) {
	if c.State != CONNECTED {
		return nil, smartcard.Error(smartcard.ErrComm)
	}
	fmt.Printf("APDU: [% 02X]\n", apdu)
	var response []byte
	var err error
	switch c.modeSend {
	case APDU1443_4:
		response, err = c.Reader.SendAPDU1443_4(apdu)
		if err != nil {
			return response, err
		}
	case T1TransactionV2:
		response, err = c.Reader.T1TransactionV2(apdu)
		if err != nil {
			return response, err
		}
		// case T0TransactionV2:
		// 	return c.reader.T0TransactionV2(apdu)

	default:
		response, err = c.Reader.TransmitBinary([]byte{}, apdu)
		if err != nil {
			return response, err
		}
	}
	fmt.Printf("RESP: [% 02X]\n", response[:])
	return response[:], nil

}

// Get ATR of Card
func (c *Card) ATR() ([]byte, error) {
	if c.State != CONNECTED {
		return nil, smartcard.Error(smartcard.ErrComm)
	}
	return nil, nil
}

// Get Data 0x00
func (c *Card) UID() ([]byte, error) {
	uuid := c.uuid
	return uuid, nil
}

// Get Data 0x00
func (c *Card) GetData(data byte) ([]byte, error) {
	resp, err := c.Reader.Transmit([]byte{0x73}, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Card) SAK() byte {
	return c.sak
}

// Get Data 0x01
func (c *Card) ATS() ([]byte, error) {
	ats := c.ats
	return ats, nil
}

func (c *Card) Switch1444_4() ([]byte, error) {
	//apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8F, 0x02, 0x00, 0x04}

	return nil, nil
}

func (c *Card) Switch1444_3() ([]byte, error) {
	//apdu := []byte{0xff, 0xc2, 0x00, 0x02, 0x04, 0x8f, 0x02, 0x00, 0x03}
	return nil, nil
}
