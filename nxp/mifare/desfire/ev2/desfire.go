/**
package with common functions to manage a Desfire TAG

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	https://github.com/ebfe/scard
	https://github.com/dumacp/smartcard

/**/
package ev2

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/dumacp/smartcard"
)

type EVmode int

const (
	D40 EVmode = iota
	EV1
	EV2
)

type KeyType int

func (k KeyType) Int() int {
	return int(k)
}

type SecondAppIndicator int

func (k SecondAppIndicator) Int() int {
	return int(k)
}

const (
	TDEA2 KeyType = iota
	TDEA3
	AES
)
const (
	TargetPrimaryApp SecondAppIndicator = iota
	TargetSecondaryApp
)

//Desfire desfire card
type Desfire struct {
	smartcard.ICard
	rndA         []byte
	rndB         []byte
	ti           []byte
	keyEnc       []byte
	keyMac       []byte
	cmdCtr       uint16
	lastKey      int
	evMode       EVmode
	iv           []byte
	currentAppID int
	pcdCap2      []byte
	pdCap2       []byte
	block        cipher.Block
	blockMac     cipher.Block
	ksesAuthEnc  []byte
	ksesAuthMac  []byte
}

//NewDesfire Create Desfire from Card
func NewDesfire(c smartcard.ICard) *Desfire {
	d := new(Desfire)
	d.ICard = c
	return d
}

//VerifyResponse function to verify response APDU
func VerifyResponse(resp []byte) error {

	if len(resp) > 0 && (resp[0] == 0x00 || resp[0] == 0xAF) {
		return nil
	}
	if len(resp) <= 0 {
		return errors.New("error in response: nil response")
	}
	return fmt.Errorf("error in response:, code error: %X, response: [% X]", resp[0], resp)
}

func (d *Desfire) GetModeEV() EVmode {
	return d.evMode
}
