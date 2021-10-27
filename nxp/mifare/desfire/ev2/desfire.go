package ev2

import (
	"crypto/cipher"
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

type desfire struct {
	smartcard.ICard
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

//SamAV2 Create SAM from Card
func NewDesfire(c smartcard.ICard) Desfire {
	d := new(desfire)
	d.ICard = c
	return d
}

func VerifyResponse(resp []byte) error {

	if len(resp) > 0 && (resp[0] == 0x00 || resp[0] == 0xAF) {
		return nil
	}

	return fmt.Errorf("error in response:, code error: %X, response: [% X]", resp[0], resp)

}
