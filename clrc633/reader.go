package clrc633

import (
	"fmt"
	"time"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type Reader struct {
	dev        *Device
	readerName string
}

// NewReader Create New Reader interface
func NewReader(dev *Device, readerName string) *Reader {
	r := &Reader{
		dev:        dev,
		readerName: readerName,
	}
	return r
}

func (r *Reader) Transceive(apdu []byte) ([]byte, error) {

	return r.dev.Transceive(apdu, 300*time.Millisecond)
}

func (r *Reader) Transmit(apdu []byte) ([]byte, error) {

	return r.dev.Transceive(apdu, 0)
}

func (r *Reader) Request() (byte, error) {

	return r.dev.Request(0x52, 60*time.Millisecond)
}

func (r *Reader) Anticoll() ([]byte, error) {
	return r.dev.Anticoll(30 * time.Millisecond)
}

func (r *Reader) Anticoll2() ([]byte, error) {
	return r.dev.Anticoll2(30 * time.Millisecond)
}

func (r *Reader) Select(data []byte) (byte, error) {
	return r.dev.Select(data, 300*time.Millisecond)
}

func (r *Reader) Select2(data []byte) (byte, error) {
	return r.dev.Select2(data, 30*time.Millisecond)
}

func (r *Reader) LoadKey(key []byte) error {
	return r.dev.LoadKey(key, 30*time.Millisecond)
}

func (r *Reader) Auth(keyType, block int, uid []byte) error {
	return r.dev.Auth(keyType, block, uid, 120*time.Millisecond)
}

func (r *Reader) RATS() ([]byte, error) {
	apdu := []byte{0xE0, 0x80}
	return r.dev.Transceive(apdu, 100*time.Millisecond)
}

// ConnectSamCard_T0 ConnectCard connect card with protocol T=1.
func (r *Reader) ConnectSamCard_T0() (smartcard.ICard, error) {
	panic("not implemented") // TODO: Implement
}

// ConnectSamCard_Tany ConnectCard connect card with protocol T=any.
func (r *Reader) ConnectSamCard_Tany() (smartcard.ICard, error) {
	panic("not implemented") // TODO: Implement
}

// ConnectCard ConnectCard connect card with protocol T=1.
func (r *Reader) ConnectCard() (smartcard.ICard, error) {
	return r.ConnectLegacyCard()
}

// Create New Card typeA interface
func (r *Reader) ConnectLegacyCard() (*Card, error) {

	if _, err := r.Request(); err != nil {
		return nil, err
	}
	respAnticoll, err := r.Anticoll()
	if err != nil {
		return nil, err
	}
	// uid := func(data []byte) []byte {
	// 	temp := make([]byte, len(data))
	// 	for i, v := range data[:] {
	// 		temp[len(temp)-i-1] = v
	// 	}
	// 	return temp
	// }(respAnticoll[:len(respAnticoll)-1])

	uid := make([]byte, 0)
	uid = append(uid, respAnticoll[:len(respAnticoll)-1]...)

	tSelect := time.Now()
	defer func() { fmt.Printf("time select: %v\n", time.Since(tSelect)) }()
	sak, err := r.Select(respAnticoll)
	if err != nil {
		return nil, err
	}

	cardS := &Card{
		sak:     sak,
		reader:  r,
		typeTag: TAG_TYPEA,
	}
	if sak == 0x04 {
		respAnticoll, err := r.Anticoll2()
		if err != nil {
			return nil, err
		}
		// uid_last := func(data []byte) []byte {
		// 	temp := make([]byte, len(data))
		// 	for i, v := range data[:] {
		// 		temp[len(temp)-i-1] = v
		// 	}
		// 	return temp
		// }(respAnticoll[:len(respAnticoll)-1])

		uid = append(uid, respAnticoll[:len(respAnticoll)-1]...)

		sak2, err := r.Select2(respAnticoll)
		if err != nil {
			return nil, err
		}
		ats, err := r.RATS()
		if err != nil {
			return nil, err
		}
		cardS.typeTag = TAG_TCL
		cardS.ats = ats
		cardS.sak = sak2
	}

	cardS.uid = func(uid []byte) []byte {
		if len(uid) >= 8 {
			fmt.Printf("long UID: % X\n", uid)
			return uid[len(uid)-7:]
		}
		return uid
	}(uid)

	return cardS, nil
}

// Create New Card typeB interface
func (r *Reader) ConnectCardB() (smartcard.ICard, error) {

	// r.Request()
	uid, err := r.Anticoll()
	if err != nil {
		return nil, err
	}
	ats, err := r.RATS()
	if err != nil {
		return nil, err
	}
	cardS := &Card{
		uid: func(uid []byte) []byte {
			if len(uid) >= 8 {
				return uid[1:]
			}
			return uid
		}(uid),
		ats:     ats,
		reader:  r,
		typeTag: TAG_TYPEB,
	}
	return cardS, nil
}

// ConnectSamCard ConnectSamCard connect card with protocol T=1.
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {
	return nil, ErrorUnsupported
}

func (r *Reader) ConnectMifareClassic() (mifare.Classic, error) {
	return nil, nil
}
