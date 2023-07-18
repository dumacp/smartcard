package acr128s

import (
	"time"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type Reader struct {
	smartcard.IReader
	mifare.IReaderClassic
	dev        *Device
	readerName string
	seq        int
}

// NewReader Create New Reader interface
func NewReader(dev *Device, readerName string) *Reader {
	r := &Reader{
		dev:        dev,
		readerName: readerName,
	}
	return r
}

func (r *Reader) Transmit(apdu []byte) ([]byte, error) {

	data := SendTypeA(apdu)

	response, err := r.dev.SendRecv(data, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	dataResponse, err := VerifyReponse(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

func (r *Reader) RFPower(on bool) ([]byte, error) {

	data := RFPower(on)

	response, err := r.dev.SendRecv(data, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}

	dataResponse, err := VerifyReponse(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

// Create New Card interface
func (r *Reader) ConnectCard() (smartcard.ICard, error) {

	cardS := &Card{
		uid:    uid,
		reader: r,
	}
	return cardS, nil
}

// Create New Card interface
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {

	cardS := &Card{
		atr:    atr,
		reader: r,
	}
	return cardS, nil
}
