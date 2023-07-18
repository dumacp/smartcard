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

func (r *Reader) TransmitA(apdu []byte) ([]byte, error) {

	data := BuildFrame_SendTypeA(apdu)

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

func (r *Reader) TransmitB(apdu []byte) ([]byte, error) {

	data := BuildFrame_SendTypeA(apdu)

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

	data := BuildFrame_RFPower(on)

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

func (r *Reader) Request() ([]byte, error) {

	data := BuildFrame_Request()

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

func (r *Reader) Anticoll() ([]byte, error) {

	data := BuildFrame_Anticoll()

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

func (r *Reader) RATS() ([]byte, error) {

	data := BuildFrame_RATS()

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

func (r *Reader) ResetSAM() ([]byte, error) {

	data := BuildFrame_ResetSAM()

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

	r.Request()
	r.Anticoll()
	uid, _ := r.RATS()
	cardS := &Card{
		uid:     uid,
		reader:  r,
		typeTag: TAG_TYPEA,
	}
	return cardS, nil
}

// Create New Card interface
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {

	atr, _ := r.ResetSAM()
	cardS := &Card{
		atr:    atr,
		reader: r,
	}
	return cardS, nil
}
