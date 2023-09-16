package rcr3300

import (
	"fmt"
	"time"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type Reader struct {
	smartcard.IReader
	mifare.IReaderClassic
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

func (r *Reader) TransmitA(apdu []byte) ([]byte, error) {

	data := BuildFrame_SendTypeA(apdu)

	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
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

	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
	if err != nil {
		return nil, err
	}

	dataResponse, err := VerifyReponse(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

func (r *Reader) TransmitSAM_T1(apdu []byte) ([]byte, error) {

	data := BuildFrame_SendSAM(apdu)

	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
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

	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
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

	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
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
	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
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
	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
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
	timeout := func() time.Duration {
		if r.dev.timeout <= 100*time.Millisecond {
			return 100 * time.Millisecond
		}
		return r.dev.timeout
	}

	response, err := r.dev.SendRecv(data, timeout())
	if err != nil {
		return nil, err
	}
	dataResponse, err := VerifyReponse(response)
	if err != nil {
		return nil, err
	}

	pps := []byte{0xFF, 0x11, 0x01, 0xEF}
	ppsResponse, err := r.dev.SendRecv(BuildFrame_SendSAM(pps), timeout())
	if err != nil {
		return nil, err
	}
	_, err = VerifyReponse(ppsResponse)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

// Create New Card typeA interface
func (r *Reader) ConnectCard() (smartcard.ICard, error) {

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
				fmt.Printf("long UID: % X\n", uid)
				return uid[len(uid)-7:]
			}
			return uid
		}(uid),
		ats:     ats,
		reader:  r,
		typeTag: TAG_TYPEA,
	}
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

// Create New Card interface
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {

	atr, _ := r.ResetSAM()
	cardS := &Card{
		atr:     atr,
		reader:  r,
		typeTag: SAM_T1,
	}
	return cardS, nil
}
