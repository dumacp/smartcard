package acr128s

import (
	"fmt"
	"time"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type Reader struct {
	dev        *Device
	readerName string
	slot       Slot
	seq        int
}

// NewReader Create New Reader interface
func NewReader(dev *Device, readerName string, slot Slot) *Reader {
	r := &Reader{
		dev:        dev,
		readerName: readerName,
		slot:       slot,
	}
	return r
}

// Transmit Primitive function transceive to send apdu
func (r *Reader) Transmit(apdu []byte) ([]byte, error) {

	header := BuildHeader__PC_to_RDR_XfrBlock(r.seq, r.slot, len(apdu))

	data, err := BuildFrame(header, apdu)

	if err != nil {
		return nil, err
	}
	r.seq += 1

	response, err := r.dev.SendRecv(data, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if len(response) <= 4 {

		if err := VerifyStatusReponse(response); err != nil {
			return nil, err
		}
		response, err = r.dev.SendRecv(FRAME_NACK, 100*time.Millisecond)
		if err != nil {
			return nil, err
		}
	}

	dataResponse, err := GetResponse__RDR_to_PC_DataBlock(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

// EscapeCommand Primitive function to send Control commands
func (r *Reader) EscapeCommand(apdu []byte) ([]byte, error) {

	header := BuildHeader__PC_to_RDR_Escape(r.seq, SLOT_PICC, len(apdu))
	data, err := BuildFrame(header, apdu)

	if err != nil {
		return nil, err
	}

	response, err := r.dev.SendRecv(data, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	r.seq += 1

	if len(response) <= 4 {
		if err := VerifyStatusReponse(response); err != nil {
			return nil, err
		}
		response, err = r.dev.SendRecv(FRAME_NACK, 100*time.Millisecond)
		if err != nil {
			return nil, err
		}
	}

	dataResponse, err := GetResponse__RDR_to_PC_Escape(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

// IccPowerOff Power off contact card
func (r *Reader) IccPowerOff() ([]byte, error) {

	header := BuildHeader__PC_to_RDR_IccPowerOff(r.seq, r.slot)

	data, err := BuildFrame(header, nil)

	if err != nil {
		return nil, err
	}
	r.seq += 1

	response, err := r.dev.SendRecv(data, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if len(response) <= 4 {

		if err := VerifyStatusReponse(response); err != nil {
			return nil, err
		}
		response, err = r.dev.SendRecv(FRAME_NACK, 100*time.Millisecond)
		if err != nil {
			return nil, err
		}
	}

	dataResponse, err := GetResponse__RDR_to_PC_SlotStatus(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

// IccPowerOn Power on contact card
func (r *Reader) IccPowerOn() ([]byte, error) {

	header := BuildHeader__PC_to_RDR_IccPowerOn(r.seq, r.slot)

	data, err := BuildFrame(header, nil)

	if err != nil {
		return nil, err
	}
	r.seq += 1

	response, err := r.dev.SendRecv(data, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if len(response) <= 4 {

		if err := VerifyStatusReponse(response); err != nil {
			return nil, err
		}
		response, err = r.dev.SendRecv(FRAME_NACK, 100*time.Millisecond)
		if err != nil {
			return nil, err
		}
	}

	dataResponse, err := GetResponse__RDR_to_PC_SlotStatus(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

// ConnectCard Create New Card interface with T=1
func (r *Reader) ConnectCard() (smartcard.ICard, error) {
	respEscape, err := r.EscapeCommand([]byte{0xE0, 0, 0, 0x25, 0})
	if err != nil {
		return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrComm)
	}
	if respEscape[len(respEscape)-1] == 0 {
		return nil, fmt.Errorf("without card")
	}

	respGetData, err := r.Transmit([]byte{0xFF, 0xCA, 0, 0, 0})
	if err != nil {
		return nil, fmt.Errorf("without card")
	}

	respGetData2, err := r.Transmit([]byte{0xFF, 0xCA, 0, 2, 0})
	if err != nil {
		return nil, fmt.Errorf("without card")
	}
	sak := byte(0xFF)
	if err := mifare.VerifyResponseIso7816(respGetData2); err == nil {
		if len(respGetData2) > 2 {
			sak = respGetData2[len(respGetData2)-3]
		}
	}

	uid := respGetData[:len(respGetData)-2]

	cardS := &Card{
		uid:    uid,
		reader: r,
		sak:    sak,
	}
	return cardS, nil
}

// ConnectSamCard Create New contact Card interface with T=1
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {
	if _, err := r.EscapeCommand([]byte{0xE0, 0, 0, 0x2E, 2, 0, 10}); err != nil {
		return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrComm)
	}
	respIccPowerOn, err := r.IccPowerOn()
	if err != nil {
		return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrComm)
	}
	if len(respIccPowerOn) < 1 || respIccPowerOn[0] != 0x3B {
		return nil, fmt.Errorf("bad response: [% X]", respIccPowerOn)
	}

	atr := respIccPowerOn[:]

	cardS := &Card{
		atr:    atr,
		reader: r,
	}
	return cardS, nil
}

// ConnectSamCard_T0 ConnectCard connect card with protocol T=1.
func (r *Reader) ConnectSamCard_T0() (smartcard.ICard, error) {
	panic("not implemented") // TODO: Implement
}

// ConnectSamCard_Tany ConnectCard connect card with protocol T=any.
func (r *Reader) ConnectSamCard_Tany() (smartcard.ICard, error) {
	panic("not implemented") // TODO: Implement
}

func (r *Reader) ConnectMifareClassic() (mifare.Classic, error) {
	panic("not implemented") // TODO: Implement
}
