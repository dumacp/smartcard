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

	// fmt.Printf("APDU: % 02X\n", apdu)

	header := BuildHeader__PC_to_RDR_XfrBlock(r.seq, r.slot, len(apdu))

	data, err := BuildFrame(header, apdu)

	if err != nil {
		// fmt.Printf("errorTransmit BuildFrame: % X\n", data)
		return nil, err
	}
	r.seq += 1

	// fmt.Printf("Transmit: % X\n", data)
	response, err := r.dev.SendRecv(data, 3000*time.Millisecond)
	if err != nil {
		// fmt.Printf("errorTransmit response: % X\n", response)
		return nil, err
	}
	if len(response) <= 4 {

		if err := VerifyStatusReponse(response); err != nil {
			// fmt.Printf("errorTransmit response: % X\n", response)
			return nil, err
		}
		response, err = r.dev.SendRecv(FRAME_NACK, 1200*time.Millisecond)
		if err != nil {
			// fmt.Printf("errorTransmit response: % X\n", response)
			return nil, err
		}
	}

	dataResponse, err := GetResponse__RDR_to_PC_DataBlock(response)
	if err != nil {
		// fmt.Printf("errorTransmit response: % X\n", response)
		return nil, err
	}
	// if len(dataResponse) < 2 {
	// 	fmt.Printf("errorTransmit response: % X, (% X)\n", response, data)
	// 	return nil, fmt.Errorf("bad Transmit response: [% X]", dataResponse)
	// }
	// fmt.Printf("Transmit response: % X\n", dataResponse)

	// fmt.Printf("APDU Response: % 02X\n", dataResponse)

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

// Especial
func (r *Reader) IccEspecial() ([]byte, error) {

	apdu := []byte{0x18, 0x10, 0xFF, 0x43, 0x00, 0xFE, 0x00}
	// apdu := []byte{0xFF, 0x11, 0x01, 0xFE}
	header := BuildHeader__PC_to_RDR_IccEspecial(r.seq, r.slot, len(apdu))

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

	dataResponse, err := GetResponse__RDR_to_PC_SlotStatus(response)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

type SerialCommSpeed int

const (
	SerialCommSpeed_9600   SerialCommSpeed = 0x00
	SerialCommSpeed_19200  SerialCommSpeed = 0x01
	SerialCommSpeed_38400  SerialCommSpeed = 0x02
	SerialCommSpeed_57600  SerialCommSpeed = 0x03
	SerialCommSpeed_115200 SerialCommSpeed = 0x04
	SerialCommSpeed_128000 SerialCommSpeed = 0x05
	SerialCommSpeed_230400 SerialCommSpeed = 0x06
)

func CommSpeedBaud2Mode(speed int) (SerialCommSpeed, error) {
	switch speed {
	case 9600:
		return SerialCommSpeed_9600, nil
	case 19200:
		return SerialCommSpeed_19200, nil
	case 38400:
		return SerialCommSpeed_38400, nil
	case 57600:
		return SerialCommSpeed_57600, nil
	case 115200:
		return SerialCommSpeed_115200, nil
	case 128000:
		return SerialCommSpeed_128000, nil
	case 230400:
		return SerialCommSpeed_230400, nil
	default:
		return 0, fmt.Errorf("invalid baud rate: %d", speed)
	}
}

func verifySerialCommSpeed(speed SerialCommSpeed) error {
	switch speed {
	case SerialCommSpeed_9600,
		SerialCommSpeed_19200,
		SerialCommSpeed_38400,
		SerialCommSpeed_57600,
		SerialCommSpeed_115200,
		SerialCommSpeed_128000,
		SerialCommSpeed_230400:
		return nil
	default:
		return fmt.Errorf("invalid serial comm speed: %d", speed)
	}
}

func (r *Reader) FirmwareVersion() ([]byte, error) {
	respEscape, err := r.EscapeCommand([]byte{0xE0, 0, 0, 0x18, 0})
	if err != nil {
		return nil, fmt.Errorf("get firmware version err = %s, %w", err, smartcard.ErrComm)
	}
	if len(respEscape) < 2 {
		return nil, fmt.Errorf("bad response: [% X]", respEscape)
	}
	if respEscape[0] != 0xE1 {
		return nil, fmt.Errorf("bad response: [% X]", respEscape)
	}
	if len(respEscape) < 5 {
		return nil, fmt.Errorf("bad response: [% X]", respEscape)
	}
	return respEscape[4:], nil
}

func (r *Reader) SetSerialCommMode(speed SerialCommSpeed) ([]byte, error) {
	if err := verifySerialCommSpeed(speed); err != nil {
		return nil, fmt.Errorf("set serial comm mode err = %s, %w", err, smartcard.ErrComm)
	}
	respEscape, err := r.EscapeCommand([]byte{0x44, byte(speed)})
	if err != nil {
		return nil, fmt.Errorf("set serial comm mode err = %s, %w", err, smartcard.ErrComm)
	}
	if len(respEscape) < 2 {
		return nil, fmt.Errorf("bad response: [% X]", respEscape)
	}
	if respEscape[0] != 0x90 {
		return nil, fmt.Errorf("bad response: [% X]", respEscape)
	}
	if respEscape[1] != byte(speed) {
		return nil, fmt.Errorf("not equal response (%d): [% X]", speed, respEscape)
	}
	return respEscape, nil
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

	r.seq = 0

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
	// defer time.Sleep(1 * time.Second)
	respEscape, err := r.EscapeCommand([]byte{0xE0, 0, 0, 0x25, 0})
	if err != nil {
		return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrComm)
	}
	if respEscape[len(respEscape)-1] == 0 {
		return nil, fmt.Errorf("without card detect Fail")
	}

	respGetData, err := r.Transmit([]byte{0xFF, 0xCA, 0, 0, 0})
	if err != nil {
		return nil, fmt.Errorf("without card polling Fail")
	}

	respIccPowerOn, err := r.IccPowerOn()
	if err != nil {
		return nil, fmt.Errorf("without card IccPowerOn Fail")
	}
	// fmt.Printf("iccPowerOn response: [% X]\n", respIccPowerOn)

	// respGetData2, err := r.Transmit([]byte{0xFF, 0xCA, 0, 2, 0})
	// if err != nil {
	// 	return nil, fmt.Errorf("without card getData Fail")
	// }
	sak := byte(0xFF)
	// if err := mifare.VerifyResponseIso7816(respGetData2); err == nil {
	// 	if len(respGetData2) > 2 {
	// 		sak = respGetData2[len(respGetData2)-3]
	// 	}
	// }

	if sak == 0xFF && len(respIccPowerOn) > 14 {
		sak = respIccPowerOn[14]
	}

	uid := respGetData[:len(respGetData)-2]

	cardS := &Card{
		uid:    uid,
		reader: r,
		sak:    sak,
		atr:    respIccPowerOn,
	}
	return cardS, nil
}

// ConnectSamCard Create New contact Card interface with T=1
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {
	// if _, err := r.EscapeCommand([]byte{0xE0, 0, 0, 0x2E, 2, 0, 10}); err != nil {
	// 	return nil, fmt.Errorf("connect card err = %s, %w", err, smartcard.ErrComm)
	// }
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

	r.IccEspecial()

	// trama2 := []byte{0xFF, 0x11, 0x01, 0xFE}
	// if _, err := r.Transmit(trama2); err != nil {
	// 	return nil, err
	// }

	return cardS, nil
}

func (r *Reader) SetEnforceISO14443A_4(a bool) error {

	resp, err := r.EscapeCommand([]byte{0xE0, 0, 0, 0x23, 0x00})
	if err != nil {
		return err
	}
	if len(resp) <= 0 {
		return fmt.Errorf("error in response, nil response")
	}
	byteControl := resp[len(resp)-1]

	var apdu1 []byte
	if a {
		byteControl = (byteControl | 0x80)
		apdu1 = []byte{0xE0, 0, 0, 0x23, 0x01, byteControl}
	} else {
		byteControl = (byteControl & 0x7F)
		apdu1 = []byte{0xE0, 0, 0, 0x23, 0x01, byteControl}
	}
	if _, err := r.EscapeCommand(apdu1); err != nil {
		return err
	}
	return nil
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
