/*
*
package to handle the communication of "omnikey/multi-iso" reader

projects on which it is based:

	https://github.com/dumacp/smartcard

/*
*/
package multiiso

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/dumacp/smartcard"
)

// // Reader implement IReader interface
// type Reader interface {
// 	smartcard.IReader
// 	mifare.IReaderClassic

// 	Transmit([]byte, []byte) ([]byte, error)
// 	TransmitAscii([]byte, []byte) ([]byte, error)
// 	TransmitBinary([]byte, []byte) ([]byte, error)
// 	SendDataFrameTransfer([]byte) ([]byte, error)
// 	SetRegister(register byte, data []byte) error
// 	GetRegister(register byte) ([]byte, error)
// 	SetModeProtocol(mode int)
// 	// SetTransmitProtocol(transmitProto TransmitProto)
// 	SendAPDU1443_4(data []byte) ([]byte, error)
// 	SendSAMDataFrameTransfer(data []byte) ([]byte, error)
// 	T1TransactionV2(data []byte) ([]byte, error)
// 	// T0TransactionV2(data []byte) ([]byte, error)
// 	SetChainning(chainning bool)
// }

const (
	//BinaryMode protocol binary mode
	BinaryMode int = iota
	//AsciiMode protocol acsii mode
	AsciiMode
)

const (
	ProtocolConf1   byte = 0x0B
	ProtocolConf2   byte = 0x13
	ProtocolConf3   byte = 0x1B
	OpMode          byte = 0x0E
	BaudRate        byte = 0x0C
	TMRhigh         byte = 0x11
	TMRlow          byte = 0x10
	ResetOffTime    byte = 0x14
	ResetCoveryTime byte = 0x015
)

const (
	highspeedselect     string = "h"
	readEEPROMregister  string = "rp"
	writeEEPROMregister string = "wp"
	sympleselect        string = "s"
	reset               string = "x"
	datatransfer        string = "t"
)

type TransmitProto int

const (
	T0 TransmitProto = iota
	T1
)

type ErrorCode byte
type BadResponse []byte
type BadChecsum []byte
type NilResponse int

func (e ErrorCode) Error() string {
	return fmt.Sprintf("code error: %X", byte(e))
}
func (e ErrorCode) Code() byte {
	return byte(e)
}
func (e BadResponse) Error() string {
	return fmt.Sprintf("bad response: [% X]", []byte(e))
}
func (e BadChecsum) Error() string {
	eb := []byte(e)
	return fmt.Sprintf("bad checksum: [% X], %X", eb, eb[len(eb)-3])
}
func (e NilResponse) Error() string {
	return "nil response"
}

type Reader struct {
	device       *Device
	readerName   string
	idx          int
	ModeProtocol int
	// transmitProto TransmitProto
	transmit    transmitfunc
	chainning   bool
	blocknumber byte
}

// NewReader Create New Reader interface
func NewReader(dev *Device, readerName string, idx int) *Reader {
	r := &Reader{
		device:     dev,
		readerName: readerName,
		idx:        idx,
	}
	r.transmit = r.TransmitBinary
	return r
}

func checksum(data []byte) byte {
	sum := byte(0)
	for _, v := range data {
		sum = sum ^ v
	}
	// fmt.Printf("checksum: %X; data: [% X]\n", sum, data)
	return sum
}

type transmitfunc func([]byte, []byte) ([]byte, error)

// SetModeProtocol set mode protocol to communication (0: binary, 1: ascii)
func (r *Reader) SetModeProtocol(mode int) {
	if mode == BinaryMode {
		r.transmit = r.TransmitBinary
		r.ModeProtocol = BinaryMode
		r.device.mode = 0
	} else {
		r.transmit = r.TransmitAscii
		r.ModeProtocol = AsciiMode
		r.device.mode = 1
	}
}

// func (r *reader) SetTransmitProtocol(transmitProto TransmitProto) {
// 	r.transmitProto = transmitProto
// }

// Transmit send data byte to reader in actual mode
func (r *Reader) Transmit(cmd, data []byte) ([]byte, error) {
	return r.transmit(cmd, data)
}

// TransmitAscii send in ascii protocol mode
func (r *Reader) TransmitAscii(cmd, data []byte) ([]byte, error) {
	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	if data != nil {
		apdu = append(apdu, strings.ToUpper(hex.EncodeToString(data))...)
	}
	// fmt.Printf("reqs TransmitAscii: [%s]\n", apdu)
	resp1, err := r.device.SendRecv(apdu)
	// fmt.Printf("resp TransmitAscii: [%s]\n", resp1)
	// fmt.Printf("resp TransmitAscii: %q\n", resp1)
	if err != nil {
		return nil, smartcard.Error(err)
	}
	return resp1, nil
}

// TransmitBinary send in binary protocol mode
func (r *Reader) TransmitBinary(cmd, data []byte) ([]byte, error) {
	apdu := make([]byte, 0)
	apdu = append(apdu, 0x02)
	apdu = append(apdu, byte(r.idx))
	apdu = append(apdu, byte(len(data)+len(cmd)))
	apdu = append(apdu, cmd...)
	if data != nil {
		apdu = append(apdu, data...)
	}
	apdu = append(apdu, checksum(apdu[1:]))
	apdu = append(apdu, 0x03)
	// fmt.Printf("apdu TransmitBinary: [% X]\n", apdu)
	resp1, err := r.device.SendRecv(apdu)
	// fmt.Printf("resp TransmitBinary: [% X]\n", resp1)
	if err != nil {
		return nil, smartcard.Error(err)
	}
	if err := verifyresponse(resp1); err != nil {
		return nil, smartcard.Error(err)
	}

	if resp1[2] == 0x01 {
		return []byte{resp1[3]}, nil
	}
	return resp1[3 : len(resp1)-2], nil
}

func verifyresponse(data []byte) error {
	if data == nil || len(data) <= 0 {
		return smartcard.ErrComm
	}
	if data[0] != 0x02 || data[len(data)-1] != 0x03 {
		return BadResponse(data)
	}
	if len(data) < 6 {
		return BadResponse(data)
	}
	if checksum(data[1:len(data)-2]) != data[len(data)-2] {
		return BadChecsum(data)
	}
	return nil
}

// SendDataFrameTransfer send in format Data Frame Transfer
func (r *Reader) SendDataFrameTransfer(data []byte) ([]byte, error) {
	cmd := make([]byte, 0)
	cmd = append(cmd, []byte(datatransfer)...)
	apdu := make([]byte, 0)
	apdu = append(apdu, data...)
	resp1, err := r.TransmitBinary(cmd, apdu)
	if err != nil {
		return nil, err
	}
	return resp1, nil
}

// SendAPDU1443_4 send in format Data Frame Transfer
func (r *Reader) SendAPDU1443_4(data []byte) ([]byte, error) {
	cmd := make([]byte, 0)
	cmd = append(cmd, byte(len(data)+1))
	cmd = append(cmd, 0x0F)
	cmd = append(cmd, r.blockNumber())

	cmd = append(cmd, data...)

	response, err := r.SendDataFrameTransfer(cmd)
	if err != nil {
		return nil, err
	}
	if response == nil || len(response) < 3 {
		return nil, smartcard.Error(fmt.Errorf("respuesta con error: [% X] ", response))
	}

	if (response[1] & 0x10) == 0x10 {
		listResponse := make([]byte, 0)
		listResponse = append(listResponse, response[2:]...)
		for (response[1] & 0x10) == 0x10 {
			r.blocknumber = response[1]
			frame := []byte{0x01, 0x0F, byte(0xA0 + r.blockNumber())}
			response, err = r.SendDataFrameTransfer(frame)
			if err != nil {
				return nil, err
			}
			if response == nil || len(response) < 3 {
				return nil, smartcard.Error(fmt.Errorf("respuesta con error: [% X] ", response))
			}
			listResponse = append(listResponse, response[2:]...)
		}
		return listResponse, nil
	}
	r.blocknumber = response[1]

	return response[2:], nil
}

// SendSAMDataFrameTransfer send APDU to SAM device in special socket ("e" command)
func (r *Reader) SendSAMDataFrameTransfer(data []byte) ([]byte, error) {
	innerData := make([]byte, 0)

	// innerData = append(innerData, 0x65)
	innerData = append(innerData, data...)

	response, err := r.Transmit([]byte{0x65}, innerData)
	// response, err := r.Transmit([]byte{}, innerData)
	if err != nil {
		time.Sleep(600 * time.Millisecond) // restore time
		return nil, err
	}

	if len(response) < 3 {
		if len(response) == 1 && response[0] == 0 {
			return response, nil
		}
		time.Sleep(600 * time.Millisecond) // restore time
		return nil, smartcard.Error(fmt.Errorf("respuesta con error: [% X] ", response))
	}

	return response[3:], nil
}

// T1TransactionV2 function to send wrapped frames T1 to SAM device through "e" command
func (r *Reader) T1TransactionV2(data []byte) ([]byte, error) {
	trama := make([]byte, 0)

	trama = append(trama, byte(len(data)&0xFF))
	trama = append(trama, 0xDF)                    // APDU T=1 Transaction. OptionByte V2
	trama = append(trama, byte(len(data)>>8&0xFF)) // Downlink length MSB (1 byte)
	trama = append(trama, 0x13)                    // Timeout
	trama = append(trama, 0x86)                    // Transmission factor byte (1 byte)
	trama = append(trama, 0x00)                    // Return length

	trama = append(trama, data...)

	return r.SendSAMDataFrameTransfer(trama)

}

// GetRegister send in format Data Frame Transfer
func (r *Reader) GetRegister(register byte) ([]byte, error) {
	cmd := []byte(readEEPROMregister)
	apdu := make([]byte, 0)

	apdu = append(apdu, register)
	return r.transmit(cmd, apdu)
}

// SetRegister send in format Data Frame Transfer
func (r *Reader) SetRegister(register byte, data []byte) error {
	cmd := []byte(writeEEPROMregister)
	apdu := make([]byte, 0)

	apdu = append(apdu, register)
	apdu = append(apdu, data...)
	_, err := r.transmit(cmd, apdu)
	if err != nil {
		return err
	}
	return nil
}

// Create New Card interface
func (r *Reader) ConnectCard() (smartcard.ICard, error) {
	c, err := r.ConnectLegacyCard()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Create New Card interface
func (r *Reader) ConnectLegacyCard() (*Card, error) {
	if !r.device.Ok {
		return nil, fmt.Errorf("serial device is not ready, %w", smartcard.ErrComm)
	}

	cmd := []byte(highspeedselect)
	apdu := make([]byte, 0)
	apdu = append(apdu, 0x88)
	resp2, err := r.transmit(cmd, apdu)
	if err != nil {
		return nil, err
	}
	if len(resp2) <= 1 {
		code := resp2[0]
		// fmt.Println("sale///////")
		return nil, ErrorCode(code)
		// return nil, smartcard.Error(ErrorCode(code))
	}
	if len(resp2) < 5 {
		bad := resp2[:]
		return nil, smartcard.Error(BadResponse(bad))
	}

	var uid []byte
	var ats []byte
	sak := byte(0xFF)

	switch {
	case len(resp2) > 9 && resp2[0] == 0x01 && (resp2[8]&0x20 == 0x20):
		uid = make([]byte, 7)
		copy(uid, resp2[1:8])
		ats = make([]byte, len(resp2[9:]))
		sak = resp2[8]
		copy(ats, resp2[9:])
	case len(resp2) > 9 && resp2[0] == 0x01:
		uid = make([]byte, 7)
		copy(uid, resp2[1:8])
		ats = make([]byte, len(resp2[9:]))
		sak = resp2[8]
		copy(ats, resp2[10:])
	case len(resp2) > 8 && resp2[0] == 0x01:
		uid = make([]byte, 7)
		copy(uid, resp2[1:8])
		ats = make([]byte, 0)
		sak = resp2[9]
	case len(resp2) > 6 && resp2[0] == 0x00 && (resp2[5]&0x20 == 0x20):
		uid = make([]byte, 4)
		copy(uid, resp2[1:5])
		sak = resp2[5]
		ats = make([]byte, len(resp2[6:]))
		copy(ats, resp2[6:])
	case len(resp2) > 6 && resp2[0] == 0x00:
		uid = make([]byte, 4)
		copy(uid, resp2[1:5])
		sak = resp2[5]
		ats = make([]byte, len(resp2[6:]))
		copy(ats, resp2[7:])
	case len(resp2) > 5 && resp2[0] == 0x00:
		uid = make([]byte, 4)
		copy(uid, resp2[1:5])
		sak = resp2[5]
		ats = make([]byte, 0)
	default:
		switch {
		case len(resp2) > 6:
			uid = make([]byte, 4)
			copy(uid, resp2[1:5])
			sak = resp2[5]
			ats = make([]byte, len(resp2[6:]))
			copy(ats, resp2[7:])
		case len(resp2) > 5:
			uid = make([]byte, 4)
			copy(uid, resp2[1:5])
			sak = resp2[5]
			ats = make([]byte, 0)
		case len(resp2) > 4:
			uid = make([]byte, 4)
			copy(uid, resp2[0:4])
			ats = make([]byte, 0)
		}
	}

	card := &Card{
		uuid:     uid,
		ats:      ats,
		sak:      sak,
		Reader:   r,
		modeSend: APDU1443_4,
	}

	return card, nil
}

// Create New Card interface
func (r *Reader) ConnectSamCard_T0() (smartcard.ICard, error) {
	return nil, fmt.Errorf("not supported")
}

// Create New Card interface
func (r *Reader) ConnectSamCard_Tany() (smartcard.ICard, error) {
	c, err := r.ConnectSamCard()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Create New Card interface
func (r *Reader) ConnectSamCard() (smartcard.ICard, error) {
	if !r.device.Ok {
		return nil, fmt.Errorf("serial device is not ready, %w", smartcard.ErrComm)
	}

	trama1 := []byte{00, 0x91, 0x00, 0x10, 0x11, 00}
	// if r.transmitProto == T0 {
	// 	trama1[1] = 0xC1
	// }
	if _, err := r.SendSAMDataFrameTransfer(trama1); err != nil {
		// 	return nil, err
		// }
		time.Sleep(100 * time.Millisecond)
		trama3 := []byte{00, 0x92, 0x00, 0x10, 0x11, 00}
		if _, err := r.SendSAMDataFrameTransfer(trama3); err != nil {
			return nil, err
		}
		return nil, err
	}
	// fmt.Printf("resp1: [%s]\n", resp1)

	/**
	 * PPS
	 */
	// trama2 := []byte{0x04, 0xE0, 0x00, 0x43, 0x18, 0x04, 0xFF, 0x11, 0x01, 0xEF}
	trama2 := []byte{0x04, 0xE0, 0x00, 0x13, 0x11, 0x04, 0xFF, 0x11, 0x86, 0x68}
	if _, err := r.SendSAMDataFrameTransfer(trama2); err != nil {
		return nil, err
	}

	card := &Card{
		Reader:   r,
		modeSend: T1TransactionV2,
	}

	return card, nil
}

func (r *Reader) SetChainning(chainning bool) {
	r.chainning = chainning
}

func (r *Reader) blockNumber() byte {
	switch {
	case r.blocknumber&0x03 == 0x03:
		return 0x02
	case r.blocknumber&0x03 == 0x02:
		return 0x03
	}
	return 0x02
}
