/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	github.com/ebfe/scard

/**/
package multiiso

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

//Reader implement IReader interface
type Reader interface {
	smartcard.IReader
	mifare.IReaderClassic
	// ConnectCard() (smartcard.ICard, error)
	// ConnectSamCard() (smartcard.ICard, error)

	Transmit([]byte, []byte) ([]byte, error)
	TransmitAscii([]byte, []byte) ([]byte, error)
	TransmitBinary([]byte, []byte) ([]byte, error)
	SendDataFrameTransfer([]byte) ([]byte, error)
	SetRegister(register byte, data []byte) error
	GetRegister(register byte) ([]byte, error)
	SetModeProtocol(mode int)
	// SetTransmitProtocol(transmitProto TransmitProto)
	SendAPDU1443_4(data []byte) ([]byte, error)
	SendSAMDataFrameTransfer(data []byte) ([]byte, error)
	T1TransactionV2(data []byte) ([]byte, error)
	// T0TransactionV2(data []byte) ([]byte, error)
	SetChainning(chainning bool)
}

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

type reader struct {
	device       *Device
	readerName   string
	idx          int
	ModeProtocol int
	// transmitProto TransmitProto
	transmit  transmitfunc
	chainning bool
}

//NewReader Create New Reader interface
func NewReader(dev *Device, readerName string, idx int) Reader {
	r := &reader{
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

func (r *reader) SetModeProtocol(mode int) {
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

//Transmit send data byte to reader in actual mode
func (r *reader) Transmit(cmd, data []byte) ([]byte, error) {
	return r.transmit(cmd, data)
}

//TransmitAscii send in ascii protocol mode
func (r *reader) TransmitAscii(cmd, data []byte) ([]byte, error) {
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

//TransmitBinary send in binary protocol mode
func (r *reader) TransmitBinary(cmd, data []byte) ([]byte, error) {
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

//SendDataFrameTransfer send in format Data Frame Transfer
func (r *reader) SendDataFrameTransfer(data []byte) ([]byte, error) {
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

//SendAPDU1443_4 send in format Data Frame Transfer
func (r *reader) SendAPDU1443_4(data []byte) ([]byte, error) {
	cmd := make([]byte, 0)
	cmd = append(cmd, byte(len(data)+1))
	cmd = append(cmd, 0x0F)
	cmd = append(cmd, r.blockNumber())
	cmd = append(cmd, data...)

	response, err := r.SendDataFrameTransfer(cmd)
	if err != nil {
		return nil, err
	}
	if response == nil || len(response) < 2 {
		return nil, smartcard.Error(fmt.Errorf("respuesta con error: [% X] ", response))
	}

	if (response[1] & 0x10) == 0x10 {
		listResponse := make([]byte, 0)
		listResponse = append(listResponse, response[2:]...)
		for (response[1] & 0x10) == 0x10 {
			frame := []byte{0x01, 0x0F, byte(0xA0 + r.blockNumber())}
			response, err = r.SendDataFrameTransfer(frame)
			if err != nil {
				return nil, err
			}
			listResponse = append(listResponse, response[2:]...)
		}
		return listResponse, nil
	}

	return response[2:], nil
}

func (r *reader) SendSAMDataFrameTransfer(data []byte) ([]byte, error) {
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

func (r *reader) T1TransactionV2(data []byte) ([]byte, error) {
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

// func (r *reader) T0TransactionV2(data []byte) ([]byte, error) {
// 	trama := make([]byte, 0)

// 	trama = append(trama, byte(len(data)&0xFF))
// 	trama = append(trama, 0xDF)                    // APDU T=1 Transaction. OptionByte V2
// 	trama = append(trama, byte(len(data)>>8&0xFF)) // Downlink length MSB (1 byte)
// 	trama = append(trama, 0x13)                    // Timeout
// 	trama = append(trama, 0x86)                    // Transmission factor byte (1 byte)
// 	trama = append(trama, 0x00)                    // Return length

// 	trama = append(trama, data...)

// 	return r.SendSAMDataFrameTransfer(trama)

// }

//GetRegister send in format Data Frame Transfer
func (r *reader) GetRegister(register byte) ([]byte, error) {
	cmd := []byte(readEEPROMregister)
	apdu := make([]byte, 0)

	apdu = append(apdu, register)
	return r.transmit(cmd, apdu)
}

//SetRegister send in format Data Frame Transfer
func (r *reader) SetRegister(register byte, data []byte) error {
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

//Create New Card interface
func (r *reader) ConnectCard() (smartcard.ICard, error) {
	if !r.device.Ok {
		return nil, fmt.Errorf("serial device is not ready, %w", smartcard.ErrComm)
	}
	// if r.ModeProtocol != BinaryMode {
	// 	return nil, fmt.Errorf("protocol mode is not binary, ascii mode is not support")
	// }

	// resp1, err := r.GetRegister(OpMode)
	// if err != nil {
	// 	return nil, err
	// }
	// if resp1[0] != 0x01 {
	// 	return nil, fmt.Errorf("OpMode in reader is not ISO 14443A")
	// }

	cmd := []byte(highspeedselect)
	apdu := make([]byte, 0)
	apdu = append(apdu, 0x88)
	resp2, err := r.transmit(cmd, apdu)
	if err != nil {
		return nil, err
	}
	if len(resp2) <= 1 {
		code := resp2[0]
		return nil, ErrorCode(code)
		// return nil, smartcard.Error(ErrorCode(code))
	}
	if len(resp2) < 5 {
		bad := resp2[:]
		return nil, smartcard.Error(BadResponse(bad))
	}

	var uid []byte
	var ats []byte

	switch {
	case len(resp2) >= 0x10 && resp2[0] == 0x01 && (resp2[8]&0x20 == 0x20):
		uid = make([]byte, 7)
		copy(uid, resp2[1:8])
		ats = make([]byte, len(resp2[9:]))
		copy(ats, resp2[9:])
	case len(resp2) >= 0x10 && resp2[0] == 0x00 && (resp2[6]&0x20 == 0x20):
		uid = make([]byte, 4)
		copy(uid, resp2[1:5])
		ats = make([]byte, len(resp2[6:]))
		copy(ats, resp2[6:])
	case len(resp2) >= 0x10 && resp2[0] == 0x01 && (resp2[8]&0x20 == 0x20):
		uid = make([]byte, 7)
		copy(uid, resp2[1:8])
		ats = make([]byte, len(resp2[9:]))
		copy(ats, resp2[5:])
	case len(resp2) >= 0x10 && (resp2[8]&0x20 == 0x20):
		uid = make([]byte, 4)
		copy(uid, resp2[1:5])
		ats = make([]byte, len(resp2[9:]))
		copy(ats, resp2[5:])
	default:
		if len(resp2) >= 6 {
			uid = make([]byte, 4)
			copy(uid, resp2[1:5])
			ats = make([]byte, len(resp2[5:]))
			copy(ats, resp2[5:])
		}
	}

	card := &card{
		uuid:   uid,
		ats:    ats,
		reader: r,
	}

	return card, nil
}

//Create New Card interface
func (r *reader) ConnectSamCard() (smartcard.ICard, error) {
	if !r.device.Ok {
		return nil, fmt.Errorf("serial device is not ready, %w", smartcard.ErrComm)
	}
	// if r.ModeProtocol != BinaryMode {
	// 	return nil, fmt.Errorf("protocol mode is not binary, ascii mode is not support")
	// }

	// _, err := r.GetRegister(OpMode)
	// if err != nil {
	// 	return nil, err
	// }

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

	card := &card{
		reader:   r,
		modeSend: T1TransactionV2,
	}

	// if r.transmitProto == T0 {
	// 	card.modeSend = T0TransactionV2
	// } else {
	// 	card.modeSend = T1TransactionV2
	// }

	return card, nil
}

func (r *reader) SetChainning(chainning bool) {
	r.chainning = chainning
}

func (r *reader) blockNumber() byte {
	ret := byte(0x02)
	if r.chainning {
		ret = 0x03
	}
	r.chainning = !r.chainning

	return ret
}
