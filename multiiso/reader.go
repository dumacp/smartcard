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

	"github.com/dumacp/smartcard/nxp/mifare"

	"github.com/dumacp/smartcard"
)

//Reader implement IReader interface
type Reader interface {
	smartcard.IReader
	mifare.IReaderClassic
	Transmit([]byte, []byte) ([]byte, error)
	TransmitAscii([]byte, []byte) ([]byte, error)
	TransmitBinary([]byte, []byte) ([]byte, error)
	SendDataFrameTransfer([]byte) ([]byte, error)
	SetRegister(register byte, data []byte) error
	GetRegister(register byte) ([]byte, error)
	SetModeProtocol(mode int)
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
	return fmt.Sprintf("nil response")
}

type reader struct {
	device       *Device
	readerName   string
	idx          int
	ModeProtocol int
	transmit     transmitfunc
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
	resp1, err := r.device.SendRecv(apdu)
	fmt.Printf("resp TransmitAscii: [% X]\n", resp1)
	fmt.Printf("resp TransmitAscii: %q\n", resp1)
	if err != nil {
		return nil, err
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
	fmt.Printf("apdu TransmitBinary: [% X]\n", apdu)
	resp1, err := r.device.SendRecv(apdu)
	fmt.Printf("resp TransmitBinary: [% X]\n", resp1)
	if err != nil {
		return nil, err
	}
	if err := verifyresponse(resp1); err != nil {
		return nil, err
	}
	return resp1[3 : len(resp1)-2], nil
}

func verifyresponse(data []byte) error {
	if data == nil || len(data) <= 0 {
		return NilResponse(-1)
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
		return nil, fmt.Errorf("serial device is not ready")
	}
	// if r.ModeProtocol != BinaryMode {
	// 	return nil, fmt.Errorf("protocol mode is not binary, ascii mode is not support")
	// }

	_, err := r.GetRegister(OpMode)
	if err != nil {
		return nil, err
	}
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
	}
	if len(resp2) < 5 {
		bad := resp2[:]
		return nil, BadResponse(bad)
	}

	uid := make([]byte, 4)
	copy(uid, resp2[1:5])
	card := &card{
		uuid:   uid,
		reader: r,
	}

	return card, nil
}
