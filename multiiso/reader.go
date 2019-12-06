/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	github.com/ebfe/scard

/**/
package multiiso

import (
	"fmt"

	"github.com/dumacp/smartcard"
)

//Reader implement IReader interface
type Reader interface {
	smartcard.IReader
	TransmitAscii([]byte) ([]byte, error)
	TransmitBinary([]byte) ([]byte, error)
	SendDataFrameTransfer([]byte) ([]byte, error)
	SetRegister(register byte, data []byte) error
	GetRegister(register byte) ([]byte, error)
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
type BADResponse []byte

func (e ErrorCode) Error() string {
	return fmt.Sprintf("code error: %X", e)
}

func (e BADResponse) Error() string {
	return fmt.Sprintf("bad response: [% X]", e)
}

type reader struct {
	device       *Device
	readerName   string
	idx          int
	ModeProtocol int
}

//NewReader Create New Reader interface
func NewReader(dev *Device, readerName string, idx int) Reader {
	r := &reader{
		device:     dev,
		readerName: readerName,
		idx:        idx,
	}
	return r
}

//TransmitAscii send in ascii protocol mode
func (*reader) TransmitAscii(data []byte) ([]byte, error) {
	return nil, nil
}

//TransmitBinary send in binary protocol mode
func (*reader) TransmitBinary(data []byte) ([]byte, error) {
	return nil, nil
}

//SendDataFrameTransfer send in format Data Frame Transfer
func (*reader) SendDataFrameTransfer(data []byte) ([]byte, error) {
	apdu := make([]byte, 0)
	apdu = append(apdu, []byte(datatransfer)...)
	apdu = append(apdu, data...)
	return nil, nil
}

//GetRegister send in format Data Frame Transfer
func (*reader) GetRegister(register byte) ([]byte, error) {
	return nil, nil
}

//SetRegister send in format Data Frame Transfer
func (*reader) SetRegister(register byte, data []byte) error {
	return nil
}

//Create New Card interface
func (r *reader) ConnectCard() (smartcard.ICard, error) {
	if r.device.ok {
		return nil, fmt.Errorf("serial device is not ready")
	}
	if r.ModeProtocol != BinaryMode {
		return nil, fmt.Errorf("protocol mode is not binary, ascii mode is not support")
	}

	resp1, err := r.GetRegister(OpMode)
	if err != nil {
		return nil, err
	}
	if resp1[0] != 0x01 {
		return nil, fmt.Errorf("OpMode in reader is not ISO 14443A")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, []byte(highspeedselect)...)
	apdu = append(apdu, 0x88)
	resp2, err := r.TransmitBinary(apdu)
	if err != nil {
		return nil, err
	}
	if len(resp2) <= 1 {
		return nil, ErrorCode(resp2[0])
	}
	if len(resp2) < 5 {
		return nil, BADResponse(resp2)
	}

	card := &card{
		Uuid: resp2[1:5],
	}

	return card, nil
}
