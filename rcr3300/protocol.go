package acr128s

import (
	"fmt"
)

type BaudType int

const (
	BAUD_9600 = iota
	BAUD_19200
	BAUD_38400
	BAUD_57600
	BAUD_115200
)

var FRAME_NACK = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}

func Checksum(data []byte) byte {
	temp := byte(0x00)
	for _, v := range data {
		temp = temp ^ v
	}
	return temp
}

var read_version = []byte{0x21}
var baud_rate = []byte{'#'}
var rf_power = []byte{0x2A}
var request = []byte{'@'}
var anticoll = []byte{'A'}
var rats = []byte{'C'}

func buildFrame(header, data []byte) []byte {

	frame := make([]byte, 0)
	frame = append(frame, 0x02)
	frame = append(frame, 0x00)
	frame = append(frame, byte(len(header)+len(data)))
	frame = append(frame, header...)
	frame = append(frame, data...)

	chk := Checksum(frame[1:])

	frame = append(frame, chk)
	return frame
}

func ReadVersion() []byte {
	return buildFrame(read_version, nil)
}
func SetBaudrate(baudrate BaudType) []byte {
	return buildFrame(baud_rate, []byte{byte(baudrate)})
}
func RFPower(on bool) []byte {
	return buildFrame(rf_power, func(on bool) []byte {
		if on {
			return []byte{0x01}
		}
		return []byte{0x00}
	}(on))
}

func VerifyStatusReponse(statusFrame []byte) error {

	if len(statusFrame) < 4 {
		return fmt.Errorf("length status is wrong, frame: [% X]", statusFrame)
	}
	if statusFrame[0] != 0x02 || statusFrame[len(statusFrame)-1] != 0x03 {
		return fmt.Errorf("bad status frame: [% X]", statusFrame)
	}
	if statusFrame[2] != statusFrame[1] {
		return fmt.Errorf("bad status chacksum frame: [% X]", statusFrame)
	}

	switch {
	case statusFrame[1] == 0x00 && statusFrame[2] == 0x00:
		return nil
	case statusFrame[1] == 0xFF && statusFrame[2] == 0xFF:
		return fmt.Errorf("checksum error frame: [% X]", statusFrame)
	case statusFrame[1] == 0xFE && statusFrame[2] == 0xFE:
		return fmt.Errorf("length error frame: [% X]", statusFrame)
	case statusFrame[1] == 0xFD && statusFrame[2] == 0xFD:
		return fmt.Errorf("ETX error frame: [% X]", statusFrame)
	case statusFrame[1] == 0x99 && statusFrame[2] == 0x99:
		return fmt.Errorf("timeout error frame: [% X]", statusFrame)
	}

	return fmt.Errorf("unkown error frame: [% X]", statusFrame)
}

func GetResponse__RDR_to_PC_DataBlock(frame []byte) ([]byte, error) {

	if len(frame) < 13 {
		return nil, fmt.Errorf("wrong len frame: [% X]", frame)
	}
	if frame[0] != 0x02 && frame[len(frame)-1] != 0x3 {
		return nil, fmt.Errorf("bad RDR_to_PC_DataBlock frame: [% X]", frame)
	}
	if Checksum(frame[1:len(frame)-2]) != frame[len(frame)-2] {
		return nil, fmt.Errorf("checksum error frame: [% X]", frame)
	}

	if len(frame) <= 13 {
		return nil, nil
	}

	dest := make([]byte, len(frame)-13)

	copy(dest, frame[11:len(frame)-2])

	return dest, nil
}

func GetResponse__RDR_to_PC_Escape(frame []byte) ([]byte, error) {

	if len(frame) < 13 {
		return nil, fmt.Errorf("wrong len frame: [% X]", frame)
	}
	if frame[0] != 0x02 && frame[len(frame)-1] != 0x3 {
		return nil, fmt.Errorf("bad RDR_to_PC_Escape frame: [% X]", frame)
	}
	if Checksum(frame[1:len(frame)-2]) != frame[len(frame)-2] {
		return nil, fmt.Errorf("checksum error frame: [% X]", frame)
	}

	if len(frame) <= 13 {
		return nil, nil
	}

	dest := make([]byte, len(frame)-13)

	copy(dest, frame[11:len(frame)-2])

	return dest, nil
}

func GetResponse__RDR_to_PC_SlotStatus(frame []byte) ([]byte, error) {

	if len(frame) < 13 {
		return nil, fmt.Errorf("wrong len frame: [% X]", frame)
	}
	if frame[0] != 0x02 && frame[len(frame)-1] != 0x3 {
		return nil, fmt.Errorf("bad RDR_to_PC_SlotStatus frame: [% X]", frame)
	}
	if Checksum(frame[1:len(frame)-2]) != frame[len(frame)-2] {
		return nil, fmt.Errorf("checksum error frame: [% X]", frame)
	}

	if len(frame) <= 13 {
		return nil, nil
	}

	dest := make([]byte, len(frame)-13)

	copy(dest, frame[11:len(frame)-2])

	return dest, nil
}
