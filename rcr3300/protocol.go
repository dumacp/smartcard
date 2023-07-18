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
var resetSam = []byte{'R'}
var sendTypeA = []byte{'A'}

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

func BuildFrame_ReadVersion() []byte {
	return buildFrame(read_version, nil)
}
func SetBaudrate(baudrate BaudType) []byte {
	return buildFrame(baud_rate, []byte{byte(baudrate)})
}
func BuildFrame_RFPower(on bool) []byte {
	return buildFrame(rf_power, func(on bool) []byte {
		if on {
			return []byte{0x01}
		}
		return []byte{0x00}
	}(on))
}

func BuildFrame_SendTypeA(apdu []byte) []byte {
	return buildFrame(sendTypeA, apdu)
}

func BuildFrame_Anticoll() []byte {
	return buildFrame(anticoll, nil)
}

func BuildFrame_Request() []byte {
	return buildFrame(request, nil)
}

func BuildFrame_RATS() []byte {
	return buildFrame(rats, nil)
}

func BuildFrame_ResetSAM() []byte {
	return buildFrame(resetSam, nil)
}

func VerifyReponse(frame []byte) ([]byte, error) {

	if len(frame) < 5 {
		return nil, fmt.Errorf("length status is wrong, frame: [% X]", frame)
	}
	if frame[0] != 0x02 {
		return nil, fmt.Errorf("bad frame: [% X]", frame)
	}
	if frame[len(frame)-1] != Checksum(frame[1:len(frame)-1]) {
		return nil, fmt.Errorf("bad chacksum frame: [% X]", frame)
	}

	switch {
	case frame[2] == 0x01 && frame[3] == 0x00:
		return nil, nil
	case frame[2] > 0x01 && len(frame[3:len(frame)-1]) == int(frame[2]):
		response := make([]byte, 0)
		response = append(response, frame[3:len(frame)-1]...)
		return response, nil
	}

	return nil, fmt.Errorf("unkown error frame: [% X]", frame)
}
