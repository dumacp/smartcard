package acr128s

import (
	"encoding/binary"
	"fmt"
)

type Slot int

const (
	SLOT_SAM  = 2
	SLOT_ICC  = 1
	SLOT_PICC = 0
)

var FRAME_NACK = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03}

func Checksum(data []byte) byte {
	temp := byte(0x00)
	for _, v := range data {
		temp = temp ^ v
	}
	return temp
}

type BuildHeader func() []byte

func BuildHeader__PC_to_RDR_IccEspecial(seq int, slot Slot, lenApdu int) func() []byte {

	return func() []byte {
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(lenApdu))
		header := []byte{0x61}
		header = append(header, lenBytes...)
		header = append(header, byte(int(slot)))
		header = append(header, byte(0x05))
		header = append(header, []byte{0x01, 0, 0}...)
		return header
	}
}

func BuildHeader__PC_to_RDR_IccPowerOn(seq int, slot Slot) func() []byte {

	return func() []byte {
		lenBytes := make([]byte, 4)
		header := []byte{0x62}
		header = append(header, lenBytes...)
		header = append(header, byte(int(slot)))
		header = append(header, byte(seq))
		header = append(header, []byte{0, 0, 0}...)
		return header
	}
}

func BuildHeader__PC_to_RDR_IccPowerOff(seq int, slot Slot) func() []byte {

	return func() []byte {
		lenBytes := make([]byte, 4)
		header := []byte{0x63}
		header = append(header, lenBytes...)
		header = append(header, byte(int(slot)))
		header = append(header, byte(seq))
		header = append(header, []byte{0, 0, 0}...)
		return header
	}
}

func BuildHeader__PC_to_RDR_XfrBlock(seq int, slot Slot, ledApdu int) func() []byte {

	return func() []byte {
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(ledApdu))
		header := []byte{0x6F}
		header = append(header, lenBytes...)
		header = append(header, byte(int(slot)))
		header = append(header, byte(0x01))
		header = append(header, byte(0x04))
		header = append(header, []byte{0, 0}...)
		return header
	}
}

func BuildHeader__PC_to_RDR_Escape(seq int, slot Slot, ledApdu int) func() []byte {

	return func() []byte {
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(ledApdu))
		header := []byte{0x6B}
		header = append(header, lenBytes...)
		header = append(header, byte(int(slot)))
		header = append(header, byte(seq))
		header = append(header, []byte{0, 0, 0}...)
		return header
	}
}

func BuildFrame(header BuildHeader, apdu []byte) ([]byte, error) {

	if len(header()) != 10 {
		return nil, fmt.Errorf("length header is wrong, header: [% X]", header())
	}
	frame := make([]byte, 0)
	frame = append(frame, 0x02)
	frame = append(frame, header()...)
	frame = append(frame, apdu...)

	chk := Checksum(frame[1:])

	frame = append(frame, chk)
	frame = append(frame, 0x03)
	return frame, nil
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
