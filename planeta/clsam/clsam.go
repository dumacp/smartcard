package clsam

import (
	"fmt"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type ClSam struct {
	smartcard.ICard
}

// ConnectSam Create Sam
func ConnectSam(r smartcard.IReader) (*ClSam, error) {

	c, err := r.ConnectSamCard()
	if err != nil {
		return nil, err
	}
	sam := &ClSam{
		ICard: c,
	}
	return sam, nil
}

// ClSam Create SAM from Card
func NewClSam(c smartcard.ICard) *ClSam {
	sam := new(ClSam)
	sam.ICard = c
	return sam
}

func (s *ClSam) Apdu(data []byte) ([]byte, error) {
	fmt.Printf("sam apdu: [% X]\n", data)
	resp, err := s.ICard.Apdu(data)
	if err != nil {
		return resp, err
	}
	fmt.Printf("sam sw: [% X]\n", resp)

	return resp, nil
}

func (s *ClSam) Serial() ([]byte, error) {

	apdu := []byte{0x00, 0xC0, 0x02, 0xA0, 0x08}
	resp, err := s.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}

	return resp[:len(resp)-2], nil
}

func (s *ClSam) OsInfo() ([]byte, error) {
	apdu := []byte{0x00, 0xC0, 0x02, 0xBE, 0x10}
	resp, err := s.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}

	return resp[:len(resp)-2], nil
}

func (s ClSam) PinVerify(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("len error in pin (len must equal to 8)")
	}
	apdu := []byte{0x00, 0x20, 0x0C, 0x07, 0x08}

	apdu = append(apdu, data...)
	resp, err := s.Apdu(apdu)
	if err != nil {
		return err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return err
	}

	return nil
}

func (s *ClSam) GetKey(keyfile []byte) (int, error) {
	apdu := []byte{0x00, 0xC4, 0x00, 0x00}
	apdu = append(apdu, byte(len(keyfile)))
	apdu = append(apdu, keyfile...)
	resp, err := s.Apdu(apdu)
	if err != nil {
		return 0, err
	}
	if len(resp) < 2 || resp[0] != 0x61 {
		return 0, fmt.Errorf("bad response: [% X]", resp)
	}
	// if err := mifare.VerifyResponseIso7816(resp); err != nil {
	// 	return nil, err
	// }

	return int(resp[1] & 0x00FF), nil
}

func (s *ClSam) GetResponse(lenResponse int) ([]byte, error) {
	apdu := []byte{0x00, 0xC0, 0x00, 0x00}
	apdu = append(apdu, byte(lenResponse))
	resp, err := s.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}

	return resp[:len(resp)-2], nil
}

func (s *ClSam) ResetChannel(data []byte) error {
	cmd := []byte{0x00, 0x72, 0x81, 0x01}
	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	apdu = append(apdu, byte(len(data)))
	apdu = append(apdu, data...)
	resp, err := s.Apdu(apdu)
	if err != nil {
		return err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return err
	}

	return nil
}

func (s *ClSam) SelectFile(fileId []byte) error {
	cmd := []byte{0x03, 0xA4, 0x00, 0x0C}
	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	apdu = append(apdu, byte(len(fileId)))
	apdu = append(apdu, fileId...)
	resp, err := s.Apdu(apdu)
	if err != nil {
		return err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return err
	}

	return nil
}

func (s *ClSam) ReadBinary(lenData int) ([]byte, error) {
	cmd := []byte{0x03, 0xB0, 0x00, 0x00}
	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	apdu = append(apdu, byte(lenData))
	resp, err := s.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}
	return resp[:len(resp)-2], nil
}

func (s *ClSam) PutFile(fileId, data []byte) ([]byte, error) {
	cmd := []byte{0x00, 0xC7}
	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	apdu = append(apdu, fileId...)
	apdu = append(apdu, byte(len(fileId)+len(data)))
	apdu = append(apdu, data...)
	resp, err := s.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(resp); err != nil {
		return nil, err
	}
	return resp[:len(resp)-2], nil
}
