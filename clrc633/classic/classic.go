package classic

import (
	"fmt"

	"github.com/dumacp/smartcard/clrc633"
	"github.com/dumacp/smartcard/nxp/mifare"
)

/**/

type MifareClassic struct {
	card *clrc633.Card
}

func NewMifareClassic(card *clrc633.Card) mifare.Classic {
	return &MifareClassic{
		card: card,
	}
}

func (mc *MifareClassic) transfer(bNr int) error {
	cmd := []byte{0xB0, byte(bNr)}
	if resp, err := mc.card.Apdu(cmd); err != nil {
		return err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return fmt.Errorf("no Ack, code: [%X]", resp[0])
	}
	return nil
}

func (mc *MifareClassic) Inc(bNr int, data []byte) error {
	cmd := []byte{0xC1, byte(bNr)}
	if resp, err := mc.card.Apdu(cmd); err != nil {
		return err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return fmt.Errorf("no Ack, code: [%X]", resp[0])
	}

	if resp, err := mc.card.ApduWithoutResponse(data); err != nil {
		return err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return fmt.Errorf("no Ack, code: [%X]", resp[0])
	}
	return mc.transfer(bNr)
}

func (mc *MifareClassic) Dec(bNr int, data []byte) error {
	cmd := []byte{0xC0, byte(bNr)}
	if resp, err := mc.card.Apdu(cmd); err != nil {
		return err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return fmt.Errorf("no Ack, code: [%X]", resp[0])
	}

	if resp, err := mc.card.ApduWithoutResponse(data); err != nil {
		return err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return fmt.Errorf("no Ack, code: [%X]", resp[0])
	}

	return mc.transfer(bNr)
}

func (mc *MifareClassic) Copy(bNr int, dstBnr int) error {
	cmd := []byte{0xC2, byte(bNr)}
	if resp, err := mc.card.Apdu(cmd); err != nil {
		return err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return fmt.Errorf("no Ack, code: [%X]", resp[0])
	}

	if resp, err := mc.card.ApduWithoutResponse(make([]byte, 4)); err != nil {
		return err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return fmt.Errorf("no Ack, code: [%X]", resp[0])
	}
	return mc.transfer(dstBnr)
}

func (mc *MifareClassic) Apdu(apdu []byte) ([]byte, error) {
	return mc.card.Apdu(apdu)
}

func (mc *MifareClassic) ATR() ([]byte, error) {
	return mc.card.ATR()
}

func (mc *MifareClassic) UID() ([]byte, error) {
	return mc.card.UID()
}

func (mc *MifareClassic) SAK() byte {
	return mc.card.SAK()
}

func (mc *MifareClassic) ATS() ([]byte, error) {
	return mc.card.ATS()
}

func (mc *MifareClassic) DisconnectCard() error {
	return mc.card.DisconnectCard()
}

func (mc *MifareClassic) DisconnectResetCard() error {
	return mc.card.DisconnectCard()
}

func (mc *MifareClassic) Auth(bNr, keyType int, key []byte) ([]byte, error) {
	if err := mc.card.MFLoadKey(key); err != nil {
		return nil, fmt.Errorf("load key %d error: %w", bNr, err)
	}
	if err := mc.card.MFAuthent(keyType, bNr); err != nil {
		return nil, fmt.Errorf("auth key %d error: %w", bNr, err)
	}

	return nil, nil
}

func (mc *MifareClassic) ReadBlocks(bNr, ext int) ([]byte, error) {

	ext_ := ext
	if ext < 1 {
		ext_ = 1
	}
	resp := make([]byte, 0)
	for i := range make([]int, ext_) {
		aid := []byte{0x30, byte(bNr + i)}
		response, err := mc.Apdu(aid)
		if err != nil {
			return nil, fmt.Errorf("read block %d error: %w", bNr, err)
		}
		if len(response) < 16 {
			if len(response) == 1 {
				return nil, fmt.Errorf("no Ack, code: [%X]", response[0])
			}
			return nil, fmt.Errorf("wrong length response (< 16), response [%X]", response)
		}
		resp = append(resp, response...)
	}

	return resp, nil
}

func (mc *MifareClassic) WriteBlock(bNr int, data []byte) ([]byte, error) {
	aid := []byte{0xA0, byte(bNr)}
	if resp, err := mc.Apdu(aid); err != nil {
		return nil, fmt.Errorf("write block %d error: %w", bNr, err)
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return nil, fmt.Errorf("no Ack, code: [%X]", resp[0])
	}
	// dataw = append(data...)
	if resp, err := mc.Apdu(data); err != nil {
		return nil, err
	} else if len(resp) > 0 && resp[0] != 0x0A {
		return nil, fmt.Errorf("no Ack, code: [%X]", resp[0])
	}

	return nil, nil
}
