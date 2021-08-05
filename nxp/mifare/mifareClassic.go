package mifare

import (
	"github.com/dumacp/smartcard"
)

//Classic Mifare Plus Interface
type Classic interface {
	smartcard.ICard
	Auth(bNr, keyType int, key []byte) ([]byte, error)
	ReadBlocks(bNr, ext int) ([]byte, error)
	WriteBlock(bNr int, data []byte) ([]byte, error)
}

type IReaderClassic interface {
	ConnectMifareClassic() (Classic, error)
}

type classic struct{}

//ConnectMclassic Create Mifare Plus Interface
func ConnectMclassic(r IReaderClassic) (Classic, error) {

	c, err := r.ConnectMifareClassic()
	if err != nil {
		return nil, err
	}
	return c, nil
}

/**

func (mc *mifareClassic) Auth(bNr, keyType int, key []byte) ([]byte, error) {
	aid := []byte{0xFF,0x82,0x00,0x00,0x06}
	aid = append(aid, key...)

	response, err :=  mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	if keyType == 0 {
		aid = []byte{0xFF,0x88,0x00,byte(bNr),0x60,0x00}
	} else {
		aid = []byte{0xFF,0x88,0x00,byte(bNr),0x61,0x00}
	}

	response, err =  mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	return response, nil
}

func (mc *mifareClassic) ReadBlocks(bNr, ext int) ([]byte, error) {
	aid := []byte{0xFF,0xB0,0x00,byte(bNr),byte(ext)}
	response, err :=  mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	return response, nil
}

func (mc *mifareClassic) WriteBlock(bNr int, data []byte) ([]byte, error) {
	aid := []byte{0xFF,0xD6,0x00,byte(bNr),byte(len(data))}
	aid = append(aid, data...)
	response, err :=  mc.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	return response, nil
}
/**/
// ConnectSamCard() (smartcard.ICard, error)