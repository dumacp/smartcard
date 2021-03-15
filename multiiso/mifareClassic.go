package multiiso

import (
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

//commands
const (
	authentication string = "l"
	readblock      string = "rb"
	writeblock     string = "wb"
)

//response
const (
	Loginsucess          byte = 'L'
	Authenticationfailed byte = 'X'
	Generalfailure       byte = 'F'
	Notaginfield         byte = 'N'
	Operationmodefailure byte = 'O'
	Outofrange           byte = 'R'
)

type mifareClassic struct {
	smartcard.ICard
}

// NewMifareClassicReader Create mifare classic reader
func NewMifareClassicReader(dev *Device, readerName string, idx int) Reader {
	r := &reader{
		device:     dev,
		readerName: readerName,
		idx:        idx,
	}
	r.transmit = r.TransmitBinary
	return r
}

//MifareClassic Create Mifare Plus Interface
func MifareClassic(c smartcard.ICard) (mifare.Classic, error) {

	mc := &mifareClassic{
		ICard: c,
	}
	return mc, nil
}

//NewMClassic Create Mifare Plus Interface
func (r *reader) ConnectMifareClassic() (mifare.Classic, error) {

	// c, err := r.ConnectCard()
	// if err != nil {
	// 	return nil, err
	// }
	// mc := &mifareClassic{
	// 	ICard: c,
	// }
	return nil, nil
}

/**/

func (mc *mifareClassic) Auth(bNr, keyType int, key []byte) ([]byte, error) {
	// fmt.Printf("reader: %s\n", mc.reader)
	sector := bNr / 4
	cmd := []byte(authentication)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	apdu = append(apdu, byte(sector))
	if keyType != 0 {
		apdu = append(apdu, 0xBB)
	} else {
		apdu = append(apdu, 0xAA)
	}
	apdu = append(apdu, key...)

	resp1, err := mc.Apdu(apdu)
	if err != nil {
		return nil, err
	}

	if resp1[0] == Loginsucess {
		return resp1, nil
	}
	return resp1, ErrorCode(resp1[0])
}

func verifyblockresponse(resp []byte) error {
	if len(resp) < 16 {
		if len(resp) == 1 {
			return ErrorCode(resp[0])
		}
		return BadResponse(resp)
	}
	return nil
}

func (mc *mifareClassic) ReadBlocks(bNr, ext int) ([]byte, error) {

	cmd := []byte(readblock)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	apdu = append(apdu, byte(bNr))
	resp1, err := mc.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := verifyblockresponse(resp1); err != nil {
		return nil, err
	}
	return resp1, nil
}

func (mc *mifareClassic) WriteBlock(bNr int, data []byte) ([]byte, error) {

	cmd := []byte(writeblock)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd...)
	apdu = append(apdu, byte(bNr))
	apdu = append(apdu, data...)
	resp1, err := mc.Apdu(apdu)
	if err != nil {
		return nil, err
	}

	if len(resp1) < 2 {
		return resp1, ErrorCode(resp1[0])
	}

	return resp1, nil
}
