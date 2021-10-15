package ev2

import (
	"encoding/binary"
	"errors"
)

func (d *desfire) SelectApplication(aid1, aid2 []byte) ([]byte, error) {

	if len(aid1) != 3 {
		return nil, errors.New("aid format error")
	}
	if len(aid2) > 0 && len(aid2) != 3 {
		return nil, errors.New("aid format error")
	}

	expaid1 := append(aid1, 0x00)
	aid := binary.LittleEndian.Uint32(expaid1)

	cmd := byte(0x5A)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	apdu = append(apdu, aid1...)
	apdu = append(apdu, aid2...)

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}

	d.currentAppID = int(aid)

	return resp, nil
}
