package ev2

import "errors"

// Returns the free memory avalaible on the card
func (d *desfire) FreeMem() ([]byte, error) {

	cmd := byte(0x6E)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	resp, err := d.Apdu(apdu)
	if err != nil {
		return resp, err
	}
	if err := VerifyResponse(resp); err != nil {
		return resp, err
	}

	return resp, nil
}

// Format At PICC level, all applications and files are deleted. At
// application level (only for delegated applications), all
// files are deleted. The deleted memory is released and can
// be reused.
func (d *desfire) Format() ([]byte, error) {

	cmd := byte(0xFC)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	resp, err := d.Apdu(apdu)
	if err != nil {
		return resp, err
	}
	if err := VerifyResponse(resp); err != nil {
		return resp, err
	}

	return resp, nil
}

// SetConfiguration Configures the card an pre personalizes the card
// with a key, defines if the UID or the random ID is sent back
// during communication setup and configures the ATS string.
func (d *desfire) SetConfiguration(option int, data []byte) ([]byte, error) {

	cmd := byte(0x5C)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	apdu = append(apdu, byte(option))
	apdu = append(apdu, data...)
	resp, err := d.Apdu(apdu)
	if err != nil {
		return resp, err
	}
	if err := VerifyResponse(resp); err != nil {
		return resp, err
	}

	return resp, nil
}

// GetVersion returns manufacturing related data of the PICC. First
// part HW related information as specified in CardVersioinList Table.
func (d *desfire) GetVersion() ([][]byte, error) {

	cmd := byte(0x60)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)

	response := make([][]byte, 0)

	for {

		switch d.evMode {
		case EV2:
			cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, nil, nil)
			if err != nil {
				return nil, err
			}
			apdu = append(apdu, cmacT...)
		case EV1:
		default:
			return nil, errors.New("only EV1 and Ev2 support")
		}

		resp, err := d.Apdu(apdu)
		if err != nil {
			return nil, err
		}
		if err := VerifyResponse(resp); err != nil {
			return nil, err
		}

		response = append(response, resp[1:len(resp)-8])

		if resp[0] == 0x00 {
			break
		}
		apdu = []byte{0xAF}
	}

	return response, nil
}

// GetCardUID resturn the UID
func (d *desfire) GetCardUID() ([]byte, error) {

	cmd := 0x51

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	var cmacdata []byte
	switch d.evMode {
	case EV2:
		var err error
		cmacdata, err = calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, nil, nil)
		if err != nil {
			return nil, err
		}
	case EV1:
	default:
		return nil, errors.New("desfire EV2 or EV1 only support")
	}

	apdu = append(apdu, cmacdata...)

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}

	var responseData []byte
	switch d.evMode {
	case EV2:
		var err error
		iv, err := calcResponseIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr+1)
		if err != nil {
			return nil, err
		}
		responseData = getDataOnFullModeResponseEV2(d.block, iv, resp)
	case EV1:
		iv, err := calcResponseIVOnFullModeEV1(d.block, cmd, nil, nil)
		if err != nil {
			return nil, err
		}
		responseData = getDataOnFullModeResponseEV1(d.block, iv, resp)
	default:
		return nil, errors.New("only desfire EV2 mode support")
	}
	defer func() {
		d.cmdCtr++
	}()

	if responseData[0] != 0x00 {
		return responseData[:7], nil
	}
	return responseData[2 : responseData[1]+2], nil
}
