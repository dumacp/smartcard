package ev2

import (
	"errors"
)

// Returns the free memory avalaible on the card
func (d *Desfire) FreeMem() ([]byte, error) {

	cmd := byte(0x6E)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
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

	switch d.evMode {
	case EV1, EV2:
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 support")
	}
}

// Format At PICC level, all applications and files are deleted. At
// application level (only for delegated applications), all
// files are deleted. The deleted memory is released and can
// be reused.
func (d *Desfire) Format() error {

	cmd := byte(0xFC)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, nil, nil)
		if err != nil {
			return err
		}
		apdu = append(apdu, cmacT...)
	case EV1:
	default:
		return errors.New("only EV1 and Ev2 support")
	}

	resp, err := d.Apdu(apdu)
	if err != nil {
		return err
	}
	if err := VerifyResponse(resp); err != nil {
		return err
	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV1, EV2:
		return nil
	default:
		return errors.New("only EV2 support")
	}
}

type ConfigurationOption int

const (
	PICC_CONFIGURATION ConfigurationOption = iota
	DEFAULT_KEYS_UPDATE
	ATS_UPDATE
	SAK_UPDATE
	SECURE_MESSAGING_CONFIGURATION
	CAPABILITY_DATA
	VC_INSTALATION_IDENTIFIER
)

// SetConfiguration Configures the card an pre personalizes the card
// with a key, defines if the UID or the random ID is sent back
// during communication setup and configures the ATS string.
func (d *Desfire) SetConfiguration(option ConfigurationOption, data []byte) error {

	cmd := byte(0x5C)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)

	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(option))

	apdu = append(apdu, cmdHeader...)

	// var cryptograma []byte
	// var block cipher.Block
	// var err error
	switch d.evMode {
	case EV2:
		iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
		if err != nil {
			return err
		}
		cryptograma := calcCryptogramEV2(d.block, data, iv)
		cmacT, err := calcMacOnCommandEV2(d.blockMac,
			d.ti, cmd, d.cmdCtr, cmdHeader, cryptograma)
		if err != nil {
			return err
		}

		apdu = append(apdu, cryptograma...)
		apdu = append(apdu, cmacT...)
	default:
		return errors.New("only Desfire Ev2 mode support")
	}

	resp, err := d.Apdu(apdu)
	if err != nil {
		return err
	}
	if err := VerifyResponse(resp); err != nil {
		return err
	}
	defer func() {
		d.cmdCtr++
	}()

	return nil
}

// GetVersion returns manufacturing related data of the PICC. First
// part HW related information as specified in CardVersioinList Table.
func (d *Desfire) GetVersion() ([][]byte, error) {

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
	defer func() {
		d.cmdCtr++
	}()

	return response, nil
}

// GetCardUID resturn the UID
func (d *Desfire) GetCardUID() ([]byte, error) {

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
