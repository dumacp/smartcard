package ev2

import "errors"

// Validates all previous write accesses on Filetype.BackupData, FileType.Value
// FileType.LinearRecord and Filetype.CyclicRecord files within the selected
// application(s). If applicable, the FileType.TransactionMAC file is updated with
// the calculated Transaction MAC
func (d *Desfire) CommitTransaction(
	return_TMC_and_TMV bool,
) ([]byte, error) {

	cmd := byte(0xC7)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)

	cmdHeader := make([]byte, 0)
	if return_TMC_and_TMV {
		cmdHeader = append(cmdHeader, byte(0x01))
	}
	apdu = append(apdu, cmdHeader...)
	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac,
			d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
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

	var responseData []byte
	switch d.evMode {
	case EV2:
		responseData = resp[1 : len(resp)-8]
	case EV1:
		return nil, errors.New("only desfire EV2 mode support")
	default:
		return nil, errors.New("only desfire EV2 mode support")
	}

	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return responseData, nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// AbortTransaction abort all previous write accesses on Filetype.BackupData, FileType.Value
// FileType.LinearRecord and Filetype.CyclicRecord files within the selected
// application(s). If applicable, theTransaction MAC calculation is aborted.
func (d *Desfire) AbortTransaction() error {

	cmd := byte(0xA7)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac,
			d.ti, byte(cmd), d.cmdCtr, nil, nil)
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

	switch d.evMode {
	case EV1, EV2:
		return nil
	default:
		return errors.New("only EV2 support")
	}
}

// CommitReaderID commit reader ID for a ongoing transacion. This will allow a backend
// to identified the attacking merchant in case of fraud detetcted.
func (d *Desfire) CommitReaderID(
	tmri []byte,
) ([]byte, error) {

	if len(tmri) != 16 {
		return nil, errors.New("only 16 bytes is allowed")
	}
	cmd := byte(0xC8)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)

	cmdHeader := make([]byte, 0)

	cmdHeader = append(cmdHeader, tmri...)

	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac,
			d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
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

	var responseData []byte
	switch d.evMode {
	case EV2:
		responseData = resp[1 : len(resp)-8]
	case EV1:
		return nil, errors.New("only desfire EV2 mode support")
	default:
		return nil, errors.New("only desfire EV2 mode support")
	}

	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return responseData, nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}
