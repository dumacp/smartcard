package ev2

import "errors"

// Validates all previous write accesses on Filetype.BackupData, FileType.Value
// FileType.LinearRecord and Filetype.CyclicRecord files within the selected
// application(s). If applicable, the FileType.TransactionMAC file is updated with
// the calculated Transaction MAC
func (d *desfire) CommitTransaction(
	return_TMC_and_TMV bool,
) error {

	cmd := byte(0xC7)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)

	cmdHeader := make([]byte, 0)
	if return_TMC_and_TMV {
		cmdHeader = append(cmdHeader, byte(0x01))
	}
	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac,
			d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
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
