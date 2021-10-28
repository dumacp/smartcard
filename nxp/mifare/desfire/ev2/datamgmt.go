package ev2

import (
	"errors"
)

// ReadData reads data from File Type StandardData, FileType.BcakupData or
// FileType.TransactionMAC files.
func (d *desfire) ReadData(fileNo int, targetSecondaryApp SecondAppIndicator,
	offset []byte,
	length []byte,
	commMode CommMode,
) ([][]byte, error) {

	if len(offset) != 3 {
		return nil, errors.New("wrong len (not 3) in \"offset\"")
	}
	if len(length) != 3 {
		return nil, errors.New("wrong len (not 3) in \"length\"")
	}

	cmd := 0xAD

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	cmdHeader = append(cmdHeader, offset...)
	cmdHeader = append(cmdHeader, length...)

	apdu = append(apdu, cmdHeader...)

	response := make([][]byte, 0)

	for {

		switch d.evMode {
		case EV2:
			switch commMode {
			case FULL, MAC:
				cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, nil, nil)
				if err != nil {
					return nil, err
				}
				apdu = append(apdu, cmacT...)
			case PLAIN:
			default:
			}
		case EV1:
			return nil, errors.New("only EV1 and Ev2 support")
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
			switch commMode {
			case FULL:
				var err error
				iv, err := calcResponseIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr+1)
				if err != nil {
					return nil, err
				}
				responseData = getDataOnFullModeResponseEV2(d.block, iv, resp)
			case MAC:
				responseData = resp[1 : len(resp)-8]
			default:
				responseData = resp[1:]
			}
		case EV1:
			return nil, errors.New("only desfire EV2 mode support")
		default:
			return nil, errors.New("only desfire EV2 mode support")
		}
		response = append(response, responseData)

		if resp[0] == 0x00 {
			break
		}
		apdu = []byte{0xAF}

	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return response, nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}
