package ev2

import (
	"encoding/binary"
	"errors"
)

// ReadData reads data from File Type StandardData, FileType.BcakupData or
// FileType.TransactionMAC files.
func (d *desfire) ReadData(fileNo int, targetSecondaryApp SecondAppIndicator,
	offset int,
	length int,
	commMode CommMode,
) ([]byte, error) {

	if offset > 0xFFFFFF {
		return nil, errors.New("wrong len (not 3) in \"offset\"")
	}
	if length > 0xFFFFFF {
		return nil, errors.New("wrong len (not 3) in \"length\"")
	}

	cmd := 0xAD

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	offset_bytes := make([]byte, 4)
	length_bytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(offset_bytes, uint32(offset))
	binary.LittleEndian.PutUint32(length_bytes, uint32(length))

	cmdHeader = append(cmdHeader, offset_bytes[:3]...)
	cmdHeader = append(cmdHeader, length_bytes[:3]...)

	apdu = append(apdu, cmdHeader...)

	response := make([]byte, 0)

	for {

		switch d.evMode {
		case EV2:
			switch commMode {
			case FULL, MAC:
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
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
		response = append(response, responseData...)

		if resp[0] == 0x00 {
			break
		}
		apdu = []byte{0xAF}
		cmdHeader = nil

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

// WriteData write data to File Type StandardData and FileType.BcakupData files.
func (d *desfire) WriteData(fileNo int, targetSecondaryApp SecondAppIndicator,
	offset int,
	datafile []byte,
	commMode CommMode,
) error {

	if offset > 0xFFFFFF {
		return errors.New("wrong len (not 3) in \"offset\"")
	}

	if len(datafile) > 0xFFFFFF {
		return errors.New("wrong len (max 0xFFFFFF) in \"len(data)\"")
	}

	cmd := 0x8D

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	offset_bytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(offset_bytes, uint32(offset))

	cmdHeader = append(cmdHeader, offset_bytes[:3]...)

	length := make([]byte, 4)

	binary.LittleEndian.PutUint32(length, uint32(len(datafile)))
	cmdHeader = append(cmdHeader, length[:3]...)

	apdu = append(apdu, cmdHeader...)

	// response := make([][]byte, 0)

	datafile_copy := make([]byte, len(datafile))
	copy(datafile_copy, datafile)

	for len(datafile_copy) > 0 {

		var data []byte
		if len(datafile_copy) > 250 {
			data = make([]byte, 250)
			copy(data, datafile_copy[:250])
			datafile_copy = datafile_copy[250:]
		} else {
			data = make([]byte, len(datafile_copy))
			copy(data, datafile_copy)
			datafile_copy = nil
		}
		switch d.evMode {
		case EV2:
			switch commMode {
			case FULL:
				iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
				if err != nil {
					return err
				}
				cryptograma := calcCryptogramEV2(d.block, data, iv)
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, cryptograma)
				if err != nil {
					return err
				}
				apdu = append(apdu, cryptograma...)
				apdu = append(apdu, cmacT...)
			case MAC:
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, data)
				if err != nil {
					return err
				}
				apdu = append(apdu, data...)
				apdu = append(apdu, cmacT...)
			case PLAIN:
			default:
			}
		case EV1:
			return errors.New("only EV1 and Ev2 support")
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

		// TODO: verify MAC

		if resp[0] == 0x00 {
			break
		}
		apdu = []byte{0xAF}
		cmdHeader = nil
	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return nil
	default:
		return errors.New("only EV2 mode support")
	}
}

// GetValue reads the currently stored from FileType.Value file.
func (d *desfire) GetValue(fileNo int, targetSecondaryApp SecondAppIndicator,
	commMode CommMode,
) ([]byte, error) {

	cmd := 0x6C

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		switch commMode {
		case FULL, MAC:
			cmacT, err := calcMacOnCommandEV2(d.blockMac,
				d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
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

// Credit increases a value stored in a FileType.Value file.
func (d *desfire) Credit(fileNo int, targetSecondaryApp SecondAppIndicator,
	value uint,
	commMode CommMode,
) error {

	cmd := 0x0C

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	apdu = append(apdu, cmdHeader...)

	data := make([]byte, 4)

	binary.LittleEndian.PutUint32(data, uint32(value))

	switch d.evMode {
	case EV2:
		switch commMode {
		case FULL:
			iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
			if err != nil {
				return err
			}
			cryptograma := calcCryptogramEV2(d.block, data, iv)
			cmacT, err := calcMacOnCommandEV2(d.blockMac,
				d.ti, byte(cmd), d.cmdCtr, cmdHeader, cryptograma)
			if err != nil {
				return err
			}
			apdu = append(apdu, cryptograma...)
			apdu = append(apdu, cmacT...)
		case MAC:
			cmacT, err := calcMacOnCommandEV2(d.blockMac,
				d.ti, byte(cmd), d.cmdCtr, cmdHeader, data)
			if err != nil {
				return err
			}
			apdu = append(apdu, data...)
			apdu = append(apdu, cmacT...)
		case PLAIN:
		default:
		}
	case EV1:
		return errors.New("only EV1 and Ev2 support")
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

	// TODO: verify MAC

	// var responseData []byte
	// switch d.evMode {
	// case EV2:
	// 	switch commMode {
	// 	case FULL, MAC:
	// 		responseData = resp[1 : len(resp)-8]
	// 	default:
	// 		responseData = resp[1:]
	// 	}
	// case EV1:
	// 	return errors.New("only desfire EV2 mode support")
	// default:
	// 	return errors.New("only desfire EV2 mode support")
	// }

	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return nil
	default:
		return errors.New("only EV2 mode support")
	}
}

// LimitedCredit allows a limited increase of a value stored in a FileType.Value file
// without having full Cmd.Credit permissions to the file.
func (d *desfire) LimitedCredit(fileNo int, targetSecondaryApp SecondAppIndicator,
	value uint,
	commMode CommMode,
) ([]byte, error) {

	cmd := 0x1C

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	apdu = append(apdu, cmdHeader...)

	data := make([]byte, 4)

	binary.LittleEndian.PutUint32(data, uint32(value))

	switch d.evMode {
	case EV2:
		switch commMode {
		case FULL:
			iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
			if err != nil {
				return nil, err
			}
			cryptograma := calcCryptogramEV2(d.block, data, iv)
			cmacT, err := calcMacOnCommandEV2(d.blockMac,
				d.ti, byte(cmd), d.cmdCtr, cmdHeader, cryptograma)
			if err != nil {
				return nil, err
			}
			apdu = append(apdu, cryptograma...)
			apdu = append(apdu, cmacT...)
		case MAC:
			cmacT, err := calcMacOnCommandEV2(d.blockMac,
				d.ti, byte(cmd), d.cmdCtr, cmdHeader, data)
			if err != nil {
				return nil, err
			}
			apdu = append(apdu, data...)
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
		case FULL, MAC:
			responseData = resp[1 : len(resp)-8]
		default:
			responseData = resp[1:]
		}
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

// Debit decreases a value stored in a FileType.Value file.
func (d *desfire) Debit(fileNo int, targetSecondaryApp SecondAppIndicator,
	value uint,
	commMode CommMode,
) ([]byte, error) {

	cmd := 0xDC

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	apdu = append(apdu, cmdHeader...)

	data := make([]byte, 4)

	binary.LittleEndian.PutUint32(data, uint32(value))

	switch d.evMode {
	case EV2:
		switch commMode {
		case FULL:
			iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
			if err != nil {
				return nil, err
			}
			cryptograma := calcCryptogramEV2(d.block, data, iv)
			cmacT, err := calcMacOnCommandEV2(d.blockMac,
				d.ti, byte(cmd), d.cmdCtr, cmdHeader, cryptograma)
			if err != nil {
				return nil, err
			}
			apdu = append(apdu, cryptograma...)
			apdu = append(apdu, cmacT...)
		case MAC:
			cmacT, err := calcMacOnCommandEV2(d.blockMac,
				d.ti, byte(cmd), d.cmdCtr, cmdHeader, data)
			if err != nil {
				return nil, err
			}
			apdu = append(apdu, data...)
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
		case FULL, MAC:
			responseData = resp[1 : len(resp)-8]
		default:
			responseData = resp[1:]
		}
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

// ReadRecords reads out a set of complete records from FileType.LinearRecord or
// FileType.CyclicRecord File.
func (d *desfire) ReadRecords(fileNo int, targetSecondaryApp SecondAppIndicator,
	recNo int,
	recCount int,
	commMode CommMode,
) ([][]byte, error) {

	if recNo > 0xFFFFFF {
		return nil, errors.New("wrong len (not 3) in \"recNo\"")
	}
	if recCount > 0xFFFFFF {
		return nil, errors.New("wrong len (not 3) in \"recCount\"")
	}

	cmd := 0xAB

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	recNo_bytes := make([]byte, 4)
	recCount_bytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(recNo_bytes, uint32(recNo))
	binary.LittleEndian.PutUint32(recCount_bytes, uint32(recCount))

	cmdHeader = append(cmdHeader, recNo_bytes[:3]...)
	cmdHeader = append(cmdHeader, recCount_bytes[:3]...)

	apdu = append(apdu, cmdHeader...)

	response := make([][]byte, 0)

	for {

		switch d.evMode {
		case EV2:
			switch commMode {
			case FULL, MAC:
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
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
		cmdHeader = nil
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

// WriteRecord write data to record a FileType.LinearRecord or FileType.CyclicRecord.
func (d *desfire) WriteRecord(fileNo int, targetSecondaryApp SecondAppIndicator,
	offset int,
	dataRecord []byte,
	commMode CommMode,
) error {

	if offset > 0xFFFFFF {
		return errors.New("wrong len (not 3) in \"offset\"")
	}

	if len(dataRecord) > 0xFFFFFF {
		return errors.New("wrong len (max 0xFFFFFF) in \"len(dataRecord)\"")
	}

	cmd := 0x8B

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	offset_bytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(offset_bytes, uint32(offset))

	cmdHeader = append(cmdHeader, offset_bytes[:3]...)

	length := make([]byte, 4)

	binary.LittleEndian.PutUint32(length, uint32(len(dataRecord)))
	cmdHeader = append(cmdHeader, length[:3]...)

	apdu = append(apdu, cmdHeader...)

	// response := make([][]byte, 0)

	datafile_copy := make([]byte, len(dataRecord))
	copy(datafile_copy, dataRecord)

	for len(datafile_copy) > 0 {

		var data []byte
		if len(datafile_copy) > 250 {
			data = make([]byte, 250)
			copy(data, datafile_copy[:250])
			datafile_copy = datafile_copy[250:]
		} else {
			data = make([]byte, len(datafile_copy))
			copy(data, datafile_copy)
			datafile_copy = nil
		}
		switch d.evMode {
		case EV2:
			switch commMode {
			case FULL:
				iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
				if err != nil {
					return err
				}
				cryptograma := calcCryptogramEV2(d.block, data, iv)
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, cryptograma)
				if err != nil {
					return err
				}
				apdu = append(apdu, cryptograma...)
				apdu = append(apdu, cmacT...)
			case MAC:
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, data)
				if err != nil {
					return err
				}
				apdu = append(apdu, data...)
				apdu = append(apdu, cmacT...)
			case PLAIN:
			default:
			}
		case EV1:
			return errors.New("only EV1 and Ev2 support")
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

		// TODO: verify MAC

		if resp[0] == 0x00 {
			break
		}
		apdu = []byte{0xAF}
		cmdHeader = nil
	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return nil
	default:
		return errors.New("only EV2 mode support")
	}
}

// UpdateRecord update data of an existing record a FileType.LinearRecord or
// FileType.CyclicRecord file.
func (d *desfire) UpdateRecord(fileNo int, targetSecondaryApp SecondAppIndicator,
	recNo int,
	offset int,
	dataRecord []byte,
	commMode CommMode,
) error {

	if offset > 0xFFFFFF {
		return errors.New("wrong len (not 3) in \"offset\"")
	}

	if len(dataRecord) > 0xFFFFFF {
		return errors.New("wrong len (max 0xFFFFFF) in \"len(dataRecord)\"")
	}

	cmd := 0x8B

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	recNo_bytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(recNo_bytes, uint32(recNo))

	cmdHeader = append(cmdHeader, recNo_bytes[:3]...)

	offset_bytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(offset_bytes, uint32(offset))

	cmdHeader = append(cmdHeader, offset_bytes[:3]...)

	length := make([]byte, 4)

	binary.LittleEndian.PutUint32(length, uint32(len(dataRecord)))
	cmdHeader = append(cmdHeader, length[:3]...)

	apdu = append(apdu, cmdHeader...)

	// response := make([][]byte, 0)

	datafile_copy := make([]byte, len(dataRecord))
	copy(datafile_copy, dataRecord)

	for len(datafile_copy) > 0 {

		var data []byte
		if len(datafile_copy) > 250 {
			data = make([]byte, 250)
			copy(data, datafile_copy[:250])
			datafile_copy = datafile_copy[250:]
		} else {
			data = make([]byte, len(datafile_copy))
			copy(data, datafile_copy)
			datafile_copy = nil
		}
		switch d.evMode {
		case EV2:
			switch commMode {
			case FULL:
				iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
				if err != nil {
					return err
				}
				cryptograma := calcCryptogramEV2(d.block, data, iv)
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, cryptograma)
				if err != nil {
					return err
				}
				apdu = append(apdu, cryptograma...)
				apdu = append(apdu, cmacT...)
			case MAC:
				cmacT, err := calcMacOnCommandEV2(d.blockMac,
					d.ti, byte(cmd), d.cmdCtr, cmdHeader, data)
				if err != nil {
					return err
				}
				apdu = append(apdu, data...)
				apdu = append(apdu, cmacT...)
			case PLAIN:
			default:
			}
		case EV1:
			return errors.New("only EV1 and Ev2 support")
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

		// TODO: verify MAC

		if resp[0] == 0x00 {
			break
		}
		apdu = []byte{0xAF}
		cmdHeader = nil
	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return nil
	default:
		return errors.New("only EV2 mode support")
	}
}

// ClearRecordFile clear all records in a FileType.LinearRecird o FileType.CyclicRecord
// file.
func (d *desfire) ClearRecordFile(fileNo int, targetSecondaryApp SecondAppIndicator,
) error {

	cmd := 0xEB

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac,
			d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
		if err != nil {
			return err
		}
		apdu = append(apdu, cmacT...)
	case EV1:
		return errors.New("only EV1 and Ev2 support")
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
	case EV2:
		return nil
	default:
		return errors.New("only EV2 mode support")
	}
}
