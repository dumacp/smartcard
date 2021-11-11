package ev2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type CommMode int

const (
	PLAIN CommMode = 0
	MAC   CommMode = 1
	FULL  CommMode = 3
)

type AccessRights int

const (
	KeyID_0x00 AccessRights = iota
	KeyID_0x01
	KeyID_0x02
	KeyID_0x03
	KeyID_0x04
	KeyID_0x05
	KeyID_0x06
	KeyID_0x07
	KeyID_0x08
	KeyID_0x09
	KeyID_0x0A
	KeyID_0x0B
	KeyID_0x0C
	KeyID_0x0D
	FREE
	NO_ACCESS
)

// CreateStdDataFile creates files for the storage of plain unformatted user data within
// an existing application on the PICC.
func (d *Desfire) CreateStdDataFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	fileSize int,
) error {

	cmd := byte(0xCD)

	if len(isoFileID) != 2 && len(isoFileID) != 0 {
		return fmt.Errorf("wrong len (not 4 or nil) in \"isoFileID\", len: %d", len(isoFileID))
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	cmdHeader = append(cmdHeader, isoFileID...)
	if fileOption_Disabled {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode|0x01<<7))
	} else {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode&0x7F))
	}

	accessRights := uint16(0)

	accessRights |= (uint16(accessRights_Read) << 12)
	accessRights |= (uint16(accessRights_Write) << 8)
	accessRights |= (uint16(accessRights_ReadWrite) << 4)
	accessRights |= (uint16(accessRights_Change) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	cmdHeader = append(cmdHeader, accessRightsBytes...)

	fileSizeBytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(fileSizeBytes, uint32(fileSize))

	cmdHeader = append(cmdHeader, fileSizeBytes[:3]...)
	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmcT...)
	default:
		return errors.New("only EV2 mode support")
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

// CreateBackupDataFile creates files for the storage of plain unformatted user data within
// an existing application on the PICC, additionally supporting the feature of an integreted
// backup mechanism.
func (d *Desfire) CreateBackupDataFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	fileSize int,
) error {

	cmd := byte(0xCB)

	if len(isoFileID) != 2 && len(isoFileID) != 0 {
		return errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	cmdHeader = append(cmdHeader, isoFileID...)
	if fileOption_Disabled {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode|0x01<<7))
	} else {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode&0x7F))
	}

	accessRights := uint16(0)

	accessRights |= (uint16(accessRights_Read) << 12)
	accessRights |= (uint16(accessRights_Write) << 8)
	accessRights |= (uint16(accessRights_ReadWrite) << 4)
	accessRights |= (uint16(accessRights_Change) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	cmdHeader = append(cmdHeader, accessRightsBytes...)

	fileSizeBytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(fileSizeBytes, uint32(fileSize))

	cmdHeader = append(cmdHeader, fileSizeBytes[:3]...)

	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmcT...)
	default:
		return errors.New("only EV2 mode support")
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

// CreateValueFile creates files for the storage and manipulation of 32bot signed values withon
// an existing application on the PICC.
func (d *Desfire) CreateValueFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	lowerLimit, upperLimit, value int,
	limitedCreditEnabled bool,
	freeAccesstoGetValue bool,
) error {

	cmd := byte(0xCC)

	if len(isoFileID) != 2 && len(isoFileID) != 0 {
		return errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if uint32(lowerLimit) > 0xFFFFFFFF {
		return errors.New("wrong len (not 4) in \"lowerLimit\"")
	}
	if uint32(upperLimit) > 0xFFFFFFFF {
		return errors.New("wrong len (not 4) in \"upperLimit\"")
	}
	if uint32(value) > 0xFFFFFFFF {
		return errors.New("wrong len (not 4) in \"value\"")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	cmdHeader = append(cmdHeader, isoFileID...)
	if fileOption_Disabled {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode|0x01<<7))
	} else {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode&0x7F))
	}

	accessRights := uint16(0)

	accessRights |= (uint16(accessRights_Read) << 12)
	accessRights |= (uint16(accessRights_Write) << 8)
	accessRights |= (uint16(accessRights_ReadWrite) << 4)
	accessRights |= (uint16(accessRights_Change) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	cmdHeader = append(cmdHeader, accessRightsBytes...)

	lowerLimitBytes := make([]byte, 4)
	upperLimitBytes := make([]byte, 4)
	valueBytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(lowerLimitBytes, uint32(lowerLimit))
	binary.LittleEndian.PutUint32(upperLimitBytes, uint32(upperLimit))
	binary.LittleEndian.PutUint32(valueBytes, uint32(value))

	cmdHeader = append(cmdHeader, lowerLimitBytes...)
	cmdHeader = append(cmdHeader, upperLimitBytes...)
	cmdHeader = append(cmdHeader, valueBytes...)

	limitedCredit := byte(0)
	if freeAccesstoGetValue {
		limitedCredit |= 0x01 << 1
	}
	if limitedCreditEnabled {
		limitedCredit |= 0x01 << 0
	}

	cmdHeader = append(cmdHeader, limitedCredit)
	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmcT...)
	default:
		return errors.New("only EV2 mode support")
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

// CreateLinearRecorFile creates files for multiple storage of structural similar data, for example for
// loyalty programs, with an existing application on the PICC. Once the file is filled completely with
// data recirds, further writing on the file is not posible unless it is cleared.
func (d *Desfire) CreateLinearRecorFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_AdditionalAccessRights_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	recordSize, maxNoOfRecords int,
) error {

	cmd := byte(0xC1)

	if len(isoFileID) != 2 && len(isoFileID) != 0 {
		return errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if recordSize > 0xFFFFFF || recordSize < 1 {
		return errors.New("wrong len (not 3) in \"recordSize\"")
	}
	if maxNoOfRecords > 0xFFFFFF || maxNoOfRecords < 2 {
		return errors.New("wrong len (not 3) in \"maxNoOfRecords\"")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	cmdHeader = append(cmdHeader, isoFileID...)
	if fileOption_AdditionalAccessRights_Disabled {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode|0x01<<7))
	} else {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode&0x7F))
	}

	accessRights := uint16(0)

	accessRights |= (uint16(accessRights_Read) << 12)
	accessRights |= (uint16(accessRights_Write) << 8)
	accessRights |= (uint16(accessRights_ReadWrite) << 4)
	accessRights |= (uint16(accessRights_Change) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	cmdHeader = append(cmdHeader, accessRightsBytes...)

	recordSizeBytes := make([]byte, 4)
	maxNoOfRecordsBytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(recordSizeBytes, uint32(recordSize))
	binary.LittleEndian.PutUint32(maxNoOfRecordsBytes, uint32(maxNoOfRecords))

	cmdHeader = append(cmdHeader, recordSizeBytes[:3]...)
	cmdHeader = append(cmdHeader, maxNoOfRecordsBytes[:3]...)
	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmcT...)
	default:
		return errors.New("only EV2 mode support")
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

// CreateCyclicRecorFile creates files for multiple storage of structural similar data, for example for
// logging transactions, with an existing application on the PICC. Once the file is filled completely with
// data records, the PICC automatically overwrites the oldest record with the lastest written one. This
// wrap is fully transparent for the PCD.
func (d *Desfire) CreateCyclicRecorFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_AdditionalAccessRights_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	recordSize, maxNoOfRecords int,
) error {

	cmd := byte(0xC0)

	if len(isoFileID) != 2 && len(isoFileID) != 0 {
		return errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if recordSize > 0xFFFFFF || recordSize < 1 {
		return errors.New("wrong len (not 3) in \"recordSize\"")
	}
	if maxNoOfRecords > 0xFFFFFF || maxNoOfRecords < 2 {
		return errors.New("wrong len (not 3) in \"maxNoOfRecords\"")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	cmdHeader = append(cmdHeader, isoFileID...)
	if fileOption_AdditionalAccessRights_Disabled {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode|0x01<<7))
	} else {
		cmdHeader = append(cmdHeader, byte(fileOption_commMode&0x7F))
	}

	accessRights := uint16(0)

	accessRights |= (uint16(accessRights_Read) << 12)
	accessRights |= (uint16(accessRights_Write) << 8)
	accessRights |= (uint16(accessRights_ReadWrite) << 4)
	accessRights |= (uint16(accessRights_Change) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	cmdHeader = append(cmdHeader, accessRightsBytes...)

	recordSizeBytes := make([]byte, 4)
	maxNoOfRecordsBytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(recordSizeBytes, uint32(recordSize))
	binary.LittleEndian.PutUint32(maxNoOfRecordsBytes, uint32(maxNoOfRecords))

	cmdHeader = append(cmdHeader, recordSizeBytes[:3]...)
	cmdHeader = append(cmdHeader, maxNoOfRecordsBytes[:3]...)

	apdu = append(apdu, cmdHeader...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmcT...)
	default:
		return errors.New("only EV2 mode support")
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

// CreateTransactionMACFile creates Transaction MAC File enables the Transaction MAC feature for
// targeted application.
func (d *Desfire) CreateTransactionMACFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_AppCommitReaderIDKey AccessRights,
	accessRights_Change AccessRights,
	tmKey []byte,
	tmKeyVersion int,
	tmKeyOption_keyType KeyType,
) error {

	cmd := byte(0xCE)

	if len(isoFileID) != 2 && len(isoFileID) != 0 {
		return errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if len(tmKey) != 16 {
		return errors.New("wrong len (not 3) in \"tmKey\"")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	cmdHeader = append(cmdHeader, isoFileID...)
	cmdHeader = append(cmdHeader, byte(fileOption_commMode))

	accessRights := uint16(0)

	accessRights |= (uint16(accessRights_Read) << 12)
	accessRights |= (uint16(0x0F) << 8)
	accessRights |= (uint16(accessRights_AppCommitReaderIDKey) << 4)
	accessRights |= (uint16(accessRights_Change) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	cmdHeader = append(cmdHeader, accessRightsBytes...)

	cmdHeader = append(cmdHeader, byte(tmKeyOption_keyType))

	apdu = append(apdu, cmdHeader...)

	data := make([]byte, 0)
	data = append(data, tmKey...)
	data = append(data, byte(tmKeyVersion))

	switch d.evMode {
	case EV2:
		iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
		if err != nil {
			return err
		}

		cryptograma := calcCryptogramEV2(d.block, data, iv)
		cmcT, err := calcMacOnCommandEV2(d.blockMac,
			d.ti, byte(cmd), d.cmdCtr, cmdHeader, cryptograma)
		if err != nil {
			return err
		}

		apdu = append(apdu, cryptograma...)

		apdu = append(apdu, cmcT...)
	default:
		return errors.New("only EV2 mode support")
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

// DeleteFile permanently deactivates a file within the file directory of the currently selected
// application.
func (d *Desfire) DeleteFile(fileNo int,
	targetSecondaryApp SecondAppIndicator,
) error {

	cmd := byte(0xDF)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	apdu = append(apdu, cmdHeader...)
	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmcT...)
	default:
		return errors.New("only EV2 mode support")
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

// GetFileIDs returns the File IDentifiers of all active files within the current selected
// application.
func (d *Desfire) GetFileIDs() ([]byte, error) {

	cmd := byte(0x6F)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			nil, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmcT...)
	default:
		return nil, errors.New("only EV2 mode support")
	}

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// GetISOFileIDs get back the ISO File IDs.
func (d *Desfire) GetISOFileIDs(fileNo int,
	targetSecondaryApp SecondAppIndicator,
) ([]byte, error) {

	cmd := byte(0xAF)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			nil, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmcT...)
	default:
		return nil, errors.New("only EV2 mode support")
	}

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// GetFileSettings get information on the properties of a specific file.
func (d *Desfire) GetFileSettings(fileNo int,
	targetSecondaryApp SecondAppIndicator,
) ([]byte, error) {

	cmd := byte(0xF5)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	apdu = append(apdu, cmdHeader...)
	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}

		apdu = append(apdu, cmcT...)
	default:
		return nil, errors.New("only EV2 mode support")
	}

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}
	defer func() {
		d.cmdCtr++
	}()

	switch d.evMode {
	case EV2:
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// ChangeFileSettings changes the access parameters of an existing file.
func (d *Desfire) ChangeFileSettings(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_AdditionalAccessRights_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	nrAddAccessRights int,
	addAccessRights []byte,
) error {

	cmd := 0x5F

	if len(isoFileID) != 2 && len(isoFileID) != 0 {
		return errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if len(addAccessRights) != (2 * nrAddAccessRights) {
		return errors.New("wrong len (nrAddAccessRights * 2) in \"nrAddAccessRights\"")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))

	apdu = append(apdu, cmdHeader...)

	data := make([]byte, 0)
	data = append(data, isoFileID...)
	if fileOption_AdditionalAccessRights_Disabled {
		data = append(data, byte(fileOption_commMode|0x01<<7))
	} else {
		data = append(data, byte(fileOption_commMode&0x7F))
	}

	accessRights := uint16(0)

	accessRights |= (uint16(accessRights_Read) << 12)
	accessRights |= (uint16(accessRights_Write) << 8)
	accessRights |= (uint16(accessRights_ReadWrite) << 4)
	accessRights |= (uint16(accessRights_Change) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	data = append(data, accessRightsBytes...)

	if !fileOption_AdditionalAccessRights_Disabled {
		data = append(data, byte(nrAddAccessRights))
		data = append(data, addAccessRights...)
	}

	switch d.evMode {
	case EV2:
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
	default:
		return errors.New("only EV2 mode support")
	}

	resp, err := d.Apdu(apdu)
	if err != nil {
		return err
	}
	if err := VerifyResponse(resp); err != nil {
		return err
	}

	// var responseData []byte
	// switch d.evMode {
	// case EV2:
	// 	var err error
	// 	iv, err := calcResponseIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr+1)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	responseData = getDataOnFullModeResponseEV2(d.block, iv, resp)
	// case EV1:
	// 	iv, err := calcResponseIVOnFullModeEV1(d.block, cmd, nil, nil)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	responseData = getDataOnFullModeResponseEV1(d.block, iv, resp)
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
