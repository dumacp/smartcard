package ev2

import (
	"encoding/binary"
	"errors"
)

type CommMode int

const (
	PLAIN CommMode = iota
	MAC
	FULL
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
func (d *desfire) CreateStdDataFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	fileSize []byte,
) ([]byte, error) {

	cmd := byte(0xCD)

	if len(isoFileID) != 2 || len(isoFileID) == 0 {
		return nil, errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
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
	cmdHeader = append(cmdHeader, fileSize...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmdHeader...)
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// CreateBackupDataFile creates files for the storage of plain unformatted user data within
// an existing application on the PICC, additionally supporting the feature of an integreted
// backup mechanism.
func (d *desfire) CreateBackupDataFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	fileSize []byte,
) ([]byte, error) {

	cmd := byte(0xCB)

	if len(isoFileID) != 2 || len(isoFileID) == 0 {
		return nil, errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
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
	cmdHeader = append(cmdHeader, fileSize...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmdHeader...)
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// CreateValueFile creates files for the storage and manipulation of 32bot signed values withon
// an existing application on the PICC.
func (d *desfire) CreateValueFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	lowerLimit, upperLimit, value []byte,
	limitedCreditEnabled bool,
	freeAccesstoGetValue bool,
) ([]byte, error) {

	cmd := byte(0xCD)

	if len(isoFileID) != 2 || len(isoFileID) == 0 {
		return nil, errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if len(lowerLimit) != 4 {
		return nil, errors.New("wrong len (not 4) in \"lowerLimit\"")
	}
	if len(upperLimit) != 4 {
		return nil, errors.New("wrong len (not 4) in \"upperLimit\"")
	}
	if len(value) != 4 {
		return nil, errors.New("wrong len (not 4) in \"value\"")
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

	cmdHeader = append(cmdHeader, lowerLimit...)
	cmdHeader = append(cmdHeader, upperLimit...)
	cmdHeader = append(cmdHeader, value...)

	limitedCredit := byte(0)
	if freeAccesstoGetValue {
		limitedCredit |= 0x01 << 1
	}
	if limitedCreditEnabled {
		limitedCredit |= 0x01 << 0
	}

	cmdHeader = append(cmdHeader, limitedCredit)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmdHeader...)
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// CreateLinearRecorFile creates files for multiple storage of structural similar data, for example for
// loyalty programs, with an existing application on the PICC. Once the file is filled completely with
// data recirds, further writing on the file is not posible unless it is cleared.
func (d *desfire) CreateLinearRecorFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	recordSize, maxNoOfRecords []byte,
	limitedCreditEnabled bool,
	freeAccesstoGetValue bool,
) ([]byte, error) {

	cmd := byte(0xC1)

	if len(isoFileID) != 2 || len(isoFileID) == 0 {
		return nil, errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if len(recordSize) != 3 {
		return nil, errors.New("wrong len (not 3) in \"recordSize\"")
	}
	if len(maxNoOfRecords) != 3 {
		return nil, errors.New("wrong len (not 3) in \"maxNoOfRecords\"")
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

	cmdHeader = append(cmdHeader, recordSize...)
	cmdHeader = append(cmdHeader, maxNoOfRecords...)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmdHeader...)
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// CreateTransactionMACFile creates Transaction MAC File enables the Transaction MAC feature for
// targeted application.
func (d *desfire) CreateTransactionMACFile(fileNo int, targetSecondaryApp SecondAppIndicator,
	isoFileID []byte,
	fileOption_Disabled bool,
	fileOption_commMode CommMode,
	accessRights_Read AccessRights,
	accessRights_Write AccessRights,
	accessRights_ReadWrite AccessRights,
	accessRights_Change AccessRights,
	tmKey []byte,
	tmKeyVersion int,
	tmKeyOption_keyType KeyType,
) ([]byte, error) {

	cmd := byte(0xCE)

	if len(isoFileID) != 2 || len(isoFileID) == 0 {
		return nil, errors.New("wrong len (not 4 or nil) in \"isoFileID\"")
	}
	if len(tmKey) != 16 {
		return nil, errors.New("wrong len (not 3) in \"tmKey\"")
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

	cmdHeader = append(cmdHeader, tmKey...)
	cmdHeader = append(cmdHeader, byte(tmKeyOption_keyType))

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmdHeader...)
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// DeleteFile permanently deactivates a file within the file directory of the currently selected
// application.
func (d *desfire) DeleteFile(fileNo int,
	targetSecondaryApp SecondAppIndicator,
) ([]byte, error) {

	cmd := byte(0xDF)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmdHeader...)
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// GetFileIDs returns the File IDentifiers of all active files within the current selected
// application.
func (d *desfire) GetFileIDs(fileNo int,
	targetSecondaryApp SecondAppIndicator,
) ([]byte, error) {

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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// GetISOFileIDs get back the ISO File IDs.
func (d *desfire) GetISOFileIDs(fileNo int,
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// GetFileSettings get information on the properties of a specific file.
func (d *desfire) GetFileSettings(fileNo int,
	targetSecondaryApp SecondAppIndicator,
) ([]byte, error) {

	cmd := byte(0xF5)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, byte(fileNo|targetSecondaryApp.Int()<<7))
	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			cmdHeader, nil)
		if err != nil {
			return nil, err
		}
		apdu = append(apdu, cmdHeader...)
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

	switch d.evMode {
	case EV2:
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}
