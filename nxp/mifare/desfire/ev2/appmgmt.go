package ev2

import (
	"encoding/binary"
	"errors"
)

// CreateApplication creates new application on the PICC. The application is
// initialized according to the given settings. The application keys of the
// active key set aer initilized with the default Application key.
//
func (d *desfire) CreateApplication(aid []byte,
	keyTypeAKS KeyType,
	changeKey int,
	numberOfAppKeys int,

	appKeySettingChangeable,
	fileCreateDeleteWithAppMasterKey,
	fileDirAccessConfWithAppMasterKey,
	appMasterKeyChangeable,

	keySett3_Enabled bool,

	keySett3_appSpecificCapabilityDataEnable,
	keySett3_appSpecificVCkeysEnable,
	keySett3_appKeySetsEnable,

	use2byte_ISOIEC_7816_4_fileID bool,
	appKeySetsEnable_rollKey,
	appKeySetsEnable_aksVersion, appKeySetsEnable_NoKeySets, appKeySetsEnable_maxKeySize int,
	isoFileID, isofileDFName []byte) ([]byte, error) {

	if len(aid) != 3 {
		return nil, errors.New("aid format error")
	}

	cmd := 0xCA
	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, aid...)

	keySett1 := changeKey << 4
	if appKeySettingChangeable {
		keySett1 |= 0x01 << 3
	}
	if fileCreateDeleteWithAppMasterKey {
		keySett1 |= 0x02 << 2
	}
	if fileDirAccessConfWithAppMasterKey {
		keySett1 |= 0x01 << 1
	}
	if appMasterKeyChangeable {
		keySett1 |= 0x01 << 0
	}

	cmdHeader = append(cmdHeader, byte(keySett1))

	keySett2 := keyTypeAKS.Int() << 6
	if use2byte_ISOIEC_7816_4_fileID {
		keySett2 |= 0x01 << 5
	}
	if keySett3_Enabled {
		keySett2 |= 0x01 << 4
	}

	keySett2 |= numberOfAppKeys & 0x0F

	cmdHeader = append(cmdHeader, byte(keySett2))

	if keySett3_Enabled {
		keySett3 := 0x00
		if keySett3_appSpecificCapabilityDataEnable {
			keySett3 |= 0x01 << 2
		}
		if keySett3_appSpecificVCkeysEnable {
			keySett3 |= 0x01 << 1
		}
		if keySett3_appKeySetsEnable {
			keySett3 |= 0x01 << 0
		}
		cmdHeader = append(cmdHeader, byte(keySett3))
	}

	if keySett3_Enabled && keySett3_appKeySetsEnable {
		cmdHeader = append(cmdHeader, byte(appKeySetsEnable_aksVersion))
		if appKeySetsEnable_NoKeySets < 2 || appKeySetsEnable_NoKeySets > 16 {
			return nil, errors.New("minimum 2 and maximum 16 key sets")
		}
		cmdHeader = append(cmdHeader, byte(appKeySetsEnable_NoKeySets))
		if (appKeySetsEnable_maxKeySize != 16) && (appKeySetsEnable_maxKeySize != 24) {
			return nil, errors.New("max key size error")
		}
		cmdHeader = append(cmdHeader, byte(appKeySetsEnable_maxKeySize))
	}

	if len(isoFileID) > 0 {
		cmdHeader = append(cmdHeader, isoFileID...)
	}
	if len(isofileDFName) < 0 {
		cmdHeader = append(cmdHeader, isofileDFName...)
	}

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
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// SelectApplication select 1 or 2 applications or the PICC level specified
// by their application identifier.
func (d *desfire) SelectApplication(aid1, aid2 []byte) error {

	if len(aid1) != 3 {
		errors.New("aid format error")
	}
	if len(aid2) > 0 && len(aid2) != 3 {
		errors.New("aid format error")
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
		return err
	}
	if err := VerifyResponse(resp); err != nil {
		return err
	}

	d.currentAppID = int(aid)

	return nil
}

// Permanently deactivates applications on the PICC. The AID is released.
func (d *desfire) DeleteApplication(aid []byte) ([]byte, error) {

	if len(aid) != 3 {
		return nil, errors.New("aid format error")
	}

	cmd := byte(0xDA)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, aid...)

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
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// CreateDelegateApplication creates delegated applications on the PICC with
// limited memory consumption. The application is initialized according to
// the gievn settings. The application keys of the active key set are
// initialized with the provided keyID.AppDAMDefaultKey
func (d *desfire) CreateDelegateApplication(aid []byte,
	damSlotNo, damSlotVersion int,
	quotaLimit int,
	keyTypeAKS KeyType,
	changeKey int,
	numberOfAppKeys int,

	appKeySettingChangeable,
	fileCreateDeleteWithAppMasterKey,
	fileDirAccessConfWithAppMasterKey,
	appMasterKeyChangeable,

	keySett3_Enabled bool,

	keySett3_appSpecificCapabilityDataEnable,
	keySett3_appSpecificVCkeysEnable,
	keySett3_appKeySetsEnable,

	use2byte_ISOIEC_7816_4_fileID bool,
	appKeySetsEnable_rollKey,
	appKeySetsEnable_aksVersion, appKeySetsEnable_NoKeySets, appKeySetsEnable_maxKeySize int,
	isoFileID, isofileDFName []byte) ([]byte, error) {

	if len(aid) != 3 {
		return nil, errors.New("aid format error")
	}

	cmd := 0xCA
	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, aid...)

	damSlotNoBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(damSlotNoBytes, uint16(damSlotNo))
	cmdHeader = append(cmdHeader, damSlotNoBytes...)

	cmdHeader = append(cmdHeader, byte(damSlotVersion))

	quotaLimitBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(quotaLimitBytes, uint16(damSlotNo))
	cmdHeader = append(cmdHeader, quotaLimitBytes...)

	keySett1 := changeKey << 4
	if appKeySettingChangeable {
		keySett1 |= 0x01 << 3
	}
	if fileCreateDeleteWithAppMasterKey {
		keySett1 |= 0x02 << 2
	}
	if fileDirAccessConfWithAppMasterKey {
		keySett1 |= 0x01 << 1
	}
	if appMasterKeyChangeable {
		keySett1 |= 0x01 << 0
	}

	cmdHeader = append(cmdHeader, byte(keySett1))

	keySett2 := keyTypeAKS.Int() << 6
	if use2byte_ISOIEC_7816_4_fileID {
		keySett2 |= 0x01 << 5
	}
	if keySett3_Enabled {
		keySett2 |= 0x01 << 4
	}

	keySett2 |= numberOfAppKeys & 0x0F

	cmdHeader = append(cmdHeader, byte(keySett2))

	if keySett3_Enabled {
		keySett3 := 0x00
		if keySett3_appSpecificCapabilityDataEnable {
			keySett3 |= 0x01 << 2
		}
		if keySett3_appSpecificVCkeysEnable {
			keySett3 |= 0x01 << 1
		}
		if keySett3_appKeySetsEnable {
			keySett3 |= 0x01 << 0
		}
		cmdHeader = append(cmdHeader, byte(keySett3))
	}

	if keySett3_Enabled && keySett3_appKeySetsEnable {
		cmdHeader = append(cmdHeader, byte(appKeySetsEnable_aksVersion))
		if appKeySetsEnable_NoKeySets < 2 || appKeySetsEnable_NoKeySets > 16 {
			return nil, errors.New("minimum 2 and maximum 16 key sets")
		}
		cmdHeader = append(cmdHeader, byte(appKeySetsEnable_NoKeySets))
		if (appKeySetsEnable_maxKeySize != 16) && (appKeySetsEnable_maxKeySize != 24) {
			return nil, errors.New("max key size error")
		}
		cmdHeader = append(cmdHeader, byte(appKeySetsEnable_maxKeySize))
	}

	if len(isoFileID) > 0 {
		cmdHeader = append(cmdHeader, isoFileID...)
	}
	if len(isofileDFName) < 0 {
		cmdHeader = append(cmdHeader, isofileDFName...)
	}

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
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// GetApplicationsID returns the application IDentifiers of all active application
func (d *desfire) GetApplicationsID() ([]byte, error) {
	cmd := byte(0x5A)
	apdu := make([]byte, 0)

	apdu = append(apdu, cmd)

	switch d.evMode {
	case EV2:
		cmcT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr,
			nil, nil)
		if err != nil {
			return nil, err
		}
		// apdu = append(apdu, cmdHeader...)
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
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// GetVersion returns the Application IDentifiers together with a File ID
// and (optionally) a DF Name of all active applications with
// ISO/IEC 7816-4 support.
func (d *desfire) GetDFNames() ([][]byte, error) {

	cmd := byte(0x6D)

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

// GetDeletedInfo returns the DAMSlotVersion and QoutaLimit of a target DAM Slot
// on the card.
func (d *desfire) GetDeletedInfo(damSlotNo int) ([]byte, error) {

	if damSlotNo > 0xFFFF {
		return nil, errors.New("DAMSlotNo format error")
	}

	damSlotNoBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(damSlotNoBytes, uint16(damSlotNo))

	cmd := byte(0x69)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	cmdHeader := make([]byte, 0)
	cmdHeader = append(cmdHeader, damSlotNoBytes...)

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
		return resp[1 : len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}
