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
		return resp[:len(resp)-8], nil
	default:
		return nil, errors.New("only EV2 mode support")
	}
}

// SelectApplication select 1 or 2 applications or the PICC level specified
// by their application identifier.
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
