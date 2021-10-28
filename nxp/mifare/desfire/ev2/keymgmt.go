package ev2

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"log"
)

func changeKeyCryptogramEV2(block, blockMac cipher.Block,
	cmd, keyNo, keySetNo, authKey, keyType, keyVersion int,
	cmdCtr uint16,
	newKey, oldKey, ti, iv []byte) ([]byte, error) {

	plaindata := make([]byte, 0)
	if keyNo&0x1F == authKey && keySetNo <= 0 {
		plaindata = append(plaindata, newKey...)
		if keyType == int(AES) {
			plaindata = append(plaindata, byte(keyVersion))
		}
	} else {
		log.Printf("keyNo: %v, lastKey: %v", keyNo, authKey)
		if len(oldKey) <= 0 {
			return nil, errors.New("old key is null")
		}
		for i := range newKey {
			plaindata = append(plaindata, newKey[i]^oldKey[i])
		}
		if keyType == int(AES) {
			plaindata = append(plaindata, byte(keyVersion))
		}
		crcdatanewkey := make([]byte, 0)
		crcdatanewkey = append(crcdatanewkey, newKey...)
		crcnewkey := ^crc32.ChecksumIEEE(crcdatanewkey)
		crcbytesnewkey := make([]byte, 4)
		binary.LittleEndian.PutUint32(crcbytesnewkey, crcnewkey)
		plaindata = append(plaindata, crcbytesnewkey[:]...)
	}

	log.Printf("plaindata          : [% X]", plaindata)

	mode := cipher.NewCBCEncrypter(block, iv)

	if len(plaindata)%block.BlockSize() != 0 {
		plaindata = append(plaindata, 0x80)
		plaindata = append(plaindata, make([]byte, block.BlockSize()-len(plaindata)%block.BlockSize())...)
	}
	log.Printf("plaindata + padding: [% X]", plaindata)

	cipherdata := make([]byte, len(plaindata))
	mode.CryptBlocks(cipherdata, plaindata)

	log.Printf("cipher data        : [% X], len: %d", cipherdata, len(cipherdata))

	cmdHeader := make([]byte, 0)
	if keySetNo >= 0 {
		cmdHeader = append(cmdHeader, byte(keySetNo))
	}
	cmdHeader = append(cmdHeader, byte(keyNo))

	cmacT, err := calcMacOnCommandEV2(blockMac, ti, byte(cmd), cmdCtr, cmdHeader, cipherdata)
	if err != nil {
		return nil, err
	}

	log.Printf("truncate cmac: [% X]", cmacT)

	cryptograma := make([]byte, 0)
	cryptograma = append(cryptograma, cipherdata...)
	cryptograma = append(cryptograma, cmacT...)

	return cryptograma, nil
}

func changeKeyCryptogramEV1(block cipher.Block,
	cmd, keyNo, authKey, keyType, keyVersion int,
	newKey, oldKey, iv []byte) ([]byte, error) {

	copyIV := make([]byte, block.BlockSize())
	copy(copyIV, iv)
	log.Printf("keyNo: %d, authKey: %d, newKey: [% X], iv: [% X], len newKey: %d",
		keyNo, authKey, newKey, iv, len(newKey))
	plaindata := make([]byte, 0)
	if (keyNo & 0x1F) == authKey {

		plaindata = append(plaindata, newKey...)
		if keyType == int(AES) {
			plaindata = append(plaindata, byte(keyVersion))
		}
		crcdata := make([]byte, 0)
		crcdata = append(crcdata, byte(cmd))
		crcdata = append(crcdata, byte(keyNo))
		crcdata = append(crcdata, plaindata...)

		crc := ^crc32.ChecksumIEEE(crcdata)
		log.Printf("crc32 data: [% X], crc: %X", crcdata, crc)
		crcbytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(crcbytes, crc)
		plaindata = append(plaindata, crcbytes[:]...)
		// log.Printf("crc32: [% X]", crc)
		// plaindata = append(plaindata, crc...)
	} else {
		if len(oldKey) <= 0 {
			return nil, errors.New("old key is null")
		}
		for i := range newKey {
			plaindata = append(plaindata, newKey[i]^oldKey[i])
		}
		if keyType == int(AES) {
			plaindata = append(plaindata, byte(keyVersion))
		}
		crcdata := make([]byte, 0)
		crcdata = append(crcdata, byte(cmd))
		crcdata = append(crcdata, byte(keyNo))
		crcdata = append(crcdata, plaindata...)
		crc := ^crc32.ChecksumIEEE(crcdata)
		crcbytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(crcbytes, crc)
		plaindata = append(plaindata, crcbytes[:]...)

		crcNK := ^crc32.ChecksumIEEE(newKey)
		crcNKbytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(crcNKbytes, crcNK)
		plaindata = append(plaindata, crcNKbytes[:]...)
	}

	mode := cipher.NewCBCEncrypter(block, copyIV)

	log.Printf("plaindata: [% X]; len plaindata: %d, %d",
		plaindata, len(plaindata), block.BlockSize())
	if len(plaindata)%block.BlockSize() != 0 {
		plaindata = append(plaindata, make([]byte, block.BlockSize()-len(plaindata)%block.BlockSize())...)
	}
	log.Printf("plaindata: [% X]; len plaindata: %d, %d",
		plaindata, len(plaindata), block.BlockSize())

	dest := make([]byte, len(plaindata))
	mode.CryptBlocks(dest, plaindata)

	return dest, nil
}

// ChangeKey depensing on the currently selectd AID, this command
// update a key of the PICC or of an application AKS.
func (d *desfire) ChangeKey(keyNo, keyVersion int,
	keyType KeyType, secondAppIndicator SecondAppIndicator,
	newKey, oldKey []byte) error {

	cmd := 0xC4

	if d.currentAppID != 0 {
		keyNo = keyNo | secondAppIndicator.Int()<<7
	} else {
		keyNo = keyNo | keyType.Int()<<6
	}

	var cryptograma []byte
	// var block cipher.Block
	var err error
	switch d.evMode {
	case EV2:
		iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
		if err != nil {
			return err
		}
		cryptograma, err = changeKeyCryptogramEV2(d.block, d.blockMac, cmd,
			keyNo, -1, d.lastKey, keyType.Int(), keyVersion,
			d.cmdCtr,
			newKey, oldKey, d.ti, iv)
		if err != nil {
			return err
		}
	case EV1:

		cryptograma, err = changeKeyCryptogramEV1(d.block,
			cmd, keyNo, d.lastKey, keyType.Int(), keyVersion,
			newKey, oldKey, d.iv)
		if err != nil {
			return err
		}
		log.Printf("cryptograma: [% X], len: %d", cryptograma, len(cryptograma))
		d.iv = cryptograma[len(cryptograma)-d.block.BlockSize()-1:]
	default:
		return errors.New("only EV1 and Ev2 support")
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)

	cmdHeader = append(cmdHeader, byte(keyNo))

	apdu = append(apdu, cmdHeader...)

	// cipherdata, err := encryptionOncommandEV1(block, cmd, cmdHeader, cryptograma,
	// 	cryptograma[len(cryptograma)-block.BlockSize():])
	// if err != nil {
	// 	return nil, err
	// }

	apdu = append(apdu, cryptograma...)
	resp, err := d.Apdu(apdu)
	if err != nil {
		return err
	}
	defer func() {
		d.cmdCtr++
	}()
	if err := VerifyResponse(resp); err != nil {
		return err
	}

	return nil
}

// ChangeKey depending on the currently selectd AID, this command
// update a key of the PICC or of an application keyset.
func (d *desfire) ChangeKeyEV2(keyNo, keySetNo, keyVersion int,
	keyType KeyType, secondAppIndicator SecondAppIndicator,
	newKey, oldKey []byte) error {

	if d.evMode != EV2 {
		errors.New("only EV2 mode support")
	}

	cmd := 0xC6

	if d.currentAppID != 0 {
		keyNo = keyNo | secondAppIndicator.Int()<<7
	} else {
		keyNo = keyNo | keyType.Int()<<6
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)

	cmdHeader = append(cmdHeader, byte(keySetNo))
	cmdHeader = append(cmdHeader, byte(keyNo))

	apdu = append(apdu, cmdHeader...)

	iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
	if err != nil {
		return err
	}

	cryptograma, err := changeKeyCryptogramEV2(d.block, d.blockMac, cmd,
		keyNo, keySetNo, d.lastKey, keyType.Int(), keyVersion,
		d.cmdCtr,
		newKey, oldKey, d.ti, iv)
	if err != nil {
		return err
	}

	// cipherdata, err := encryptionOncommandEV1(block, cmd, cmdHeader, cryptograma,
	// 	cryptograma[len(cryptograma)-block.BlockSize():])
	// if err != nil {
	// 	return nil, err
	// }

	apdu = append(apdu, cryptograma...)
	resp, err := d.Apdu(apdu)
	if err != nil {
		return err
	}
	defer func() {
		d.cmdCtr++
	}()
	if err := VerifyResponse(resp); err != nil {
		return err
	}

	return nil
}

// GetKeySettings depending on the selected AID, this command retrieves
// the PICCKeySettings of the PICC or the AppKeySettings of the (primary)
// application. In addition it returns the number of keys which are configured
// for the selected application an if applicable the AppKeySettings.
func (d *desfire) GetKeySettings() ([]byte, error) {

	cmd := 0x45

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

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

// InitializeKeySet depending on the currently selected application,
// initialize the key set with specific index.
func (d *desfire) InitializeKeySet(keySetNo int, keySetType KeyType,
	secondAppIndicator SecondAppIndicator) ([]byte, error) {

	cmd := 0x56

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	cmdHeader := []byte{byte(keySetNo | secondAppIndicator.Int()<<7), byte(keySetType)}

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
		if err != nil {
			return nil, err
		}

		apdu = append(apdu, cmdHeader...)
		apdu = append(apdu, cmacT...)
	case EV1:
		apdu = append(apdu, cmdHeader...)
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

// FinalizeKeySet the currently selected application, finalize the key set with
// specific number.
func (d *desfire) FinalizeKeySet(keySetNo, keySetVersion int,
	secondAppIndicator SecondAppIndicator) error {

	cmd := 0x57

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	cmdHeader := []byte{byte(keySetNo | secondAppIndicator.Int()<<7), byte(keySetVersion)}

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmdHeader...)
		apdu = append(apdu, cmacT...)
	case EV1:
		apdu = append(apdu, cmdHeader...)
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

// RollKeySet the currently selected application, roll to the key set with
// specific number.
func (d *desfire) RollKeySet(keySetNo int, secondAppIndicator SecondAppIndicator) error {

	cmd := 0x55

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	cmdHeader := []byte{byte(keySetNo | secondAppIndicator.Int()<<7)}

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
		if err != nil {
			return err
		}

		apdu = append(apdu, cmdHeader...)
		apdu = append(apdu, cmacT...)
	case EV1:
		apdu = append(apdu, cmdHeader...)
	default:
		return errors.New("only EV1 and EV2 support")
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

// ChangeKeySettings depending on the currently selected AID, this command changes
// the PICCKeySettings of the PICC or the AppKeySettings of the application.
func (d *desfire) ChangeKeySettings(keySetting int) error {

	cmd := 0x54

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	cmdHeader := []byte{byte(keySetting)}

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
		if err != nil {
			return err
		}
		apdu = append(apdu, cmdHeader...)
		apdu = append(apdu, cmacT...)
	case EV1:
		apdu = append(apdu, cmdHeader...)
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

type KeySetOptionVersion int

const (
	AllKeySetCurrentlyAID = iota
	SpecificKeySetCurrentlyAID
	NoKeySet
)

// GetKeyVersion depending on the currently selected AID and given key number
// parameter, return key version of the key targeted or return all key set
// versions of the selected application. (not KeySetNo: keySetOption = 2,
// specific KeySet in currently AID = , all KeySet in currently AID = 0)
func (d *desfire) GetKeyVersion(keyNo, keySetNo int, keySetOption KeySetOptionVersion,
	secondAppIndicator SecondAppIndicator) ([]byte, error) {

	cmd := 0x64

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))

	keyNoByte := byte(keyNo | secondAppIndicator.Int()<<7)

	cmdHeader := make([]byte, 0)
	switch keySetOption {
	case AllKeySetCurrentlyAID:
		cmdHeader = append(cmdHeader, keyNoByte|0x01<<6)
		cmdHeader = append(cmdHeader, byte(0x01<<7))
	case SpecificKeySetCurrentlyAID:
		cmdHeader = append(cmdHeader, keyNoByte|0x01<<6)
		cmdHeader = append(cmdHeader, byte(keySetNo&(0x0F<<4)))
	case NoKeySet:
		cmdHeader = append(cmdHeader, byte(keyNoByte&(0xFF^0x01<<6)))
	}

	switch d.evMode {
	case EV2:
		cmacT, err := calcMacOnCommandEV2(d.blockMac, d.ti, byte(cmd), d.cmdCtr, cmdHeader, nil)
		if err != nil {
			return nil, err
		}

		apdu = append(apdu, cmdHeader...)
		apdu = append(apdu, cmacT...)
	case EV1:
		apdu = append(apdu, cmdHeader...)
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
