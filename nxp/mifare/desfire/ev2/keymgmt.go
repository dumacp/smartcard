package ev2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"log"
)

func changeKeyCryptogramEV2(block, blockMac cipher.Block,
	keyNo, keySetNo, authKey, keyType, keyVersion int,
	cmdCtr uint16,
	newKey, oldKey, keyEnc, keyMac, ti, iv []byte) ([]byte, error) {

	plaindata := make([]byte, 0)
	if keyNo == authKey && keySetNo == 0 {
		plaindata = append(plaindata, newKey...)
		if keyType == int(AES) {
			plaindata = append(plaindata, byte(keyVersion))
		}
		plaindata = append(plaindata, crc32.NewIEEE().Sum(plaindata)...)
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
		plaindata = append(plaindata, crc32.NewIEEE().Sum(plaindata)...)
		plaindata = append(plaindata, crc32.NewIEEE().Sum(newKey)...)
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	dest := make([]byte, len(plaindata))
	mode.CryptBlocks(dest, plaindata)

	return dest, nil
}

func changeKeyCryptogramEV1(block cipher.Block,
	cmd, keyNo, authKey, keyType, keyVersion int,
	cmdCtr uint16,
	newKey, oldKey, keyEnc, keyMac, iv []byte) ([]byte, error) {

	copyIV := make([]byte, block.BlockSize())
	copy(copyIV, iv)
	log.Printf("keyNo: %d, authKey: %d, newKey: [% X], iv: [% X], len newKey: %d",
		keyNo, authKey, newKey, iv, len(newKey))
	plaindata := make([]byte, 0)
	if keyNo == authKey {

		plaindata = append(plaindata, newKey...)
		if keyType == int(AES) {
			plaindata = append(plaindata, byte(keyVersion))
		}
		crcdata := make([]byte, 0)
		crcdata = append(crcdata, byte(cmd))
		crcdata = append(crcdata, byte(keyNo|keyType<<6))
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
	newKey, oldKey []byte) ([]byte, error) {

	cmd := 0xC4

	var cryptograma []byte
	var block cipher.Block
	var err error
	switch d.evMode {
	case EV2:
		block, err = aes.NewCipher(d.keyEnc)
		if err != nil {
			return nil, err
		}
		blockMac, err := aes.NewCipher(d.keyMac)
		if err != nil {
			return nil, err
		}
		iv, err := calcCommandIVOnFullModeEV2(d.ksesAuthEnc, d.ti, d.cmdCtr)
		if err != nil {
			return nil, err
		}
		cryptograma, err = changeKeyCryptogramEV2(block, blockMac,
			keyNo, 0, d.lastKey, keyType.Int(), keyVersion,
			d.cmdCtr,
			newKey, oldKey, d.keyEnc, d.keyMac, d.ti, iv)
		if err != nil {
			return nil, err
		}
	default:
		switch len(d.keyEnc) {
		case 8:
			key := make([]byte, 0)
			key = append(key, d.keyEnc[:]...)
			key = append(key, d.keyEnc[:]...)
			key = append(key, d.keyEnc[:]...)
			log.Printf("key 8 enc: [% X]", key)
			block, err = des.NewTripleDESCipher(key)
		case 16:
			key := make([]byte, 0)
			key = append(key, d.keyEnc[:]...)
			key = append(key, d.keyEnc[:8]...)
			log.Printf("key 16 enc: [% X]", key)
			block, err = des.NewTripleDESCipher(key)
		case 24:
			key := make([]byte, 0)
			key = append(key, d.keyEnc[:]...)
			log.Printf("key 24 enc: [% X]", key)
			block, err = des.NewTripleDESCipher(key)
		default:
			return nil, errors.New("len key is invalid")
		}
		if err != nil {
			return nil, err
		}
		cryptograma, err = changeKeyCryptogramEV1(block,
			cmd, keyNo, d.lastKey, keyType.Int(), keyVersion,
			d.cmdCtr,
			newKey, oldKey, d.keyEnc, d.keyMac, d.iv)
		if err != nil {
			return nil, err
		}
		log.Printf("cryptograma: [% X], len: %d", cryptograma, len(cryptograma))
		d.iv = cryptograma[len(cryptograma)-block.BlockSize()-1:]
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, byte(cmd))
	cmdHeader := make([]byte, 0)
	if d.currentAppID == 0x00 {
		log.Printf("keytype: %d", keyType)
		cmdHeader = append(cmdHeader, byte(keyNo|keyType.Int()<<6))
		apdu = append(apdu, cmdHeader...)
	} else {
		log.Printf("secondAppIndicator: %d", secondAppIndicator)
		cmdHeader = append(cmdHeader, byte(keyNo|secondAppIndicator.Int()<<7))
		apdu = append(apdu, cmdHeader...)
	}

	// cipherdata, err := encryptionOncommandEV1(block, cmd, cmdHeader, cryptograma,
	// 	cryptograma[len(cryptograma)-block.BlockSize():])
	// if err != nil {
	// 	return nil, err
	// }

	apdu = append(apdu, cryptograma...)
	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	defer func() {
		d.cmdCtr++
	}()
	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// GetKeySettings depending on the selected AID, this command retrieves
// the PICCKeySettings of the PICC or the AppKeySettings of the (primary)
// application. In addition it returns the number of keys which are configured
// for the selected application an if applicable the AppKeySettings.
func (d *desfire) GetKeySettings() ([]byte, error) {

	cmd := byte(0x45)

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd)
	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}

	return resp, nil
}
