package ev2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"log"

	"github.com/aead/cmac"
)

func calcResponseIVOnFullModeEV2(ksesAuthEnc, ti []byte, cmdCtr uint16) ([]byte, error) {

	block, err := aes.NewCipher(ksesAuthEnc)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 0)

	ctr := make([]byte, 2)
	binary.LittleEndian.PutUint16(ctr, cmdCtr)

	iv = append(iv, 0x5A)
	iv = append(iv, 0xA5)
	iv = append(iv, ti...)
	iv = append(iv, ctr...)
	iv = append(iv, make([]byte, block.BlockSize()-(2+len(ti)+len(ctr)))...)

	mode := cipher.NewCBCEncrypter(block, make([]byte, block.BlockSize()))

	resp := make([]byte, len(iv))
	mode.CryptBlocks(resp, iv)

	return resp, nil
}

func calcCommandIVOnFullModeEV2(ksesAuthEnc, ti []byte, cmdCtr uint16) ([]byte, error) {

	block, err := aes.NewCipher(ksesAuthEnc)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 0)

	ctr := make([]byte, 2)
	binary.LittleEndian.PutUint16(ctr, cmdCtr)

	iv = append(iv, 0xA5)
	iv = append(iv, 0x5A)
	iv = append(iv, ti...)
	iv = append(iv, ctr...)
	iv = append(iv, make([]byte, block.BlockSize()-(2+len(ti)+len(ctr)))...)

	mode := cipher.NewCBCEncrypter(block, make([]byte, block.BlockSize()))

	resp := make([]byte, len(iv))
	mode.CryptBlocks(resp, iv)

	return resp, nil
}

func calcMacOnCommandEV2(block cipher.Block, ti []byte,
	cmd byte, cmdCtr uint16, cmdHeader, data []byte) ([]byte, error) {
	datamac := make([]byte, 0)

	datamac = append(datamac, cmd)

	cmdCtrBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(cmdCtrBytes, cmdCtr)
	datamac = append(datamac, cmdCtrBytes...)
	datamac = append(datamac, ti...)
	datamac = append(datamac, cmdHeader...)
	datamac = append(datamac, data...)

	// if len(datamac)%block.BlockSize() != 0 {
	// 	datamac = append(datamac, 0x80)
	// 	datamac = append(datamac,
	// 		make([]byte, block.BlockSize()-len(datamac)%block.BlockSize())...)
	// }

	log.Printf("data in cmac: [% X]", datamac)

	result, err := cmac.Sum(datamac, block, block.BlockSize())
	if err != nil {
		return nil, err
	}

	log.Printf("long cmac: [% X]", result)

	cmacT := make([]byte, 0)
	for i, v := range result {
		if i%2 != 0 {
			cmacT = append(cmacT, v)
		}
	}

	log.Printf("truncate cmac: [% X]", cmacT)

	return cmacT, nil
}

func calcMacOnResponseEV2(block cipher.Block, ti []byte,
	rc byte, cmdCtr uint16, data []byte) ([]byte, error) {
	datamac := make([]byte, 0)

	datamac = append(datamac, rc)

	cmdCtrBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(cmdCtrBytes, cmdCtr)
	datamac = append(datamac, cmdCtrBytes...)
	datamac = append(datamac, ti...)
	datamac = append(datamac, data...)

	// if len(datamac)%block.BlockSize() != 0 {
	// 	datamac = append(datamac, 0x80)
	// 	datamac = append(datamac,
	// 		make([]byte, block.BlockSize()-len(datamac)%block.BlockSize())...)
	// }

	log.Printf("data in cmac: [% X]", datamac)

	result, err := cmac.Sum(datamac, block, block.BlockSize())
	if err != nil {
		return nil, err
	}

	log.Printf("long cmac: [% X]", result)

	cmacT := make([]byte, 0)
	for i, v := range result {
		if i%2 != 0 {
			cmacT = append(cmacT, v)
		}
	}

	log.Printf("truncate cmac: [% X]", cmacT)

	return cmacT, nil
}

func getDataOnFullModeResponseEV2(block cipher.Block, iv []byte,
	reponse []byte) []byte {

	mode := cipher.NewCBCDecrypter(block, iv)

	dest := make([]byte, len(reponse[1:len(reponse)-8]))
	mode.CryptBlocks(dest, reponse[1:len(reponse)-8])
	log.Printf("palindata EV2: [% X], len: %d", dest, len(dest))
	return dest
}

func calcCryptogramEV2(block cipher.Block, plaindata, iv []byte) []byte {
	switch {

	case len(plaindata)%block.BlockSize() == 0:
		plaindata = append(plaindata, 0x80)
		plaindata = append(plaindata,
			make([]byte, block.BlockSize()-len(plaindata)%block.BlockSize())...)
	case len(plaindata)%block.BlockSize() == block.BlockSize()-1:
		plaindata = append(plaindata, []byte{0x80, 0x00}...)
		plaindata = append(plaindata,
			make([]byte, block.BlockSize()-len(plaindata)%block.BlockSize())...)
	case len(plaindata)%block.BlockSize() != 0 &&
		len(plaindata)%block.BlockSize() != block.BlockSize()-1:
		plaindata = append(plaindata, 0x80)
		plaindata = append(plaindata,
			make([]byte, block.BlockSize()-len(plaindata)%block.BlockSize())...)

	}
	mode := cipher.NewCBCEncrypter(block, iv)
	dest := make([]byte, len(plaindata))
	mode.CryptBlocks(dest, plaindata)
	log.Printf("palindata EV2: [% X], len: %d", plaindata, len(plaindata))
	log.Printf("crytogram EV2: [% X], len: %d", dest, len(dest))
	return dest
}

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
