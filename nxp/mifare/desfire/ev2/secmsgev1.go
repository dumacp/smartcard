package ev2

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"log"

	"github.com/aead/cmac"
)

func encryptionOncommandEV1(block cipher.Block, cmd int, cmdHeader, cmdData, iv []byte) ([]byte, error) {

	mode := cipher.NewCBCEncrypter(block, iv)

	plaindata := make([]byte, 0)

	crcData := make([]byte, 0)
	crcData = append(crcData, byte(cmd))
	crcData = append(crcData, cmdHeader...)
	crcData = append(crcData, cmdData...)

	crc := crc32.NewIEEE().Sum(crcData)

	plaindata = append(plaindata, cmdData...)
	plaindata = append(plaindata, crc[len(crc)-4:]...)

	if len(plaindata)%block.BlockSize() != 0 {
		plaindata = append(plaindata,
			make([]byte, block.BlockSize()-len(plaindata)%block.BlockSize())...)
	}

	resp := make([]byte, len(plaindata))
	mode.CryptBlocks(resp, plaindata)

	return resp, nil
}

func calcResponseIVOnFullModeEV1(block cipher.Block,
	cmd int, cmdHeader, iv []byte) ([]byte, error) {

	data := make([]byte, 0)
	data = append(data, byte(cmd))
	data = append(data, cmdHeader...)
	// data = append(data, 0x80)
	// data = append(data, make([]byte, 6)...)

	log.Printf("datacmac: % X", data)

	res, err := cmac.Sum(data, block, 8)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func getDataOnFullModeResponseEV1(block cipher.Block, iv []byte,
	reponse []byte) []byte {

	log.Printf("IV: [% X]", iv)

	mode := cipher.NewCBCDecrypter(block, iv)
	dest := make([]byte, len(reponse[1:]))
	mode.CryptBlocks(dest, reponse[1:])

	return dest

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
