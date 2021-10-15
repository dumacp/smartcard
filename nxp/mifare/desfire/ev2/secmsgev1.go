package ev2

import (
	"crypto/cipher"
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
