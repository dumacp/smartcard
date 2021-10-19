package ev2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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
	return dest
}
