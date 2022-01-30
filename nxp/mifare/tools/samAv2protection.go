package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/aead/cmac"
	"github.com/nmelo/smartcard"
)

//EncryptFullProtection function to Encrypted data in full protection mode
func EncryptFullProtection(cmdCtr int, data, ke []byte) ([]byte, error) {

	lenBlock := len(ke)

	if lenBlock%8 != 0 || len(ke)%8 != 0 {
		return nil, fmt.Errorf("key len is wrong")
	}

	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}

	vCmdCtr := make([]byte, 4)
	binary.BigEndian.PutUint32(vCmdCtr, uint32(cmdCtr))
	ivMac := make([]byte, 16)
	//iv := []byte{0x01, 0x01, 0x01, 0x01}
	iv := make([]byte, 0)
	iv = append(iv, vCmdCtr...)
	iv = append(iv, vCmdCtr...)
	iv = append(iv, vCmdCtr...)
	iv = append(iv, []byte{0x01, 0x01, 0x01, 0x01}...)

	modeMac := cipher.NewCBCEncrypter(block, ivMac)
	ivEnc := make([]byte, 16)
	modeMac.CryptBlocks(ivEnc, iv)

	mode := cipher.NewCBCEncrypter(block, ivEnc)

	log.Printf("data    : [ %X ], len: %d", data, len(data))

	if mod := len(data) % lenBlock; mod != 0 {
		data = append(data, 0x80)
		data = append(data, make([]byte, lenBlock-mod-1)...)
	}

	dst := make([]byte, len(data))

	mode.CryptBlocks(dst, data)

	log.Printf("dataload: [ %X ], len: %d", data, len(data))

	return dst, nil
}

//MacFullProtection function to calculated the CMAC in full protection mode
func MacFullProtection(cmd smartcard.ISO7816cmd, cmdCtr int, data, key []byte) ([]byte, error) {

	lenBlock := len(key)

	log.Printf("cmdCtr: %d", cmdCtr)
	log.Printf("km: [ %X ]", key)

	if lenBlock%8 != 0 {
		return nil, fmt.Errorf("key len is wrong")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	dataMac := make([]byte, 0)
	dataMac = append(dataMac, cmd.CLA)
	dataMac = append(dataMac, cmd.INS)
	ctrBuff := make([]byte, 4)
	binary.BigEndian.PutUint32(ctrBuff, uint32(cmdCtr))
	dataMac = append(dataMac, ctrBuff...)
	dataMac = append(dataMac, cmd.P1)
	dataMac = append(dataMac, cmd.P2)
	if data != nil {
		dataMac = append(dataMac, byte(0x08+len(data)))
		dataMac = append(dataMac, data...)
	} else {
		dataMac = append(dataMac, 0x08)
	}

	//if mod := len(dataMac) % 16; mod != 0 {
	//	padding := make([]byte, 16-mod)
	//	dataMac = append(dataMac, padding...)
	//}
	log.Printf("cmacload: [ %X ], len: %d", dataMac, len(dataMac))
	log.Printf("data    : [ %X ], len: %d", data, len(data))
	//if mod := len(dataMac) % lenBlock; mod != 0 {
	//	dataMac = append(dataMac, make([]byte, lenBlock-mod)...)
	//}
	//log.Printf("cmacload: [ %X ], len: %d", dataMac, len(dataMac))

	cmac16, err := cmac.Sum(dataMac, block, lenBlock)
	if err != nil {
		return nil, err
	}

	cmac8 := make([]byte, 0)
	for i, v := range cmac16 {
		if i%2 != 0 {
			cmac8 = append(cmac8, v)
		}
	}
	// cmac8 := cmac16[0:8]

	return cmac8, nil
}

func offlineChangeKeyCalculateMacKey(kc []byte, changeCtr int) ([]byte, error) {
	lenBlock := len(kc)
	if lenBlock%8 != 0 || len(kc)%8 != 0 {
		return nil, fmt.Errorf("key len is wrong")
	}

	block, err := aes.NewCipher(kc)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, len(kc))
	mode := cipher.NewCBCEncrypter(block, iv)

	changeCtrSlice := make([]byte, 2)
	binary.BigEndian.PutUint16(changeCtrSlice, uint16(changeCtr))

	sv2Fuffix := []byte{0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72}
	sv2 := make([]byte, 0)
	sv2 = append(sv2, changeCtrSlice...)
	sv2 = append(sv2, sv2Fuffix...)

	kcm := make([]byte, len(sv2))
	mode.CryptBlocks(kcm, sv2)
	return kcm, nil
}

func offlineChangeKeyCalculateEncriptionKey(kc []byte, changeCtr int) ([]byte, error) {
	lenBlock := len(kc)
	if lenBlock%8 != 0 || len(kc)%8 != 0 {
		return nil, fmt.Errorf("key len is wrong")
	}

	block, err := aes.NewCipher(kc)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, len(kc))
	mode := cipher.NewCBCEncrypter(block, iv)

	changeCtrSlice := make([]byte, 2)
	binary.BigEndian.PutUint16(changeCtrSlice, uint16(changeCtr))

	sv1Fuffix := []byte{0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71}
	sv1 := make([]byte, 0)
	sv1 = append(sv1, changeCtrSlice...)
	sv1 = append(sv1, sv1Fuffix...)

	kce := make([]byte, len(sv1))
	mode.CryptBlocks(kce, sv1)
	return kce, nil
}

//OfflineChangeKeyEncrypt function to Encrypt data in full OfflineChangeKey
func OfflineChangeKeyEncrypt(data, kc, samUID []byte, changeCtr int) ([]byte, error) {

	kce, err := offlineChangeKeyCalculateEncriptionKey(kc, changeCtr)
	if err != nil {
		return nil, err
	}

	lenBlock := len(kc)
	if lenBlock%8 != 0 || len(kc)%8 != 0 {
		return nil, fmt.Errorf("key len is wrong")
	}

	block, err := aes.NewCipher(kce)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, lenBlock)
	mode := cipher.NewCBCEncrypter(block, iv)

	if samUID != nil {
		data = append(data, samUID...)
	}

	log.Printf("data   : [ %X ]", data)

	if mod := len(data) % lenBlock; mod != 0 {
		data = append(data, 0x80)
		data = append(data, make([]byte, lenBlock-mod-1)...)
	}
	log.Printf("data   : [ %X ]", data)

	dst := make([]byte, len(data))

	mode.CryptBlocks(dst, data)

	return dst, nil
}

//OfflineChangeKeyMac function to have Macing data in full OfflineChangeKey
func OfflineChangeKeyMac(data, kc []byte, changeCtr int) ([]byte, error) {

	kcm, err := offlineChangeKeyCalculateMacKey(kc, changeCtr)
	if err != nil {
		return nil, err
	}

	lenBlock := len(kc)
	if lenBlock%8 != 0 || len(kc)%8 != 0 {
		return nil, fmt.Errorf("key len is wrong")
	}

	block, err := aes.NewCipher(kcm)
	if err != nil {
		return nil, err
	}

	cmacS, err := cmac.Sum(data, block, lenBlock)
	if err != nil {
		return nil, err
	}

	cmacT := make([]byte, 0)
	for i, v := range cmacS {
		if i%2 != 0 {
			cmacT = append(cmacT, v)
		}
	}

	return cmacT, nil
}
