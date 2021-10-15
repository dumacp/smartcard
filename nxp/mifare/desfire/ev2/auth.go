package ev2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"log"
	"math/rand"
	"time"

	"github.com/aead/cmac"
)

func Apdu_AuthenticateISO(secondAppIndicator int, keyNumber int) []byte {
	cmd := byte(0x1A)
	keyNo := byte(keyNumber) | byte(secondAppIndicator<<7)

	apdu := make([]byte, 0)

	apdu = append(apdu, cmd)
	apdu = append(apdu, keyNo)

	return apdu
}

// AuthenticateISO authentication as already support by DESFire EV1. Only for KeyType.2TDEA
// or KeyType.3TDEA keys. After this authentication EV1 backwards compatible secure
// messaging is used.
func (d *desfire) AuthenticateISO(secondAppIndicator int, keyNumber int) ([]byte, error) {

	apdu := Apdu_AuthenticateISO(secondAppIndicator, keyNumber)

	d.lastKey = keyNumber

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}

	if err := VerifyResponse(resp); err != nil {
		return resp, err
	}

	return resp, nil
}

func Apdu_AuthenticateISOPart2(cryptograma []byte) []byte {
	cmd := byte(0xAF)

	apdu := make([]byte, 0)

	apdu = append(apdu, cmd)
	apdu = append(apdu, cryptograma...)

	return apdu

}

func (d *desfire) AuthenticateISOPart2(key, data []byte) ([]byte, error) {

	if len(key) == 16 {
		key = append(key, key[:8]...)
	}

	rand.Seed(time.Now().UnixNano())

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, block.BlockSize())

	mode := cipher.NewCBCDecrypter(block, iv)
	// modeD := cipher.NewCBCDecrypter(block, iv)

	// log.Printf("aid1 response: [ %X ], apdu: [ %X ]", response, aid1)
	rndBC := data[1:]

	rndB := make([]byte, len(rndBC))
	mode.CryptBlocks(rndB, rndBC)
	rndBr := make([]byte, len(rndB))
	copy(rndBr, rndB)
	rndBr = append(rndBr, rndBr[0])
	rndBr = rndBr[1:]
	log.Printf("rotate rndB: [ %X ], [ %X ]", rndB, rndBr)
	rndA := make([]byte, len(rndB))
	rand.Read(rndA)
	log.Printf("origin rndA: [ %X ]", rndA)

	rndD := make([]byte, 0)

	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	rndDc := make([]byte, len(rndD))
	mode = cipher.NewCBCEncrypter(block, rndBC[len(rndBC)-block.BlockSize():])
	mode.CryptBlocks(rndDc, rndD)

	//fmt.Printf("aid2: [% X]\n", aid2)
	apdu := Apdu_AuthenticateISOPart2(rndDc)
	resp, err := d.Apdu(apdu)
	if err != nil {
		log.Printf("fail response: [ %X ], apdu: [ %X ]", resp, apdu)
		return nil, err
	}

	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}

	piccRndA := make([]byte, len(resp[1:]))
	mode = cipher.NewCBCDecrypter(block, rndDc[len(rndDc)-block.BlockSize():])
	mode.CryptBlocks(piccRndA, resp[1:])

	log.Printf("origin rndA: [ %X ]", rndA)
	log.Printf("respon rndA: [ %X ]", piccRndA)

	d.evMode = EV1
	d.iv = make([]byte, block.BlockSize())

	kex := make([]byte, 0)
	// kex = append(kex, rndA[4:8]...)
	// kex = append(kex, rndB[4:8]...)
	kex = append(kex, rndA[0:4]...)
	kex = append(kex, rndB[0:4]...)
	// kex = append(kex, rndA[4:8]...)
	// kex = append(kex, rndB[4:8]...)

	// for _, i := range []int{7, 6, 5, 4} {
	// 	kex = append(kex, rndA[i])
	// }
	// for _, i := range []int{7, 6, 5, 4} {
	// 	kex = append(kex, rndB[i])
	// }
	// for _, i := range []int{3, 2, 1, 0} {
	// 	kex = append(kex, rndA[i])
	// }
	// for _, i := range []int{3, 2, 1, 0} {
	// 	kex = append(kex, rndB[i])
	// }
	// for _, i := range []int{7, 6, 5, 4} {
	// 	kex = append(kex, rndA[i])
	// }
	// for _, i := range []int{7, 6, 5, 4} {
	// 	kex = append(kex, rndB[i])
	// }

	d.cmdCtr = 0

	switch len(kex) {
	case 8:
		key := make([]byte, 0)
		key = append(key, kex...)
		key = append(key, kex...)
		key = append(key, kex...)
		log.Printf("key 8 enc: [% X]", key)
		d.keyEnc = key
		block, err = des.NewTripleDESCipher(key)
	case 16:
		key := make([]byte, 0)
		key = append(key, kex...)
		key = append(key, kex[:8]...)
		log.Printf("key 16 enc: [% X]", key)
		d.keyEnc = key
		block, err = des.NewTripleDESCipher(key)
	case 24:
		key := make([]byte, 0)
		key = append(key, kex[:]...)
		log.Printf("key 24 enc: [% X]", key)
		d.keyEnc = key
		block, err = des.NewTripleDESCipher(key)
	default:
		return resp, errors.New("len key is invalid")
	}
	if err != nil {
		return resp, err
	}
	d.block = block
	return resp, nil
}

func Apdu_AuthenticateEV2First(secondAppIndicator int, keyNumber int, pcdCap2 []byte) []byte {
	cmd := byte(0x71)
	keyNo := byte(keyNumber) | byte(secondAppIndicator<<7)

	lenCap := byte(0x00)

	if len(pcdCap2) > 0 {
		lenCap = byte(len(pcdCap2))
	}

	apdu := make([]byte, 0)

	apdu = append(apdu, cmd)
	apdu = append(apdu, keyNo)
	apdu = append(apdu, lenCap)
	apdu = append(apdu, pcdCap2...)

	return apdu
}

func Apdu_AuthenticateEV2FirstPart2(data []byte) []byte {
	cmd := 0xAF
	apdu := make([]byte, 0)

	apdu = append(apdu, byte(cmd))
	apdu = append(apdu, data...)

	return apdu
}

// AuthenticateEV2First authentication for Keytype AES keys. After this authentication EV2 secure
// messaging is used. This authentication in intended to be the first in a transaction.
func (d *desfire) AuthenticateEV2First(secondAppIndicator int, keyNumber int, pcdCap2 []byte) ([]byte, error) {

	apdu := Apdu_AuthenticateEV2First(secondAppIndicator, keyNumber, pcdCap2)

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}

	if err := VerifyResponse(resp); err != nil {
		return resp, err
	}

	d.pcdCap2 = pcdCap2

	return resp, nil
}

func (d *desfire) AuthenticateEV2FirstPart2(key, data []byte) ([]byte, error) {

	rand.Seed(time.Now().UnixNano())

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, block.BlockSize())

	mode := cipher.NewCBCDecrypter(block, iv)
	// modeE := cipher.NewCBCEncrypter(block, iv)
	// modeD := cipher.NewCBCDecrypter(block, iv)

	// log.Printf("aid1 response: [ %X ], apdu: [ %X ]", response, aid1)
	rndBC := data[1:]

	rndB := make([]byte, len(rndBC))
	mode.CryptBlocks(rndB, rndBC)
	rndBr := make([]byte, len(rndB))
	copy(rndBr, rndB)
	rndBr = append(rndBr, rndBr[0])
	rndBr = rndBr[1:]
	log.Printf("rotate rndB: [ %X ], [ %X ]", rndB, rndBr)
	rndA := make([]byte, len(rndB))
	rand.Read(rndA)
	log.Printf("origin rndA: [ %X ]", rndA)

	rndD := make([]byte, 0)

	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	rndDc := make([]byte, len(rndD))
	// mode = cipher.NewCBCEncrypter(block, rndBC[:])
	mode = cipher.NewCBCEncrypter(block, iv[:])
	mode.CryptBlocks(rndDc, rndD)

	//fmt.Printf("aid2: [% X]\n", aid2)
	apdu := Apdu_AuthenticateEV2FirstPart2(rndDc)
	resp, err := d.Apdu(apdu)
	if err != nil {
		log.Printf("fail response: [ %X ], apdu: [ %X ]", resp, apdu)
		return nil, err
	}

	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}

	lastResp := make([]byte, len(resp[1:]))
	// mode = cipher.NewCBCDecrypter(block, rndDc[len(rndDc)-block.BlockSize():])
	mode = cipher.NewCBCDecrypter(block, iv[:])
	mode.CryptBlocks(lastResp, resp[1:])
	log.Printf("response last: [ %X ]", lastResp)

	d.ti = make([]byte, 0)
	d.ti = append(d.ti, lastResp[:4]...)

	log.Printf("origin rndA: [ %X ]", rndA)
	log.Printf("respon rndA: [ %X ]", lastResp[4:len(rndA)+4])

	d.pdCap2 = make([]byte, 0)
	d.pdCap2 = append(d.pdCap2, lastResp[len(lastResp)-6:]...)

	d.evMode = EV2

	sv1 := []byte{0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80}
	sv2 := []byte{0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80}

	trailing := make([]byte, 0)
	trailing = append(trailing, rndA[0:2]...)
	xor := make([]byte, 0)
	for _, indx := range []int{2, 3, 4, 5, 6, 7} {
		xor = append(xor, rndA[indx])
	}
	for i, v := range rndB[0:6] {
		trailing = append(trailing, xor[i]^v)
	}
	trailing = append(trailing, rndB[6:]...)
	trailing = append(trailing, rndA[8:]...)

	sv1 = append(sv1, trailing...)
	sv2 = append(sv2, trailing...)

	blockMack, err := aes.NewCipher(key)
	if err != nil {
		return resp, err
	}

	ksesAuthEnc, err := cmac.Sum(sv1, blockMack, 16)
	if err != nil {
		return resp, err
	}
	d.ksesAuthEnc = ksesAuthEnc

	ksesAuthMac, err := cmac.Sum(sv2, blockMack, 16)
	if err != nil {
		return resp, err
	}
	d.ksesAuthMac = ksesAuthMac

	d.block, err = aes.NewCipher(ksesAuthEnc)
	if err != nil {
		return resp, err
	}
	d.blockMac, err = aes.NewCipher(ksesAuthMac)
	if err != nil {
		return resp, err
	}

	d.cmdCtr = 0

	return resp, nil
}

func (d *desfire) AuthenticateEV2NonFirst() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (d *desfire) AuthenticateEV2NonFirstPart2() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}
