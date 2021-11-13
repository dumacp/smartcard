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
func (d *Desfire) AuthenticateISO(secondAppIndicator SecondAppIndicator, keyNumber int) ([]byte, error) {

	apdu := Apdu_AuthenticateISO(secondAppIndicator.Int(), keyNumber)

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

func (d *Desfire) AuthenticateISOPart2(key, data []byte) ([]byte, error) {

	if len(key) == 16 {
		key = append(key, key[:8]...)
	}
	if len(data) < 8 {
		return nil, errors.New("nil data")
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
func (d *Desfire) AuthenticateEV2First(secondAppIndicator SecondAppIndicator, keyNumber int, pcdCap2 []byte) ([]byte, error) {

	apdu := Apdu_AuthenticateEV2First(secondAppIndicator.Int(), keyNumber, pcdCap2)

	resp, err := d.Apdu(apdu)
	if err != nil {
		return nil, err
	}

	if err := VerifyResponse(resp); err != nil {
		return resp, err
	}

	d.pcdCap2 = pcdCap2
	d.lastKey = keyNumber

	return resp[1:], nil
}

func (d *Desfire) AuthenticateEV2FirstPart2(key, data []byte) ([]byte, error) {

	log.Printf("key: %X", key)
	log.Printf("data: %X", data)

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
	rndBC := data[:]

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

	log.Printf("TI: [ %X ]", d.ti)

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

	blockEnc, err := aes.NewCipher(key)
	if err != nil {
		return resp, err
	}

	ksesAuthEnc, err := cmac.Sum(sv1, blockEnc, 16)
	if err != nil {
		return resp, err
	}
	d.ksesAuthEnc = ksesAuthEnc

	blockMack, err := aes.NewCipher(key)
	if err != nil {
		return resp, err
	}

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

func (d *Desfire) AuthenticateEV2FirstPart2_block_1(rndB []byte) ([]byte, error) {

	rand.Seed(time.Now().UnixNano())

	// block, err := aes.NewCipher(key)
	// if err != nil {
	// 	return nil, err
	// }
	// iv := make([]byte, block.BlockSize())

	// mode := cipher.NewCBCDecrypter(block, iv)

	// rndBC := data[1:]

	// rndB := make([]byte, len(rndBC))
	// mode.CryptBlocks(rndB, rndBC)
	d.rndB = make([]byte, len(rndB))
	copy(d.rndB, rndB)
	rndBr := make([]byte, len(rndB))
	copy(rndBr, rndB)
	rndBr = append(rndBr, rndBr[0])
	rndBr = rndBr[1:]
	log.Printf("rotate rndB: [ %X ], [ %X ]", rndB, rndBr)
	rndA := make([]byte, len(rndB))
	rand.Read(rndA)
	d.rndA = make([]byte, len(rndA))
	copy(d.rndA, rndA)
	log.Printf("origin rndA: [ %X ]", rndA)

	rndD := make([]byte, 0)

	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	return rndD, nil

}
func (d *Desfire) AuthenticateEV2FirstPart2_block_2(rndDc []byte) ([]byte, error) {

	apdu := Apdu_AuthenticateEV2FirstPart2(rndDc)
	resp, err := d.Apdu(apdu)
	if err != nil {
		log.Printf("fail response: [ %X ], apdu: [ %X ]", resp, apdu)
		return nil, err
	}

	if err := VerifyResponse(resp); err != nil {
		return nil, err
	}

	return resp[1:], nil

}
func (d *Desfire) AuthenticateEV2FirstPart2_block_3(lastResp []byte) ([]byte, []byte, error) {

	d.ti = make([]byte, 0)
	d.ti = append(d.ti, lastResp[:4]...)

	log.Printf("TI: [ %X ]", d.ti)

	d.pdCap2 = make([]byte, 0)
	d.pdCap2 = append(d.pdCap2, lastResp[len(lastResp)-6:]...)

	d.evMode = EV2

	sv1 := []byte{0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80}
	sv2 := []byte{0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80}

	trailing := make([]byte, 0)
	trailing = append(trailing, d.rndA[0:2]...)
	xor := make([]byte, 0)
	for _, indx := range []int{2, 3, 4, 5, 6, 7} {
		xor = append(xor, d.rndA[indx])
	}
	for i, v := range d.rndB[0:6] {
		trailing = append(trailing, xor[i]^v)
	}
	trailing = append(trailing, d.rndB[6:]...)
	trailing = append(trailing, d.rndA[8:]...)

	sv1 = append(sv1, trailing...)
	sv2 = append(sv2, trailing...)

	return sv1, sv2, nil
}
func (d *Desfire) AuthenticateEV2FirstPart2_block_4(ksesAuthEnc, ksesAuthMac []byte) error {

	var err error
	d.ksesAuthEnc = make([]byte, len(ksesAuthEnc))
	copy(d.ksesAuthEnc, ksesAuthEnc)

	d.ksesAuthMac = make([]byte, len(ksesAuthMac))
	copy(d.ksesAuthMac, ksesAuthMac)

	d.block, err = aes.NewCipher(ksesAuthEnc)
	if err != nil {
		return err
	}
	d.blockMac, err = aes.NewCipher(ksesAuthMac)
	if err != nil {
		return err
	}

	d.cmdCtr = 0

	return nil
}

func (d *Desfire) AuthenticateEV2NonFirst() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (d *Desfire) AuthenticateEV2NonFirstPart2() ([]byte, error) {
	panic("not implemented") // TODO: Implement
}
