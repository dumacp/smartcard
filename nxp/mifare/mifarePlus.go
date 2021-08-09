/**
Implementation to mifare smartcard family (Mifare Plus, Desfire, SamAV2, ...)
/**/
package mifare

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"time"

	"github.com/aead/cmac"
	"github.com/dumacp/smartcard"
)

//MifarePlus MifarePlus Interface
type MifarePlus interface {
	smartcard.ICard
	WritePerso(int, []byte) ([]byte, error)
	CommitPerso() ([]byte, error)
	FirstAuthf1(keyBNr int) ([]byte, error)
	FirstAuthf2([]byte) ([]byte, error)
	FirstAuth(keyBNr int, key []byte) ([]byte, error)
	ReadPlainMacMac(bNr, ext int) ([]byte, error)
	ReadPlainMacUnMacCommand(bNr, ext int) ([]byte, error)
	ReadEncMacMac(bNr, ext int) ([]byte, error)
	WriteEncMacMac(bNr int, data []byte) error
	IncTransfEncMacMac(bNr int, data []byte) error
	DecTransfEncMacMac(bNr int, data []byte) error
	TransfMacMac(bNr int) error
	KeyEnc(key []byte)
	KeyMac(key []byte)
	Ti(ti []byte)
	ReadCounter(counter int)
	WriteCounter(counter int)
}

type mifarePlus struct {
	smartcard.ICard
	keyMac       []byte
	keyEnc       []byte
	readCounter  int
	writeCounter int
	ti           []byte
}

//ConnectMplus Create Mifare Plus Interface
func ConnectMplus(r smartcard.IReader) (MifarePlus, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	mplus := &mifarePlus{
		ICard: c,
	}
	return mplus, nil
}

//Mplus Create Mifare Plus Interface
func Mplus(c smartcard.ICard) MifarePlus {

	// c, err := r.ConnectCard()
	// if err != nil {
	// 	return nil, err
	// }
	mplus := &mifarePlus{
		ICard: c,
	}
	return mplus
}

/**/
//Valid response: response[0] == 0x90
func verifyResponse(data []byte) error {
	if len(data) <= 0 {
		return fmt.Errorf("null response")
	}
	if data[0] != 0x90 {
		return fmt.Errorf("error in response SC: %X, response [% X]", data[0], data)
	}
	return nil
}

func (mplus *mifarePlus) KeyEnc(key []byte) {
	mplus.keyEnc = key
}

func (mplus *mifarePlus) KeyMac(key []byte) {
	mplus.keyMac = key
}

func (mplus *mifarePlus) Ti(ti []byte) {
	mplus.ti = ti
}

func (mplus *mifarePlus) ReadCounter(counter int) {
	mplus.readCounter = counter
}

func (mplus *mifarePlus) WriteCounter(counter int) {
	mplus.writeCounter = counter
}

//Write Perso (Security Level 0)
func (mplus *mifarePlus) WritePerso(bNr int, key []byte) ([]byte, error) {
	keyB1 := byte((bNr >> 8) & 0xFF)
	keyB2 := byte(bNr & 0xFF)
	aid := []byte{0xA8, keyB2, keyB1}
	aid = append(aid, key...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	return response, nil
}

//Commit Perso (Security Level 0)
func (mplus *mifarePlus) CommitPerso() ([]byte, error) {
	aid := []byte{0xAA}
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	return response, nil
}

//First Authentication first step
func (mplus *mifarePlus) FirstAuthf1(keyBNr int) ([]byte, error) {
	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)
	aid := []byte{0x70, keyB2, keyB1, 0x00}
	// aid := []byte{0x70, keyB2, keyB1, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	//fmt.Printf("aid: [% X]", aid)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	// fmt.Printf("response: [% X]\n", response)
	return response[1:], nil
}

//First Authentication second step
func (mplus *mifarePlus) FirstAuthf2(data []byte) ([]byte, error) {
	aid := make([]byte, 0)
	aid = append(aid, byte(0x72))
	aid = append(aid, data...)
	// fmt.Printf("f2 aid: [% X]\n", aid)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	/**/
	/**/
	// fmt.Printf("response: [% X]\n", response)
	return response[1:], nil
}

//Following Authentication first Step
func (mplus *mifarePlus) FallowAuthf1(keyBNr int) ([]byte, error) {
	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)
	aid := []byte{0x76, keyB2, keyB1, 0x00}
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	return response[1:], nil
}

//Following Authentication second Step
func (mplus *mifarePlus) FallowtAuthf2(data []byte) ([]byte, error) {
	aid := []byte{0x72}
	aid = append(aid, data...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	return response[1:], nil
}

//First Authentication (All in)
func (mplus *mifarePlus) FirstAuth(keyBNr int, key []byte) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	response, err := mplus.FirstAuthf1(keyBNr)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("resp: [% X]\n", response)
	rndBc := response
	// fmt.Printf("rndBc: [% X]\n", rndBc)

	iv := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	rndB := make([]byte, 16)
	modeD.CryptBlocks(rndB, rndBc)
	fmt.Printf("rndB: [% X]\n", rndB)

	//rotate rndB
	rndBr := make([]byte, 16)
	copy(rndBr, rndB)
	rndBr = append(rndBr, rndBr[0])
	rndBr = rndBr[1:]
	// fmt.Printf("rndBrot: [% X]\n", rndBr)

	rndA := make([]byte, 16)
	rand.Read(rndA)
	fmt.Printf("rndA: [% X]\n", rndA)

	rndD := make([]byte, 0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)
	// fmt.Printf("rndD: [% X]\n", rndD)

	rndDc := make([]byte, len(rndD))
	modeE.CryptBlocks(rndDc, rndD)
	//fmt.Printf("rndDc: [% X]\n", rndDc)

	response, err = mplus.FirstAuthf2(rndDc)
	if err != nil {
		return nil, err
	}

	keyEnc, keyMac, err := calcSessionKeyEV0(rndA, rndB, key)
	if err != nil {
		return nil, err
	}

	mplus.keyMac = keyMac
	mplus.keyEnc = keyEnc

	result := make([]byte, len(response))
	modeD = cipher.NewCBCDecrypter(block, iv)
	modeD.CryptBlocks(result, response[:])

	fmt.Printf("result: [% X]\n", result)

	ti := make([]byte, 4)

	copy(ti, result[0:4])

	mplus.Ti(ti)

	return response, nil
}

//Read in plain, MAC on response, MAC on command
func (mplus *mifarePlus) ReadPlainMacMac(bNr, ext int) ([]byte, error) {

	cmd := byte(0x33)
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	cmac1, err := mplus.macReadCommand(byte(cmd), bNr, ext)
	if err != nil {
		return nil, err
	}

	fmt.Printf("cmac: [% X]\n", cmac1)

	aid := []byte{cmd, bNB2, bNB1, byte(ext)}
	aid = append(aid, cmac1...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}

	data := response[1 : len(response)-8]
	macResp := response[len(response)-8:]

	cmac2, err := mplus.macReadResponse(response[0], bNr, ext, data)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(macResp, cmac2) {
		return nil, fmt.Errorf("mac fail in response, response: [% X]", response)
	}

	mplus.readCounter++

	return data, nil
}

//Read in plain, MAC on response, MAC on command
func (mplus *mifarePlus) ReadPlainMacUnMacCommand(bNr, ext int) ([]byte, error) {

	cmd := byte(0x37)
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	// cmac1, err := mplus.macReadCommand(byte(cmd), bNr, ext)
	// if err != nil {
	// 	return nil, err
	// }

	// fmt.Printf("cmac: [% X]\n", cmac1)

	aid := []byte{cmd, bNB2, bNB1, byte(ext)}
	// aid = append(aid, cmac1...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}

	data := response[1 : len(response)-8]
	macResp := response[len(response)-8:]

	cmac2, err := mplus.macReadResponse(cmd, bNr, ext, data)
	if err != nil {
		return nil, err
	}
	fmt.Printf("cmac: [% X]\n", cmac2)

	if !bytes.Equal(macResp, cmac2) {
		return nil, fmt.Errorf("mac fail in response, response: [% X]", response)
	}

	mplus.readCounter++

	return data, nil
}

//Read encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) ReadEncMacMac(bNr, ext int) ([]byte, error) {

	cmd := byte(0x31)
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	cmac1, err := mplus.macReadCommand(byte(cmd), bNr, ext)
	if err != nil {
		return nil, err
	}

	aid := []byte{cmd, bNB2, bNB1, byte(ext)}
	aid = append(aid, cmac1...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}

	dataE := response[1 : len(response)-8]
	macResp := response[len(response)-8:]

	cmac2, err := mplus.macReadResponse(response[0], bNr, ext, dataE)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(macResp, cmac2) {
		return nil, fmt.Errorf("mac fail in response, response: [% X]; cmac: [% X]", response, cmac2)
	}

	rCountB1 := byte(((mplus.readCounter + 1) >> 8) & 0xFF)
	rCountB2 := byte((mplus.readCounter + 1) & 0xFF)
	wCountB1 := byte((mplus.writeCounter >> 8) & 0xFF)
	wCountB2 := byte(mplus.writeCounter & 0xFF)
	ivDec := make([]byte, 0)
	for i := 0; i < 3; i++ {
		ivDec = append(ivDec, rCountB2)
		ivDec = append(ivDec, rCountB1)
		ivDec = append(ivDec, wCountB2)
		ivDec = append(ivDec, wCountB1)
	}
	ivDec = append(ivDec, mplus.ti...)

	block, err := aes.NewCipher(mplus.keyEnc)
	if err != nil {
		return nil, err
	}
	modeD := cipher.NewCBCDecrypter(block, ivDec)

	data := make([]byte, len(dataE))
	modeD.CryptBlocks(data, dataE)

	mplus.readCounter++

	return data, nil
}

//Write encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) WriteEncMacMac(bNr int, data []byte) error {

	cmd := byte(0xA1)
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	rCountB1 := byte((mplus.readCounter >> 8) & 0xFF)
	rCountB2 := byte(mplus.readCounter & 0xFF)
	wCountB1 := byte((mplus.writeCounter >> 8) & 0xFF)
	wCountB2 := byte(mplus.writeCounter & 0xFF)

	ivEnc := make([]byte, 0)
	ivEnc = append(ivEnc, mplus.ti...)
	for i := 0; i < 3; i++ {
		ivEnc = append(ivEnc, rCountB2)
		ivEnc = append(ivEnc, rCountB1)
		ivEnc = append(ivEnc, wCountB2)
		ivEnc = append(ivEnc, wCountB1)
	}

	/**/
	block, err := aes.NewCipher(mplus.keyEnc)
	if err != nil {
		return err
	}
	modeE := cipher.NewCBCEncrypter(block, ivEnc)
	/**/
	dataE := make([]byte, len(data))
	modeE.CryptBlocks(dataE, data)

	cmac1, err := mplus.macWriteCommand(cmd, bNr, -1, dataE)
	if err != nil {
		return err
	}
	aid := []byte{cmd, bNB2, bNB1}
	aid = append(aid, dataE...)
	aid = append(aid, cmac1...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
	}

	macResp := response[len(response)-8:]

	cmac2, err := mplus.macWriteResponse(response[0])
	if err != nil {
		return err
	}

	if !bytes.Equal(macResp, cmac2) {
		return fmt.Errorf("mac fail in response, response: [% X]; macCalc: [% X]", response, cmac2)
	}

	mplus.writeCounter++

	return nil
}

//Decrement encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) DecTransfEncMacMac(bNr int, data []byte) error {

	cmd := byte(0xB7)
	if len(data) > 4 {
		return fmt.Errorf("length Data Value is incorrect (must 4)")
	}

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	rCountB1 := byte((mplus.readCounter >> 8) & 0xFF)
	rCountB2 := byte(mplus.readCounter & 0xFF)
	wCountB1 := byte((mplus.writeCounter >> 8) & 0xFF)
	wCountB2 := byte(mplus.writeCounter & 0xFF)

	ivEnc := make([]byte, 0)
	ivEnc = append(ivEnc, mplus.ti...)
	for i := 0; i < 3; i++ {
		ivEnc = append(ivEnc, rCountB2)
		ivEnc = append(ivEnc, rCountB1)
		ivEnc = append(ivEnc, wCountB2)
		ivEnc = append(ivEnc, wCountB1)
	}

	/**/
	block, err := aes.NewCipher(mplus.keyEnc)
	if err != nil {
		return err
	}
	modeE := cipher.NewCBCEncrypter(block, ivEnc)
	/**/
	if len(data)%16 != 0 {
		data = append(data, byte(0x80))
	}
	for len(data)%16 != 0 {
		data = append(data, byte(0x00))
	}
	dataE := make([]byte, len(data))
	modeE.CryptBlocks(dataE, data)

	cmac1, err := mplus.macWriteCommand(cmd, bNr, bNr, dataE)
	if err != nil {
		return err
	}

	aid := []byte{cmd, bNB2, bNB1, bNB2, bNB1}
	aid = append(aid, dataE...)
	aid = append(aid, cmac1...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
	}

	macResp := response[len(response)-8:]

	cmac2, err := mplus.macWriteResponse(response[0])
	if err != nil {
		return err
	}

	if !bytes.Equal(macResp, cmac2) {
		return fmt.Errorf("mac fail in response, response: [% X]; macCalc: [% X]", response, cmac2)
	}

	mplus.writeCounter++

	return nil
}

//Increment encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) IncTransfEncMacMac(bNr int, data []byte) error {

	cmd := byte(0xB7)
	if len(data) > 4 {
		return fmt.Errorf("length Data Value is incorrect (must 4)")
	}

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	rCountB1 := byte((mplus.readCounter >> 8) & 0xFF)
	rCountB2 := byte(mplus.readCounter & 0xFF)
	wCountB1 := byte((mplus.writeCounter >> 8) & 0xFF)
	wCountB2 := byte(mplus.writeCounter & 0xFF)

	ivEnc := make([]byte, 0)
	ivEnc = append(ivEnc, mplus.ti...)
	for i := 0; i < 3; i++ {
		ivEnc = append(ivEnc, rCountB2)
		ivEnc = append(ivEnc, rCountB1)
		ivEnc = append(ivEnc, wCountB2)
		ivEnc = append(ivEnc, wCountB1)
	}

	/**/
	block, err := aes.NewCipher(mplus.keyEnc)
	if err != nil {
		return err
	}
	modeE := cipher.NewCBCEncrypter(block, ivEnc)
	/**/
	if len(data)%16 != 0 {
		data = append(data, byte(0x80))
	}
	for len(data)%16 != 0 {
		data = append(data, byte(0x00))
	}
	dataE := make([]byte, len(data))
	modeE.CryptBlocks(dataE, data)

	cmac1, err := mplus.macWriteCommand(cmd, bNr, bNr, dataE)
	if err != nil {
		return err
	}

	aid := []byte{cmd, bNB2, bNB1, bNB2, bNB1}
	aid = append(aid, dataE...)
	aid = append(aid, cmac1...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
	}

	macResp := response[len(response)-8:]

	cmac2, err := mplus.macWriteResponse(response[0])
	if err != nil {
		return err
	}

	if !bytes.Equal(macResp, cmac2) {
		return fmt.Errorf("mac fail in response, response: [% X]; macCalc: [% X]", response, cmac2)
	}

	mplus.writeCounter++

	return nil
}

//Transfer encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) TransfMacMac(bNr int) error {

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	cmac1, err := mplus.macWriteCommand(byte(0xB5), bNr, -1, nil)
	if err != nil {
		return err
	}

	aid := []byte{0xB5, bNB2, bNB1}
	aid = append(aid, cmac1...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
	}

	macResp := response[len(response)-8:]

	cmac2, err := mplus.macWriteResponse(response[0])
	if err != nil {
		return err
	}

	if !bytes.Equal(macResp, cmac2) {
		return fmt.Errorf("mac fail in response, response: [% X]; macCalc: [% X]", response, cmac2)
	}
	mplus.writeCounter++

	return nil
}

func (mplus *mifarePlus) macWriteCommand(cmd byte, bNrDest, bNrSource int, data []byte) ([]byte, error) {
	bNB1 := byte((bNrDest >> 8) & 0xFF)
	bNB2 := byte(bNrDest & 0xFF)

	wCountB1 := byte((mplus.writeCounter >> 8) & 0xFF)
	wCountB2 := byte(mplus.writeCounter & 0xFF)

	blockMac, err := aes.NewCipher(mplus.keyMac)
	if err != nil {
		return nil, err
	}

	var1 := []byte{cmd}
	var1 = append(var1, wCountB2)
	var1 = append(var1, wCountB1)
	var1 = append(var1, mplus.ti...)
	var1 = append(var1, bNB2)
	var1 = append(var1, bNB1)
	if bNrSource > 0 {
		bNBs1 := byte((bNrSource >> 8) & 0xFF)
		bNBs2 := byte(bNrSource & 0xFF)
		var1 = append(var1, bNBs2)
		var1 = append(var1, bNBs1)
	}
	if data != nil {
		var1 = append(var1, data...)
	}

	cmacS, err := cmac.Sum(var1, blockMac, 16)
	if err != nil {
		return nil, err
	}
	cmac1 := make([]byte, 0)
	for i, v := range cmacS {
		if i%2 != 0 {
			cmac1 = append(cmac1, v)
		}
	}

	return cmac1, nil
}

func (mplus *mifarePlus) macWriteResponse(sc byte) ([]byte, error) {
	wCountB1 := byte(((mplus.writeCounter + 1) >> 8) & 0xFF)
	wCountB2 := byte((mplus.writeCounter + 1) & 0xFF)
	var2 := make([]byte, 0)
	var2 = append(var2, sc)
	var2 = append(var2, wCountB2)
	var2 = append(var2, wCountB1)
	var2 = append(var2, mplus.ti...)

	blockMac, err := aes.NewCipher(mplus.keyMac)
	if err != nil {
		return nil, err
	}

	cmacS2, err := cmac.Sum(var2, blockMac, 16)
	if err != nil {
		return nil, err
	}

	cmac2 := make([]byte, 0)
	for i, v := range cmacS2 {
		if i%2 != 0 {
			cmac2 = append(cmac2, v)
		}
	}
	return cmac2, err
}

func (mplus *mifarePlus) macReadCommand(cmd byte, bNr, ext int) ([]byte, error) {
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	rCountB1 := byte((mplus.readCounter >> 8) & 0xFF)
	rCountB2 := byte(mplus.readCounter & 0xFF)

	blockMac, err := aes.NewCipher(mplus.keyMac)
	if err != nil {
		return nil, err
	}

	var1 := []byte{cmd}
	var1 = append(var1, rCountB2)
	var1 = append(var1, rCountB1)
	var1 = append(var1, mplus.ti...)
	var1 = append(var1, bNB2)
	var1 = append(var1, bNB1)
	var1 = append(var1, byte(ext))

	/**
	if len(var1)%8 != 0 {
		i := 0
		for i = 0; i < 8; i++ {
			if ((var1[len(var1)-1] >> i) & 0x01) == 0x01 {
				break
			}
		}
		if i == 0 {
			var1 = append(var1, 0x80)
		} else {
			mask := byte(0x00)
			for j := 0; j < i; j++ {
				mask = mask << 1
			}
			var1[len(var1)-1] |= mask
		}
	}

	for len(var1)%8 != 0 {
		var1 = append(var1, byte(0x00))
	}
	/**/
	if len(var1)%16 != 0 {
		var1 = append(var1, byte(0x80))
		var1 = append(var1, make([]byte, 16-len(var1)%16)...)
	}
	fmt.Printf("var1 cmac: [% X]\n", var1)
	cmacS, err := cmac.Sum(var1, blockMac, 16)
	if err != nil {
		return nil, err
	}
	fmt.Printf("cmac: [% X]\n", cmacS)
	cmac1 := make([]byte, 0)
	for i, v := range cmacS {
		if i%2 == 0 {
			cmac1 = append(cmac1, v)
		}
	}

	return cmac1, nil
}

func (mplus *mifarePlus) macReadResponse(sc byte, bNr, ext int, data []byte) ([]byte, error) {
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)
	rCountB1 := byte(((mplus.readCounter + 1) >> 8) & 0xFF)
	rCountB2 := byte((mplus.readCounter + 1) & 0xFF)
	var2 := make([]byte, 0)
	var2 = append(var2, sc)
	var2 = append(var2, rCountB2)
	var2 = append(var2, rCountB1)
	var2 = append(var2, mplus.ti...)
	var2 = append(var2, bNB2)
	var2 = append(var2, bNB1)
	var2 = append(var2, byte(ext))
	var2 = append(var2, data...)
	/**/
	if len(var2)%16 != 0 {
		var2 = append(var2, byte(0x80))
	}
	for len(var2)%16 != 0 {
		var2 = append(var2, byte(0x00))
	}
	/**/

	fmt.Printf("payload cmac: [% X]\n", var2)

	blockMac, err := aes.NewCipher(mplus.keyMac)
	if err != nil {
		return nil, err
	}
	cmacS2, err := cmac.Sum(var2, blockMac, 16)
	if err != nil {
		return nil, err
	}

	fmt.Printf("cmac: [% X]\n", cmacS2)

	cmac2 := make([]byte, 0)
	for i, v := range cmacS2 {
		if i%2 != 0 {
			cmac2 = append(cmac2, v)
		}
	}

	return cmac2, err
}

func funcExtract(data []byte, i, j int) []byte {
	return data[i : j+1]
	// return data[16-i : 16-j]
}

func calcSessionKeyEV1(rndA, rndB, key []byte) ([]byte, []byte, error) {
	keySessionBaseENC := make([]byte, 0)

	A := funcExtract(rndA, 14, 15)
	B := funcExtract(rndA, 8, 13)
	F := funcExtract(rndA, 0, 7)

	C := funcExtract(rndB, 10, 15)
	E := funcExtract(rndB, 0, 9)

	D := make([]byte, len(B))
	for i := range D {
		D[i] = B[i] ^ C[i]
	}

	keySessionBaseENC = append(keySessionBaseENC, F...)
	keySessionBaseENC = append(keySessionBaseENC, E...)
	keySessionBaseENC = append(keySessionBaseENC, D...)
	keySessionBaseENC = append(keySessionBaseENC, A...)
	keySessionBaseENC = append(keySessionBaseENC, []byte{0x80, 0x00, 0x01, 0x00, 0x5A, 0xA5}...)

	blockEnc, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	keyEnc, err := cmac.Sum(keySessionBaseENC, blockEnc, 16)
	if err != nil {
		return nil, nil, err
	}

	keySessionBaseMAC := make([]byte, 0)

	keySessionBaseMAC = append(keySessionBaseMAC, F...)
	keySessionBaseMAC = append(keySessionBaseMAC, E...)
	keySessionBaseMAC = append(keySessionBaseMAC, D...)
	keySessionBaseMAC = append(keySessionBaseMAC, A...)
	keySessionBaseMAC = append(keySessionBaseMAC, []byte{0x80, 0x00, 0x01, 0x00, 0xA5, 0x5A}...)
	fmt.Printf("keySessionBaseMAC: [% X], [0]: %X\n", keySessionBaseMAC, keySessionBaseMAC[0])

	blockMac, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	keyMac, err := cmac.Sum(keySessionBaseMAC, blockMac, 16)
	if err != nil {
		return nil, nil, err
	}

	return keyEnc, keyMac, nil
}

func calcSessionKeyEV0(rndA, rndB, key []byte) ([]byte, []byte, error) {
	keySessionBaseENC := make([]byte, 0)

	// tempA := make([]byte, len(rndA))
	// tempB := make([]byte, len(rndB))
	// copy(tempA, rndA)
	// copy(tempB, rndB)

	// for i := range rndA {
	// 	rndA[i] = tempA[len(tempA)-1-i]
	// }
	// for i := range rndB {
	// 	rndB[i] = tempB[len(tempB)-1-i]
	// }
	fmt.Printf("rndA: [% X\n", rndA)
	fmt.Printf("rndB: [% X\n", rndB)

	A := funcExtract(rndA, 0, 4)
	B := funcExtract(rndB, 0, 4)

	C := funcExtract(rndA, 7, 11)
	D := funcExtract(rndB, 7, 11)

	E := make([]byte, len(D))
	for i := range D {
		E[i] = D[i] ^ C[i]
	}

	keySessionBaseENC = append(keySessionBaseENC, 0x11)
	keySessionBaseENC = append(keySessionBaseENC, E...)
	keySessionBaseENC = append(keySessionBaseENC, B...)
	keySessionBaseENC = append(keySessionBaseENC, A...)

	keyEnc := make([]byte, 16)

	iv := make([]byte, 16)
	blockENC, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	modeE := cipher.NewCBCEncrypter(blockENC, iv)
	modeE.CryptBlocks(keyEnc, keySessionBaseENC)

	keySessionBaseMAC := make([]byte, 0)

	H := funcExtract(rndA, 0, 4)
	F := funcExtract(rndA, 7, 11)

	I := funcExtract(rndB, 0, 4)
	G := funcExtract(rndB, 7, 11)

	J := make([]byte, len(I))
	for i := range D {
		J[i] = H[i] ^ I[i]
	}

	keySessionBaseMAC = append(keySessionBaseMAC, F...)
	keySessionBaseMAC = append(keySessionBaseMAC, G...)
	keySessionBaseMAC = append(keySessionBaseMAC, J...)
	keySessionBaseMAC = append(keySessionBaseMAC, 0x22)
	// keySessionBaseMAC = append(keySessionBaseMAC, J...)
	// keySessionBaseMAC = append(keySessionBaseMAC, G...)
	// keySessionBaseMAC = append(keySessionBaseMAC, F...)

	fmt.Printf("keySessionBaseMAC: [% X], [0]: %X\n", keySessionBaseMAC, keySessionBaseMAC[0])

	keyMac := make([]byte, 16)

	iv = make([]byte, 16)
	blockMAC, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	modeE = cipher.NewCBCEncrypter(blockMAC, iv)
	modeE.CryptBlocks(keyMac, keySessionBaseMAC)

	// reverse := make([]byte, len(keySessionBaseMAC))
	// for i := range reverse {
	// 	reverse[i] = keySessionBaseMAC[len(keySessionBaseMAC)-1-i]
	// }
	// fmt.Printf("reverse: [% X], [0]: %X\n", reverse, reverse[0])
	// modeE.CryptBlocks(keyMac, reverse)

	return keyEnc, keyMac, nil
}
