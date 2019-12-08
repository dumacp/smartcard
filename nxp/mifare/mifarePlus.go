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

//Mifare Plus Interface
type MifarePlus interface {
	WritePerso(int, []byte) ([]byte, error)
	CommitPerso() ([]byte, error)
	FirstAuthf1(keyBNr int) ([]byte, error)
	FirstAuthf2([]byte) ([]byte, error)
	FirstAuth(keyBNr int, key []byte) ([]byte, error)
	ReadPlainMacMac(bNr, ext int) ([]byte, error)
	ReadEncMacMac(bNr, ext int) ([]byte, error)
	WriteEncMacMac(bNr int, data []byte) error
	IncTransfEncMacMac(bNr int, data []byte) error
	TransfMacMac(bNr int) error
	KeyEnc(key []byte)
	KeyMac(key []byte)
	Ti(ti []byte)
	ReadCounter(counter int)
	WriteCounter(counter int)
}

type mifarePlus struct {
	card         smartcard.ICard
	keyMac       []byte
	keyEnc       []byte
	readCounter  int
	writeCounter int
	ti           []byte
}

//Create Mifare Plus Interface
func ConnectMplus(r smartcard.IReader) (MifarePlus, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	mplus := &mifarePlus{
		card: c,
	}
	return mplus, nil
}

/**/
//Valid response: response[0] == 0x90
func verifyResponse(data []byte) error {
	if data == nil {
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
	response, err := mplus.card.Apdu(aid)
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
	response, err := mplus.card.Apdu(aid)
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
	//fmt.Printf("aid: [% X]", aid)
	response, err := mplus.card.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	//fmt.Printf("response: [% X]", response)
	return response[1:], nil
}

//First Authentication second step
func (mplus *mifarePlus) FirstAuthf2(data []byte) ([]byte, error) {
	aid := make([]byte, 0)
	aid = append(aid, byte(0x72))
	aid = append(aid, data...)
	response, err := mplus.card.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	/**/
	/**/
	return response[1:], nil
}

//Following Authentication first Step
func (mplus *mifarePlus) FallowAuthf1(keyBNr int) ([]byte, error) {
	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)
	aid := []byte{0x76, keyB2, keyB1, 0x00}
	response, err := mplus.card.Apdu(aid)
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
	response, err := mplus.card.Apdu(aid)
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
	//fmt.Printf("resp: [% X]\n", response)
	rndBc := response
	//fmt.Printf("rndBc: [% X]\n", rndBc)

	iv := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	rndB := make([]byte, 16)
	modeD.CryptBlocks(rndB, rndBc)
	//fmt.Printf("rndB: [% X]\n", rndB)

	//rotate rndB
	rndB = append(rndB, rndB[0])
	rndB = rndB[1:]
	//fmt.Printf("rndBrot: [% X]\n", rndB)

	rndA := make([]byte, 16)
	rand.Read(rndA)
	//fmt.Printf("rndA: [% X]\n", rndA)

	rndD := make([]byte, 0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndB...)
	//fmt.Printf("rndD: [% X]\n", rndD)

	rndDc := make([]byte, len(rndD))
	modeE.CryptBlocks(rndDc, rndD)
	//fmt.Printf("rndDc: [% X]\n", rndDc)

	response, err = mplus.FirstAuthf2(rndDc)
	if err != nil {
		return nil, err
	}
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

	aid := []byte{cmd, bNB2, bNB1, byte(ext)}
	aid = append(aid, cmac1...)
	response, err := mplus.card.Apdu(aid)
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
		return nil, fmt.Errorf("Mac Fail in response, response: [% X]\n", response)
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
	response, err := mplus.card.Apdu(aid)
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
		return nil, fmt.Errorf("Mac Fail in response, response: [% X]; cmac: [% X]\n", response, cmac2)
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
	aid := []byte{cmd, bNB2, bNB1}
	aid = append(aid, dataE...)
	aid = append(aid, cmac1...)
	response, err := mplus.card.Apdu(aid)
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
		return fmt.Errorf("Mac Fail in response, response: [% X]; macCalc: [% X]\n", response, cmac2)
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
	response, err := mplus.card.Apdu(aid)
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
		return fmt.Errorf("Mac Fail in response, response: [% X]; macCalc: [% X]\n", response, cmac2)
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
	response, err := mplus.card.Apdu(aid)
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
		return fmt.Errorf("Mac Fail in response, response: [% X]; macCalc: [% X]\n", response, cmac2)
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
		var1 = append(var1, byte(0x80))
	}
	for len(var1)%8 != 0 {
		var1 = append(var1, byte(0x00))
	}
	/**/
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
	/**
	if len(var2)%16 != 0 {
		var2 = append(var2, byte(0x80))
	}
	for len(data)%16 != 0 {
		var2 = append(var2, byte(0x00))
	}
	/**/

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
