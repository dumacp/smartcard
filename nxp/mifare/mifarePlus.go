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
	WritePerso(int, []byte) ([]byte, error) //SL0
	CommitPerso() ([]byte, error)           //SL0
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
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}
	return response[1:], nil
}

//First Authentication second step
func (mplus *mifarePlus) FirstAuthf2(data []byte) ([]byte, error) {
	aid := make([]byte, 0)
	aid = append(aid, byte(0x72))
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
	rndBc := response

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

	rndA := make([]byte, 16)
	rand.Read(rndA)
	fmt.Printf("rndA: [% X]\n", rndA)

	rndD := make([]byte, 0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	rndDc := make([]byte, len(rndD))
	modeE.CryptBlocks(rndDc, rndD)

	response, err = mplus.FirstAuthf2(rndDc)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(response))
	modeD = cipher.NewCBCDecrypter(block, iv)
	modeD.CryptBlocks(result, response[:])

	var keyEnc, keyMac []byte
	if result[len(result)-1]&0x01 == 0x00 {
		keyEnc, keyMac, err = calcSessionKeyEV0(rndA, rndB, key)
	} else {
		keyEnc, keyMac, err = calcSessionKeyEV1(rndA, rndB, key)
	}
	if err != nil {
		return nil, err
	}

	mplus.KeyEnc(keyEnc)
	mplus.KeyMac(keyMac)

	// fmt.Printf("result: [% X]\n", result)

	ti := make([]byte, 4)

	copy(ti, result[0:4])

	mplus.Ti(ti)
	mplus.WriteCounter(0)
	mplus.ReadCounter(0)

	return response, nil
}

//Read in plain, MAC on response, MAC on command
func (mplus *mifarePlus) ReadPlainMacMac(bNr, ext int) ([]byte, error) {

	cmd := byte(0x33)
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	cmacReq, err := mplus.macReadCommand(byte(cmd), bNr, ext)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("cmac: [% X]\n", cmac1)

	aid := []byte{cmd, bNB2, bNB1, byte(ext)}
	aid = append(aid, cmacReq...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}

	data := response[1 : len(response)-8]
	macResp := response[len(response)-8:]

	cmacResp, err := mplus.macReadResponse(response[0], bNr, ext, data)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(macResp, cmacResp) {
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
	aid := []byte{cmd, bNB2, bNB1, byte(ext)}

	response, err := mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
	}

	data := response[1 : len(response)-8]
	macResp := response[len(response)-8:]

	cmacResp, err := mplus.macReadResponse(cmd, bNr, ext, data)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(macResp, cmacResp) {
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

	cmacResp, err := mplus.macReadResponse(response[0], bNr, ext, dataE)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(macResp, cmacResp) {
		return nil, fmt.Errorf("mac fail in response, response: [% X]; cmac: [% X]", response, cmacResp)
	}

	data, err := decCalc(mplus.readCounter, mplus.writeCounter, mplus.keyEnc, mplus.ti, dataE)
	if err != nil {
		return nil, err
	}

	mplus.readCounter++

	return data, nil
}

//Write encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) WriteEncMacMac(bNr int, data []byte) error {

	cmd := byte(0xA1)
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	dataE, err := encCalc(mplus.readCounter, mplus.writeCounter, mplus.keyEnc, mplus.ti, data)
	if err != nil {
		return err
	}

	cmacReq, err := mplus.macWriteCommand(cmd, bNr, dataE)
	if err != nil {
		return err
	}
	aid := []byte{cmd, bNB2, bNB1}
	aid = append(aid, dataE...)
	aid = append(aid, cmacReq...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
	}

	macResp := response[len(response)-8:]

	cmacResp, err := mplus.macWriteResponse(response[0])
	if err != nil {
		return err
	}

	if !bytes.Equal(macResp, cmacResp) {
		return fmt.Errorf("mac fail in response, response: [% X]; macCalc: [% X]", response, cmacResp)
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

	dataE, err := encCalc(mplus.readCounter, mplus.writeCounter, mplus.keyEnc, mplus.ti, data)
	if err != nil {
		return err
	}

	payload := make([]byte, 0)

	payload = append(payload, bNB2)
	payload = append(payload, bNB1)
	payload = append(payload, dataE...)

	cmacReq, err := mplus.macWriteCommand(cmd, bNr, payload)
	if err != nil {
		return err
	}

	aid := []byte{cmd, bNB2, bNB1, bNB2, bNB1}
	aid = append(aid, dataE...)
	aid = append(aid, cmacReq...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
	}

	macResp := response[len(response)-8:]

	cmacResp, err := mplus.macWriteResponse(response[0])
	if err != nil {
		return err
	}

	if !bytes.Equal(macResp, cmacResp) {
		return fmt.Errorf("mac fail in response, response: [% X]; macCalc: [% X]", response, cmacResp)
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

	dataE, err := encCalc(mplus.readCounter, mplus.writeCounter, mplus.keyEnc, mplus.ti, data)
	if err != nil {
		return err
	}

	payload := make([]byte, 0)

	payload = append(payload, bNB2)
	payload = append(payload, bNB1)
	payload = append(payload, dataE...)

	cmacReq, err := mplus.macWriteCommand(cmd, bNr, payload)
	if err != nil {
		return err
	}

	aid := []byte{cmd, bNB2, bNB1, bNB2, bNB1}
	aid = append(aid, dataE...)
	aid = append(aid, cmacReq...)
	response, err := mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
	}

	macResp := response[len(response)-8:]

	cmacResp, err := mplus.macWriteResponse(response[0])
	if err != nil {
		return err
	}

	if !bytes.Equal(macResp, cmacResp) {
		return fmt.Errorf("mac fail in response, response: [% X]; macCalc: [% X]", response, cmacResp)
	}

	mplus.writeCounter++

	return nil
}

//Transfer encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) TransfMacMac(bNr int) error {

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	cmac1, err := mplus.macWriteCommand(byte(0xB5), bNr, nil)
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

//encCalc calcule encrypted data to request
func encCalc(readCounter, writeCounter int, key, ti, data []byte) ([]byte, error) {

	rCountB1 := byte((readCounter >> 8) & 0xFF)
	rCountB2 := byte(readCounter & 0xFF)
	wCountB1 := byte((writeCounter >> 8) & 0xFF)
	wCountB2 := byte(writeCounter & 0xFF)

	ivEnc := make([]byte, 0)
	ivEnc = append(ivEnc, ti...)
	for i := 0; i < 3; i++ {
		ivEnc = append(ivEnc, rCountB2)
		ivEnc = append(ivEnc, rCountB1)
		ivEnc = append(ivEnc, wCountB2)
		ivEnc = append(ivEnc, wCountB1)
	}

	fmt.Printf("iv enc: [% X]\n", ivEnc)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	modeE := cipher.NewCBCEncrypter(block, ivEnc)

	if len(data)%16 != 0 {
		data = append(data, byte(0x80))
	}
	for len(data)%16 != 0 {
		data = append(data, byte(0x00))
	}
	dataE := make([]byte, len(data))
	modeE.CryptBlocks(dataE, data)
	return dataE, nil
}

//encCalc calcule decrypted data to response
func decCalc(readCounter, writeCounter int, key, ti, data []byte) ([]byte, error) {

	rCountB1 := byte(((readCounter + 1) >> 8) & 0xFF)
	rCountB2 := byte((readCounter + 1) & 0xFF)
	wCountB1 := byte((writeCounter >> 8) & 0xFF)
	wCountB2 := byte(writeCounter & 0xFF)
	ivDec := make([]byte, 0)
	for i := 0; i < 3; i++ {
		ivDec = append(ivDec, rCountB2)
		ivDec = append(ivDec, rCountB1)
		ivDec = append(ivDec, wCountB2)
		ivDec = append(ivDec, wCountB1)
	}
	ivDec = append(ivDec, ti...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	modeD := cipher.NewCBCDecrypter(block, ivDec)
	if len(data)%16 != 0 {
		data = append(data, byte(0x80))
	}
	for len(data)%16 != 0 {
		data = append(data, byte(0x00))
	}
	dataE := make([]byte, len(data))
	modeD.CryptBlocks(dataE, data)
	return dataE, nil
}

//macCacl calcule mac to message
func macCalc(key, data []byte) ([]byte, error) {

	blockMac, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cmacS, err := cmac.Sum(data, blockMac, 16)
	if err != nil {
		return nil, err
	}
	cmacR := make([]byte, 0)
	for i, v := range cmacS {
		if i%2 != 0 {
			cmacR = append(cmacR, v)
		}
	}

	return cmacR, nil
}

func (mplus *mifarePlus) macWriteCommand(cmd byte, bNr int, data interface{}) ([]byte, error) {

	countB1 := byte((mplus.writeCounter >> 8) & 0xFF)
	countB2 := byte(mplus.writeCounter & 0xFF)

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	payload := make([]byte, 0)
	payload = append(payload, cmd)
	payload = append(payload, countB2)
	payload = append(payload, countB1)
	payload = append(payload, mplus.ti...)
	payload = append(payload, bNB2)
	payload = append(payload, bNB1)

	if data != nil {
		switch v := data.(type) {
		case int:
			bNBs1 := byte((v >> 8) & 0xFF)
			bNBs2 := byte(v & 0xFF)
			payload = append(payload, bNBs2)
			payload = append(payload, bNBs1)
		case []byte:
			payload = append(payload, v...)
		}
	}
	return macCalc(mplus.keyMac, payload)
}

func (mplus *mifarePlus) macWriteResponse(sc byte) ([]byte, error) {
	wCountB1 := byte(((mplus.writeCounter + 1) >> 8) & 0xFF)
	wCountB2 := byte((mplus.writeCounter + 1) & 0xFF)
	payload := make([]byte, 0)
	payload = append(payload, sc)
	payload = append(payload, wCountB2)
	payload = append(payload, wCountB1)
	payload = append(payload, mplus.ti...)

	return macCalc(mplus.keyMac, payload)
}

func (mplus *mifarePlus) macReadCommand(cmd byte, bNr, ext int) ([]byte, error) {
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	rCountB1 := byte((mplus.readCounter >> 8) & 0xFF)
	rCountB2 := byte(mplus.readCounter & 0xFF)

	payload := []byte{cmd}
	payload = append(payload, rCountB2)
	payload = append(payload, rCountB1)
	payload = append(payload, mplus.ti...)
	payload = append(payload, bNB2)
	payload = append(payload, bNB1)
	payload = append(payload, byte(ext))

	return macCalc(mplus.keyMac, payload)
}

func (mplus *mifarePlus) macReadResponse(sc byte, bNr, ext int, data []byte) ([]byte, error) {
	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)
	rCountB1 := byte(((mplus.readCounter + 1) >> 8) & 0xFF)
	rCountB2 := byte((mplus.readCounter + 1) & 0xFF)
	payload := make([]byte, 0)
	payload = append(payload, sc)
	payload = append(payload, rCountB2)
	payload = append(payload, rCountB1)
	payload = append(payload, mplus.ti...)
	payload = append(payload, bNB2)
	payload = append(payload, bNB1)
	payload = append(payload, byte(ext))
	payload = append(payload, data...)

	return macCalc(mplus.keyMac, payload)
}

func funcExtract(data []byte, i, j int) []byte {
	return data[15-i : (15+1)-j]
}

func calcSessionKeyEV1(rndA, rndB, key []byte) ([]byte, []byte, error) {
	keySessionBaseENC := make([]byte, 0)

	A := funcExtract(rndA, 15, 14)
	B := funcExtract(rndA, 13, 8)
	F := funcExtract(rndA, 7, 0)

	C := funcExtract(rndB, 15, 10)
	E := funcExtract(rndB, 9, 0)

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

	A := funcExtract(rndA, 4, 0)
	B := funcExtract(rndB, 4, 0)

	C := funcExtract(rndA, 11, 7)
	D := funcExtract(rndB, 11, 7)

	E := make([]byte, len(D))
	for i := range D {
		E[i] = D[i] ^ C[i]
	}

	keySessionBaseENC = append(keySessionBaseENC, A...)
	keySessionBaseENC = append(keySessionBaseENC, B...)
	keySessionBaseENC = append(keySessionBaseENC, E...)
	keySessionBaseENC = append(keySessionBaseENC, 0x11)

	keyEnc := make([]byte, 16)

	iv := make([]byte, 16)
	blockENC, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	modeE := cipher.NewCBCEncrypter(blockENC, iv)
	modeE.CryptBlocks(keyEnc, keySessionBaseENC)

	keySessionBaseMAC := make([]byte, 0)
	H := funcExtract(rndA, 15, 11)
	F := funcExtract(rndA, 8, 4)

	I := funcExtract(rndB, 15, 11)
	G := funcExtract(rndB, 8, 4)

	J := make([]byte, len(I))
	for i := range D {
		J[i] = H[i] ^ I[i]
	}

	keySessionBaseMAC = append(keySessionBaseMAC, F...)
	keySessionBaseMAC = append(keySessionBaseMAC, G...)
	keySessionBaseMAC = append(keySessionBaseMAC, J...)
	keySessionBaseMAC = append(keySessionBaseMAC, 0x22)

	keyMac := make([]byte, 16)

	iv = make([]byte, 16)
	blockMAC, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	modeE = cipher.NewCBCEncrypter(blockMAC, iv)

	modeE.CryptBlocks(keyMac, keySessionBaseMAC)

	return keyEnc, keyMac, nil
}

func reverse(data []byte) []byte {
	reverse := make([]byte, len(data))
	for i := range reverse {
		reverse[i] = data[len(data)-1-i]
	}
	return reverse
}
