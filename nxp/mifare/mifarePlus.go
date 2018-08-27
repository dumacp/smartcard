/**
Implementation to mifare smartcard family (Mifare Plus, Desfire, SamAV2, ...)
/**/
package mifare


import (
	"fmt"
	"math/rand"
	"time"
	"bytes"
	"crypto/cipher"
	"crypto/aes"
	"github.com/aead/cmac"
	"github.com/dumacp/smartcard"
)


//Mifare Plus Interface
type MifarePlus interface{
	smartcard.Card
	UID()	([]byte, error)
	ATS()	([]byte, error)
	FirstAuthf1(keyBNr int) ([]byte, error)
	FirstAuthf2([]byte) ([]byte, error)
	FirstAuth(keyBNr int, key []byte) ([]byte, error)
	ReadPlainMacMac(keyBNr, ext, readCounter int, ti, keyMac []byte) ([]byte, error)
	ReadEncMacMac(keyBNr, ext, readCounter, writeCounter int, ti, keyMac, keyEnc []byte) ([]byte, error)
	WriteEncMacMac(keyBNr int, data []byte, readCounter, writeCounter int, ti, keyMac, keyEnc []byte) (error)
}

type mifarePlus struct {
	smartcard.Card
}

//Create Mifare Plus Interface
func ConnectMplus(r smartcard.Reader) (MifarePlus, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	mplus := &mifarePlus{
		c,
	}
	return mplus, nil
}

/**/
//Valid response: response[0] == 0x90
func isValidResponse(data []byte) bool {
	if data == nil {
		return false
	}
	if len(data) < 2 {
		return false
	}
	if data[len(data)-2] == 0x90 && data[len(data)-1] == 0x00 {
		return true
	}
	return false
}

//Get Data 0x00
func (mplus *mifarePlus) UID() ([]byte, error) {
	aid := []byte{0xFF,0xCA,0x00,0x00,0x00}
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if !isValidResponse(response) {
		return nil, fmt.Errorf("bad response: [% X]", response)
	}
	return response[0:len(response)-2], nil
}

//Get Data 0x01
func (mplus *mifarePlus) ATS() ([]byte, error) {
	aid := []byte{0xFF,0xCA,0x01,0x00,0x00}
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if !isValidResponse(response) {
		return nil, fmt.Errorf("bad response: [% X]", response)
	}
	return response[0:len(response)-2], nil
}

//First Authentication first step
func (mplus *mifarePlus) FirstAuthf1(keyBNr int) ([]byte, error) {
	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)
	aid := []byte{0x70,keyB2,keyB1,0x00}
	//fmt.Printf("aid: [% X]", aid)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if response[0] != byte(0x90) {
		return nil, fmt.Errorf("bad response: [% X]", response)
	}
	//fmt.Printf("response: [% X]", response)
	return response[1:], nil
}

//First Authentication second step
func (mplus *mifarePlus) FirstAuthf2(data []byte) ([]byte, error) {
	aid := make([]byte,0)
	aid = append(aid, byte(0x72))
	aid = append(aid, data...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if response[0] != byte(0x90) {
		return nil, fmt.Errorf("bad response: [% X]", response)
	}
	return response[1:], nil
}

//Following Authentication first Step
func (mplus *mifarePlus) FallowAuthf1(keyBNr int) ([]byte, error) {
	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)
	aid := []byte{0x76,keyB2,keyB1,0x00}
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if response[0] != byte(0x90) {
		return nil, fmt.Errorf("bad response: [% X]", response)
	}
	return response[1:], nil
}

//Following Authentication second Step
func (mplus *mifarePlus) FallowtAuthf2(data []byte) ([]byte, error) {
	aid := []byte{0x72}
	aid = append(aid, data...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if response[0] != byte(0x90) {
		return nil, fmt.Errorf("bad response: [% X]", response)
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
	rndBc := response[1:17]
	//fmt.Printf("rndBc: [% X]", rndBc)

	iv := make([]byte,16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	rndB := make([]byte,16)
	modeD.CryptBlocks(rndB, rndBc)

	//rotate rndB
	rndB = append(rndB,rndB[1])
	rndB = rndB[1:]

	rndA := make([]byte,16)
	rand.Read(rndA)

	rndD := make([]byte,0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndB...)

	rndDc := make([]byte,len(rndD))
	modeE.CryptBlocks(rndDc, rndD)

	response, err = mplus.FirstAuthf2(rndDc)
	if err != nil {
		return nil, err
	}

	if response[len(response) -1] != byte(0x90) {
		return nil, fmt.Errorf("bad response: [% X]", response)
	}

	return response[1:], nil
}

//Read in plain, MAC on response, MAC on command
func (mplus *mifarePlus) ReadPlainMacMac(keyBNr, ext, readCounter int, Ti , keyMac []byte) ([]byte, error) {

	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)

	rCountB1 := byte((readCounter >> 8) & 0xFF)
	rCountB2 := byte(readCounter & 0xFF)

	//iv := make([]byte,16)
        block, err := aes.NewCipher(keyMac)
        if err != nil {
                return nil, err
        }

	var1 := []byte{0x33}
        var1 = append(var1, rCountB2)
        var1 = append(var1, rCountB1)
        var1 = append(var1, Ti...)
        var1 = append(var1, keyB2)
        var1 = append(var1, keyB1)
        var1 = append(var1, byte(ext))
        cmacS, err := cmac.Sum(var1, block, 16)
        if err != nil {
                return nil, err
        }
        cmac1 := make([]byte,0)
        for i, v := range cmacS {
                if i%2 != 0 {
                        cmac1 = append(cmac1, v)
                }
        }

	aid := []byte{0x33,keyB2,keyB1,byte(ext)}
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if response[0] != byte(0x90) {
		return nil, fmt.Errorf("bad response: [% X]\n", response)
	}

	data := response[1:len(response)-8]
	macResp := response[len(response)-8:]

	rCountB1 = byte((readCounter+1 >> 8) & 0xFF)
	rCountB2 = byte(readCounter+1 & 0xFF)
	var2 := make([]byte,0)
	var2 = append(var2, response[0])
        var2 = append(var2, rCountB2)
        var2 = append(var2, rCountB1)
        var2 = append(var2, Ti...)
        var2 = append(var2, keyB2)
        var2 = append(var2, keyB1)
        var2 = append(var2, byte(ext))
        var2 = append(var2, data...)

        cmacS2, err := cmac.Sum(var2, block, 16)
        if err != nil {
                return nil, err
        }

        cmac2 := make([]byte,0)
	for i, v := range cmacS2 {
                if i%2 != 0 {
                        cmac2 = append(cmac2, v)
                }
        }

	if !bytes.Equal(macResp, cmac2) {
		return nil, fmt.Errorf("Mac Fail in response, response: [% X]\n", response)
	}

	return data, nil
}

//Read encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) ReadEncMacMac(keyBNr, ext, readCounter, writeCounter int, ti , keyMac, keyEnc []byte) ([]byte, error) {

	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)

	rCountB1 := byte((readCounter >> 8) & 0xFF)
	rCountB2 := byte(readCounter & 0xFF)
	wCountB1 := byte((writeCounter >> 8) & 0xFF)
	wCountB2 := byte(writeCounter & 0xFF)


        blockMac, err := aes.NewCipher(keyMac)
        if err != nil {
                return nil, err
        }

	var1 := []byte{0x31}
        var1 = append(var1, rCountB2)
        var1 = append(var1, rCountB1)
        var1 = append(var1, ti...)
        var1 = append(var1, keyB2)
        var1 = append(var1, keyB1)
        var1 = append(var1, byte(ext))
        cmacS, err := cmac.Sum(var1, blockMac, 16)
        if err != nil {
                return nil, err
        }
        cmac1 := make([]byte,0)
        for i, v := range cmacS {
                if i%2 != 0 {
                        cmac1 = append(cmac1, v)
                }
        }

	aid := []byte{0x31,keyB2,keyB1,byte(ext)}
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if response[0] != byte(0x90) {
		return nil, fmt.Errorf("bad response: [% X]\n", response)
	}

	dataE := response[1:len(response)-8]
	macResp := response[len(response)-8:]

	rCountB1 = byte((readCounter+1 >> 8) & 0xFF)
	rCountB2 = byte(readCounter+1 & 0xFF)
	var2 := make([]byte,0)
	var2 = append(var2, response[0])
        var2 = append(var2, rCountB2)
        var2 = append(var2, rCountB1)
        var2 = append(var2, ti...)
        var2 = append(var2, keyB2)
        var2 = append(var2, keyB1)
        var2 = append(var2, byte(ext))
        var2 = append(var2, dataE...)

        cmacS2, err := cmac.Sum(var2, blockMac, 16)
        if err != nil {
                return nil, err
        }

        cmac2 := make([]byte,0)
	for i, v := range cmacS2 {
                if i%2 != 0 {
                        cmac2 = append(cmac2, v)
                }
        }

	if !bytes.Equal(macResp, cmac2) {
		return nil, fmt.Errorf("Mac Fail in response, response: [% X]\n", response)
	}

	ivDec := make([]byte,0)
	for i:=0; i<3; i++ {
		ivDec = append(ivDec, rCountB2)
		ivDec = append(ivDec, rCountB1)
		ivDec = append(ivDec, wCountB2)
		ivDec = append(ivDec, wCountB1)
	}
	ivDec = append(ivDec, ti...)

        block, err := aes.NewCipher(keyEnc)
        if err != nil {
                return nil, err
        }
	modeD := cipher.NewCBCDecrypter(block, ivDec)

	data := make([]byte,len(dataE))
	modeD.CryptBlocks(data, dataE)

	return data, nil
}

//Write encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) WriteEncMacMac(keyBNr int, data []byte, readCounter, writeCounter int, ti , keyMac, keyEnc []byte) (error) {

	keyB1 := byte((keyBNr >> 8) & 0xFF)
	keyB2 := byte(keyBNr & 0xFF)

	rCountB1 := byte((readCounter >> 8) & 0xFF)
	rCountB2 := byte(readCounter & 0xFF)
	wCountB1 := byte((writeCounter >> 8) & 0xFF)
	wCountB2 := byte(writeCounter & 0xFF)

	ivEnc := make([]byte,0)
	ivEnc = append(ivEnc, ti...)
	for i:=0; i<3; i++ {
		ivEnc = append(ivEnc, rCountB2)
		ivEnc = append(ivEnc, rCountB1)
		ivEnc = append(ivEnc, wCountB2)
		ivEnc = append(ivEnc, wCountB1)
	}

	/**/
        block, err := aes.NewCipher(keyEnc)
        if err != nil {
                return err
        }
	modeE := cipher.NewCBCEncrypter(block, ivEnc)
	/**/
	dataE := make([]byte,len(data))
	modeE.CryptBlocks(dataE, data)

        blockMac, err := aes.NewCipher(keyMac)
        if err != nil {
                return err
        }

	var1 := []byte{0xA1}
        var1 = append(var1, wCountB2)
        var1 = append(var1, wCountB1)
        var1 = append(var1, ti...)
        var1 = append(var1, keyB2)
        var1 = append(var1, keyB1)
        var1 = append(var1, dataE...)

        cmacS, err := cmac.Sum(var1, blockMac, 16)
        if err != nil {
                return err
        }
        cmac1 := make([]byte,0)
        for i, v := range cmacS {
                if i%2 != 0 {
                        cmac1 = append(cmac1, v)
                }
        }

	aid := []byte{0xA1,keyB2,keyB1}
	aid = append(aid,dataE...)
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if response[0] != byte(0x90) {
		return fmt.Errorf("bad response: [% X]\n", response)
	}

	macResp := response[len(response)-8:]

	wCountB1 = byte((writeCounter+1 >> 8) & 0xFF)
	wCountB2 = byte(writeCounter+1 & 0xFF)
	var2 := make([]byte,0)
	var2 = append(var2, response[0])
        var2 = append(var2, wCountB2)
        var2 = append(var2, wCountB1)
        var2 = append(var2, ti...)

        cmacS2, err := cmac.Sum(var2, blockMac, 16)
        if err != nil {
                return err
        }

        cmac2 := make([]byte,0)
	for i, v := range cmacS2 {
                if i%2 != 0 {
                        cmac2 = append(cmac2, v)
                }
        }

	if !bytes.Equal(macResp, cmac2) {
		return fmt.Errorf("Mac Fail in response, response: [% X]; macCalc: [% X]\n", response, cmac2)
	}

	return nil
}
