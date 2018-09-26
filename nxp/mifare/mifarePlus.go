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
	WritePerso(int, []byte) ([]byte, error)
	CommitPerso() ([]byte, error)
	FirstAuthf1(keyBNr int) ([]byte, error)
	FirstAuthf2([]byte) ([]byte, error)
	FirstAuth(keyBNr int, key []byte) ([]byte, error)
	ReadPlainMacMac(bNr, ext, readCounter int, ti, keyMac []byte) ([]byte, error)
	ReadEncMacMac(bNr, ext, readCounter, writeCounter int, ti, keyMac, keyEnc []byte) ([]byte, error)
	WriteEncMacMac(bNr int, data []byte, readCounter, writeCounter int, ti, keyMac, keyEnc []byte) (error)
	IncEncMacMac(bNr int, data []byte, readCounter, writeCounter int, ti , keyMac, keyEnc []byte) (error)
	TransMacMac(bNr, writeCounter int, ti , keyMac []byte) (error)
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
func verifyResponse(data []byte) error {
	if data == nil {
		return fmt.Errorf("null response")
	}
	if data[0] != 0x90 {
		return fmt.Errorf("error in response SC: %X, response [% X]", data[0], data)
	}
	return nil
}

//Write Perso (Security Level 0)
func (mplus *mifarePlus) WritePerso(bNr int, key []byte) ([]byte, error) {
	keyB1 := byte((bNr >> 8) & 0xFF)
	keyB2 := byte(bNr & 0xFF)
	aid := []byte{0xA8,keyB2,keyB1}
	aid = append(aid, key...)
	response, err :=  mplus.Apdu(aid)
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
	response, err :=  mplus.Apdu(aid)
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
	aid := []byte{0x70,keyB2,keyB1,0x00}
	//fmt.Printf("aid: [% X]", aid)
	response, err :=  mplus.Apdu(aid)
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
	aid := make([]byte,0)
	aid = append(aid, byte(0x72))
	aid = append(aid, data...)
	response, err :=  mplus.Apdu(aid)
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
	aid := []byte{0x76,keyB2,keyB1,0x00}
	response, err :=  mplus.Apdu(aid)
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
	response, err :=  mplus.Apdu(aid)
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

	iv := make([]byte,16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	rndB := make([]byte,16)
	modeD.CryptBlocks(rndB, rndBc)
	//fmt.Printf("rndB: [% X]\n", rndB)

	//rotate rndB
	rndB = append(rndB,rndB[0])
	rndB = rndB[1:]
	//fmt.Printf("rndBrot: [% X]\n", rndB)

	rndA := make([]byte,16)
	rand.Read(rndA)
	//fmt.Printf("rndA: [% X]\n", rndA)

	rndD := make([]byte,0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndB...)
	//fmt.Printf("rndD: [% X]\n", rndD)

	rndDc := make([]byte,len(rndD))
	modeE.CryptBlocks(rndDc, rndD)
	//fmt.Printf("rndDc: [% X]\n", rndDc)

	response, err = mplus.FirstAuthf2(rndDc)
	if err != nil {
		return nil, err
	}
	return response, nil
}

//Read in plain, MAC on response, MAC on command
func (mplus *mifarePlus) ReadPlainMacMac(bNr, ext, readCounter int, Ti , keyMac []byte) ([]byte, error) {

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

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
        var1 = append(var1, bNB2)
        var1 = append(var1, bNB1)
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

	aid := []byte{0x33,bNB2,bNB1,byte(ext)}
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
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
        var2 = append(var2, bNB2)
        var2 = append(var2, bNB1)
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
func (mplus *mifarePlus) ReadEncMacMac(bNr, ext, readCounter, writeCounter int, ti , keyMac, keyEnc []byte) ([]byte, error) {

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

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
	var1 = append(var1, bNB2)
	var1 = append(var1, bNB1)
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
	aid := []byte{0x31,bNB2,bNB1,byte(ext)}
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return nil, err
	}
	if err := verifyResponse(response); err != nil {
		return nil, err
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
	var2 = append(var2, bNB2)
	var2 = append(var2, bNB1)
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
func (mplus *mifarePlus) WriteEncMacMac(bNr int, data []byte, readCounter, writeCounter int, ti , keyMac, keyEnc []byte) (error) {

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

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
        var1 = append(var1, bNB2)
        var1 = append(var1, bNB1)
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

	aid := []byte{0xA1,bNB2,bNB1}
	aid = append(aid,dataE...)
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
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

//Increment encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) IncEncMacMac(bNr int, data []byte, readCounter, writeCounter int, ti , keyMac, keyEnc []byte) (error) {

	if len(data) > 4 {
		return fmt.Errorf("length Data Value is incorrect (must 4)")
	}

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

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
	padding := make([]byte,16-len(data))
	padding = append(padding, byte(0x80))
	data = append(data, padding...)
	dataE := make([]byte,len(data))
	modeE.CryptBlocks(dataE, data)

        blockMac, err := aes.NewCipher(keyMac)
        if err != nil {
                return err
        }

	var1 := []byte{0xB1}
        var1 = append(var1, wCountB2)
        var1 = append(var1, wCountB1)
        var1 = append(var1, ti...)
        var1 = append(var1, bNB2)
        var1 = append(var1, bNB1)
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

	aid := []byte{0xB1,bNB2,bNB1}
	aid = append(aid,dataE...)
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
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

//Transfer encrypted, MAC on response, MAC on command
func (mplus *mifarePlus) TransMacMac(bNr, writeCounter int, ti , keyMac []byte) (error) {

	bNB1 := byte((bNr >> 8) & 0xFF)
	bNB2 := byte(bNr & 0xFF)

	wCountB1 := byte((writeCounter >> 8) & 0xFF)
	wCountB2 := byte(writeCounter & 0xFF)

        blockMac, err := aes.NewCipher(keyMac)
        if err != nil {
                return err
        }

	var1 := []byte{0xB5}
        var1 = append(var1, wCountB2)
        var1 = append(var1, wCountB1)
        var1 = append(var1, ti...)
        var1 = append(var1, bNB2)
        var1 = append(var1, bNB1)

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

	aid := []byte{0xB5,bNB2,bNB1}
	aid = append(aid,cmac1...)
	response, err :=  mplus.Apdu(aid)
	if err != nil {
		return err
	}
	if err := verifyResponse(response); err != nil {
		return err
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


