package samav2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/aead/cmac"
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/nxp/mifare/tools"
)

//SamAv2 Interface
type SamAv2 interface {
	smartcard.ICard
	GetVersion() ([]byte, error)
	/*AuthHostAV2 SAM_AuthenticationHost AV2 mode
	key, key to Authentication
	keyNo, key entry number in SAM key storage
	keyVr, key version used
	hostMode, hostMode (0: plain, 1: Mac, 2: Full)*/
	AuthHostAV2(key []byte, keyNo, keyVr, hostMode int) ([]byte, error)
	NonXauthMFPf1(first bool, sl, keyNo, keyVer int, data, dataDiv []byte) ([]byte, error)
	NonXauthMFPf2(data []byte) ([]byte, error)
	DumpSessionKey() ([]byte, error)
	LockUnlock(key, maxchainBlocks []byte, keyNr, keyVr, unlockKeyNo, unlockKeyVer, p1 int) ([]byte, error)
	SwitchToAV2(key []byte, keyNr, keyVr int) ([]byte, error)
	AuthHostAV1(block cipher.Block, keyNo, keyVer, authMode int) ([]byte, error)
	ChangeKeyEntryAv1(keyNbr, proMax int,
		keyVA, keyVB, keyVC []byte,
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC byte,
		dfAid, set []byte,
	) ([]byte, error)
	ChangeKeyEntry(keyNbr, proMax int,
		keyVA, keyVB, keyVC []byte,
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
		dfAid, set []byte,
	) ([]byte, error)
	ChangeKeyEntryOffline(keyNbr, proMax, changeCtr int,
		keyVA, keyVB, keyVC []byte,
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
		dfAid, set []byte,
		kc, samUID []byte,
	) ([]byte, error)
	ActivateOfflineKey(keyNo, keyVer int,
		divInput []byte,
	) ([]byte, error)
	SAMCombinedWriteMFP(typeMFPdata TypeMFPdata, data []byte,
	) ([]byte, error)
	SAMCombinedReadMFP(typeMFPdata TypeMFPdata, isLastFrame bool, data []byte,
	) ([]byte, error)
}

type samAv2 struct {
	smartcard.ICard
	UUID     []byte
	Kex      []byte
	Kx       []byte
	Ke       []byte
	Km       []byte
	HostMode int
	CmdCtr   int
}

//ConnectSamAv2 Create SamAv2 interface
func ConnectSamAv2(r smartcard.IReader) (SamAv2, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	sam := &samAv2{
		ICard: c,
	}
	return sam, nil
}

//ConnectSam Create SamAv2 interface
func ConnectSam(r smartcard.IReader) (SamAv2, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	sam := &samAv2{
		ICard: c,
	}
	return sam, nil
}

//SamAV2 Create SAM from Card
func SamAV2(c smartcard.ICard) SamAv2 {
	sam := new(samAv2)
	sam.ICard = c
	return sam
}

//ApduGetVersion SAM_GetVersion
func ApduGetVersion() []byte {
	return []byte{0x80, 0x60, 0x00, 0x00, 0x00}
}
func (sam *samAv2) GetVersion() ([]byte, error) {
	return sam.Apdu(ApduGetVersion())
}

func (sam *samAv2) UID() ([]byte, error) {
	if sam.UUID != nil {
		return sam.UUID, nil
	}
	ver, err := sam.GetVersion()
	if err != nil {
		return nil, err
	}

	if ver != nil && len(ver) > 20 {
		return ver[14:21], nil
	}
	return nil, fmt.Errorf("bad formed response, [ %X ]", ver)
}

//rotate(2)
func rotate(data []byte, rot int) []byte {
	res := make([]byte, 0)
	res = append(res, data[rot:]...)
	res = append(res, data[0:rot]...)
	return res
}

//AuthHostAV2 SAM_AuthenticationHost AV2 mode
func (sam *samAv2) AuthHostAV1(block cipher.Block, keyNo, keyVer, authMode int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	iv := make([]byte, block.BlockSize())

	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	aid1 := []byte{0x80, 0xa4, byte(authMode), 0x00, 0x02, byte(keyNo), byte(keyVer), 0x00}

	response, err := sam.Apdu(aid1)
	if err != nil {
		log.Printf("fail response: [ %X ], apdu: [ %X ]", response, aid1)
		return nil, err
	}
	if response[len(response)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response)
	}
	log.Printf("aid1 response: [ %X ], apdu: [ %X ]", response, aid1)
	rndBC := response[0 : len(response)-2]

	rndB := make([]byte, len(rndBC))
	modeD.CryptBlocks(rndB, rndBC)
	rndBr := rotate(rndB, 1)
	log.Printf("rotate rndB: [ %X ], [ %X ]", rndB, rndBr)
	rndA := make([]byte, len(rndB))
	rand.Read(rndA)

	rndD := make([]byte, 0)

	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	rndDc := make([]byte, len(rndD))
	modeE.CryptBlocks(rndDc, rndD)

	aid2 := []byte{0x80, 0xa4, 0x00, 0x00, byte(len(rndDc))}
	aid2 = append(aid2, rndDc...)
	aid2 = append(aid2, byte(0x00))
	//fmt.Printf("aid2: [% X]\n", aid2)
	response, err = sam.Apdu(aid2)
	if err != nil {
		log.Printf("fail response: [ %X ], apdu: [ %X ]", response, aid2)
		return nil, err
	}
	log.Printf("aid2 response: [ %X ], apdu: [ %X ]", response, aid2)

	if err := mifare.VerifyResponseIso7816(response); err != nil {
		log.Printf("fail response: [ %X ], apdu: [ %X ]", response, aid2)
		return nil, err
	}

	kex := make([]byte, 0)
	kex = append(kex, rndA[0:4]...)
	kex = append(kex, rndB[0:4]...)
	// kex = append(kex, rndA[4:8]...)
	// kex = append(kex, rndB[4:8]...)

	sam.Kex = kex

	sam.CmdCtr = 1
	return response, nil
}

//ApduLockUnlock Apdu LockUnlock
func ApduLockUnlock(keyNr, keyVr, unlockKeyNo, unlockKeyVer, p1 int, maxchainBlocks []byte) []byte {
	aid1 := []byte{0x80, 0x10, byte(p1), 0x00, 0x00}
	//keyNr
	aid1 = append(aid1, byte(keyNr))
	//KeyVr
	aid1 = append(aid1, byte(keyVr))
	//maxchainBlocks
	aid1 = append(aid1, make([]byte, 3)...)
	//Le
	if (p1 != 0x03) && (p1 != 0x40) {
		aid1[4] = 0x07
		aid1 = append(aid1, byte(unlockKeyNo))
		aid1 = append(aid1, byte(unlockKeyVer))
	} else {
		aid1[4] = 0x05
	}
	aid1 = append(aid1, 0x00)

	return aid1

}

//ApduLockUnlockPart2 APDU LockUnlock part2
func ApduLockUnlockPart2(cmacb, rnd []byte) []byte {
	aid2 := []byte{0x80, 0x10, 0x00, 0x00, 0x14}
	aid2 = append(aid2, cmacb...)
	aid2 = append(aid2, rnd...)
	aid2 = append(aid2, byte(0x00))

	return aid2
}

func (sam *samAv2) LockUnlock(key, maxchainBlocks []byte, keyNr, keyVr, unlockKeyNo, unlockKeyVer, p1 int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	iv := make([]byte, len(key))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	// aid1 := []byte{0x80, 0x10, 0x03, 0x00, 0x05}
	// //keyNr
	// aid1 = append(aid1, byte(keyNr))
	// //KeyVr
	// aid1 = append(aid1, byte(keyVr))
	// //maxchainBlocks
	// aid1 = append(aid1, make([]byte, 3)...)
	// //Le
	// aid1 = append(aid1, 0x00)

	aid1 := ApduLockUnlock(keyNr, keyVr, unlockKeyNo, unlockKeyVer, p1, maxchainBlocks)

	response, err := sam.Apdu(aid1)
	if err != nil {
		log.Printf("fail response: [ %X ]", response)
		return nil, err
	}
	log.Printf("fail response: [ %X ], apdu: [ %X ]", response, aid1)

	if response[len(response)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response)
	}
	rnd2 := response[0 : len(response)-2]
	var1 := make([]byte, 0)
	var1 = append(var1, rnd2...)
	var1 = append(var1, 0x03)
	var1 = append(var1, make([]byte, 3)...)
	cmacS, err := cmac.Sum(var1, block, 16)
	if err != nil {
		return nil, err
	}
	cmac2 := make([]byte, 0)
	for i, v := range cmacS {
		if i%2 != 0 {
			cmac2 = append(cmac2, v)
		}
	}
	rnd1 := make([]byte, 12)
	rand.Read(rnd1)

	/**
	fmt.Printf("cmacS: [% X]\n", cmacS)
	fmt.Printf("cmac2: [% X]\n", cmac2)
	fmt.Printf("rnd1: [% X]\n", rnd1)
	fmt.Printf("rnd2: [% X]\n", rnd2)
	/**/

	// aid2 := []byte{0x80, 0x10, 0x00, 0x00, 0x14}
	// aid2 = append(aid2, cmac2...)
	// aid2 = append(aid2, rnd1...)
	// aid2 = append(aid2, byte(0x00))

	aid2 := ApduLockUnlockPart2(cmac2, rnd1)
	//fmt.Printf("aid2: [% X]\n", aid2)
	response, err = sam.Apdu(aid2)
	if err != nil {
		return nil, err
	}
	log.Printf("fail aid response: [ %X ], apdu: [ %X ]", response, aid2)
	if response[len(response)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response)
	}

	rndBc := response[8 : len(response)-2]

	aXor := make([]byte, 5)
	for i, _ := range aXor {
		aXor[i] = rnd1[i] ^ rnd2[i]
	}
	divKey := make([]byte, 0)
	divKey = append(divKey, rnd1[7:12]...)
	divKey = append(divKey, rnd2[7:12]...)
	divKey = append(divKey, aXor...)
	divKey = append(divKey, byte(0x91))

	kex := make([]byte, 16)
	modeE.CryptBlocks(kex, divKey)

	sam.Kex = kex

	rndB := make([]byte, len(rndBc))
	block, err = aes.NewCipher(kex)
	if err != nil {
		return nil, err
	}
	modeD = cipher.NewCBCDecrypter(block, iv)
	modeD.CryptBlocks(rndB, rndBc)

	rndA := make([]byte, len(rndB))
	rand.Read(rndA)
	/**
	fmt.Printf("rndA: [% X]\n", rndA)
	fmt.Printf("rndB: [% X]\n", rndB)
	/**/

	//rotate(2)
	//rotate := 2
	//for i, v := range rndB {
	//	if i >= rotate {
	//		break
	//	}
	//	rndB = append(rndB, v)
	//	rndB = rndB[1:]
	//}
	rndBr := rotate(rndB, 2)

	//fmt.Printf("rndB2: [% X]\n", rndB)

	rndD := make([]byte, 0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	//fmt.Printf("rndD: [% X]\n", rndD)

	ecipher := make([]byte, len(rndD))
	modeE = cipher.NewCBCEncrypter(block, iv)
	modeE.CryptBlocks(ecipher, rndD)

	aid3 := []byte{0x80, 0x10, 0x00, 0x00, 0x20}
	aid3 = append(aid3, ecipher...)
	aid3 = append(aid3, byte(0x00))

	response, err = sam.Apdu(aid3)
	if err != nil {
		return nil, err
	}

	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	return response, nil
}

func (sam *samAv2) SwitchToAV2(key []byte, keyNr, keyVr int) ([]byte, error) {
	return sam.LockUnlock(key, make([]byte, 3), keyNr, keyVr, 0, 0, 0x03)
}

//AuthHostAV2 SAM_AuthenticationHost AV2 mode
func (sam *samAv2) AuthHostAV2(key []byte, keyNo, keyVer, hostMode int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	iv := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if hostMode > 3 {
		return nil, fmt.Errorf("hostMode incorrect: %d", hostMode)
	}
	sam.HostMode = hostMode
	sam.Kx = key
	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	aid1 := []byte{0x80, 0xa4, 0x00, 0x00, 0x03, byte(keyNo), byte(keyVer), byte(hostMode), 0x00}

	response, err := sam.Apdu(aid1)
	if err != nil {
		return nil, err
	}
	// log.Printf("fail aid response: [ %X ], apdu: [ %X ]", response, aid1)
	if response[len(response)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response)
	}
	rnd2 := response[0 : len(response)-2]
	var1 := make([]byte, 0)
	var1 = append(var1, rnd2...)
	var1 = append(var1, byte(hostMode))
	var1 = append(var1, make([]byte, 3)...)
	cmacS, err := cmac.Sum(var1, block, 16)
	if err != nil {
		return nil, err
	}
	cmac2 := make([]byte, 0)
	for i, v := range cmacS {
		if i%2 != 0 {
			cmac2 = append(cmac2, v)
		}
	}
	rnd1 := make([]byte, 12)
	rand.Read(rnd1)

	/**
	fmt.Printf("cmacS: [% X]\n", cmacS)
	fmt.Printf("cmac2: [% X]\n", cmac2)
	fmt.Printf("rnd1: [% X]\n", rnd1)
	fmt.Printf("rnd2: [% X]\n", rnd2)
	/**/

	aid2 := []byte{0x80, 0xa4, 0x00, 0x00, 0x14}
	aid2 = append(aid2, cmac2...)
	aid2 = append(aid2, rnd1...)
	aid2 = append(aid2, byte(0x00))
	//fmt.Printf("aid2: [% X]\n", aid2)
	response, err = sam.Apdu(aid2)
	if err != nil {
		return nil, err
	}
	// log.Printf("fail aid response: [ %X ], apdu: [ %X ]", response, aid2)

	if response[len(response)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response)
	}

	rndBc := response[8 : len(response)-2]

	aXor := make([]byte, 5)
	for i, _ := range aXor {
		aXor[i] = rnd1[i] ^ rnd2[i]
	}
	divKey := make([]byte, 0)
	divKey = append(divKey, rnd1[7:12]...)
	divKey = append(divKey, rnd2[7:12]...)
	divKey = append(divKey, aXor...)
	divKey = append(divKey, byte(0x91))

	kex := make([]byte, 16)
	modeE.CryptBlocks(kex, divKey)

	sam.Kex = kex

	rndB := make([]byte, len(rndBc))
	block, err = aes.NewCipher(kex)
	if err != nil {
		return nil, err
	}
	modeD = cipher.NewCBCDecrypter(block, iv)
	modeD.CryptBlocks(rndB, rndBc)

	rndA := make([]byte, len(rndB))
	rand.Read(rndA)
	/**
	fmt.Printf("rndA: [% X]\n", rndA)
	fmt.Printf("rndB: [% X]\n", rndB)
	/**/

	//rotate(2)
	//rotate := 2
	//for i, v := range rndB {
	//	if i >= rotate {
	//		break
	//	}
	//	rndB = append(rndB, v)
	//	rndB = rndB[1:]
	//}
	rndBr := rotate(rndB, 2)

	//fmt.Printf("rndB2: [% X]\n", rndB)

	rndD := make([]byte, 0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	//fmt.Printf("rndD: [% X]\n", rndD)

	ecipher := make([]byte, len(rndD))
	modeE = cipher.NewCBCEncrypter(block, iv)
	modeE.CryptBlocks(ecipher, rndD)

	aid3 := []byte{0x80, 0xa4, 0x00, 0x00, 0x20}
	aid3 = append(aid3, ecipher...)
	aid3 = append(aid3, byte(0x00))

	response, err = sam.Apdu(aid3)
	if err != nil {
		return nil, err
	}

	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}

	if hostMode > 0 {

		funcExtract := func(data []byte, i, j int) []byte {
			return data[16-i : 16-j]
		}

		sv2 := make([]byte, 0)

		sv2 = append(sv2, funcExtract(rndA, 9, 4)...)
		sv2 = append(sv2, funcExtract(rndB, 9, 4)...)

		fragb := funcExtract(rndB, 16, 11)

		for k, v := range funcExtract(rndA, 16, 11) {
			sv2 = append(sv2, fragb[k]^v)
		}
		sv2 = append(sv2, 0x82)
		log.Printf("SV2: [ %X ]", sv2)
		//km, err := cmac.Sum(sv2, block, 16)
		//if err != nil {
		//	return nil, err
		//}
		//log.Printf("km: [ %X ]", km)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		// km, err := cmac.Sum(sv2, block, 16)
		// if err != nil {
		// 	return nil, err
		// }
		// log.Printf("km: [ %X ]", km)
		// //block, err := aes.NewCipher(key)
		// //if err != nil {
		// //	return nil, err
		// //}
		modeE := cipher.NewCBCEncrypter(block, iv)
		km := make([]byte, 16)
		modeE.CryptBlocks(km, sv2)
		log.Printf("km: [ %X ]", km)

		sam.Km = km
	}

	if hostMode > 1 {
		funcExtract := func(data []byte, i, j int) []byte {
			return data[16-i : 16-j]
		}

		sv1 := make([]byte, 0)

		sv1 = append(sv1, funcExtract(rndA, 5, 0)...)
		sv1 = append(sv1, funcExtract(rndB, 5, 0)...)

		fraga := funcExtract(rndB, 12, 7)

		for k, v := range funcExtract(rndA, 12, 7) {
			sv1 = append(sv1, fraga[k]^v)
		}
		sv1 = append(sv1, 0x81)

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		// ke, err := cmac.Sum(sv1, block, 16)
		// if err != nil {
		// 	return nil, err
		// }

		modeE := cipher.NewCBCEncrypter(block, iv)
		ke := make([]byte, 16)
		modeE.CryptBlocks(ke, sv1)
		log.Printf("ke: [ %X ]", ke)

		sam.Ke = ke
	}

	sam.CmdCtr = 0
	return response, nil
}

//ApduNonXauthMFPf1 SAM_AuthenticationMFP (non-X-mode) first part
func ApduNonXauthMFPf1(first bool, sl, keyNo, keyVer int, data, dataDiv []byte) []byte {
	p1 := byte(0x00)
	if dataDiv != nil {
		p1 = byte(0x01)
	}
	if !first {
		p1 = p1 + byte(0x02)
	}
	if sl == 2 {
		p1 = p1 + byte(0x04)
	} else if sl == 3 {
		p1 = p1 + byte(0x0C)
	} else if sl != 0 {
		p1 = p1 + byte(0x80)
	}

	aid1 := []byte{0x80, 0xA3, p1, 0x00, byte(18 + len(dataDiv))}
	aid1 = append(aid1, byte(keyNo))
	aid1 = append(aid1, byte(keyVer))
	aid1 = append(aid1, data...)

	if dataDiv != nil {
		aid1 = append(aid1, dataDiv...)
	}

	aid1 = append(aid1, byte(0x00))
	fmt.Printf("aid: [% X]\n", aid1)
	return aid1
}

//NonXauthMFPf1 SAM_AuthenticationMFP (non-X-mode) first part
func (sam *samAv2) NonXauthMFPf1(first bool, sl, keyNo, keyVer int, data, dataDiv []byte) ([]byte, error) {
	return sam.Apdu(ApduNonXauthMFPf1(first, sl, keyNo, keyVer, data, dataDiv))
}

//ApduNonXauthMFPf2 SAM_AuthenticationMFP (non-X-mode) second part
func ApduNonXauthMFPf2(data []byte) []byte {

	aid1 := []byte{0x80, 0xA3, 0x00, 0x00, byte(len(data))}
	aid1 = append(aid1, data...)
	aid1 = append(aid1, byte(0x00))

	fmt.Printf("aid: [% X]\n", aid1)
	return aid1
}

//NonXauthMFPf2 SAM_AuthenticationMFP (non-X-mode) second part
func (sam *samAv2) NonXauthMFPf2(data []byte) ([]byte, error) {
	return sam.Apdu(ApduNonXauthMFPf2(data))
}

//ApduDumpSessionKey SAM_DumpSessionKey (session key of an established authentication with a DESFire or MIFARE Plus PICC)
func ApduDumpSessionKey() []byte {
	return []byte{0x80, 0xD5, 0x00, 0x00, 0x00}
}

//DumpSessionKey SAM_DumpSessionKey (session key of an established authentication with a DESFire or MIFARE Plus PICC)
func (sam *samAv2) DumpSessionKey() ([]byte, error) {
	response, err := sam.Apdu(ApduDumpSessionKey())
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	return response, nil
}

//ApduSamKillAuthPICC SAM_KillAuthentication invalidates any kind authentication PICC
func ApduSamKillAuthPICC() []byte {
	return []byte{0x80, 0xCA, 0x01, 0x00}
}

//ApduEncipher_Data SAM_EncipherOffile_Data command encrypts data received from any other system based on the given cipher text data andt the current valid cryptographic OfflineCrypto Key.
func ApduEncipher_Data(last bool, offset int, dataPlain []byte) []byte {
	p1 := byte(0x00)
	if !last {
		p1 = byte(0xAF)
	}
	aid1 := []byte{0x80, 0xED, byte(p1), byte(offset)}
	aid1 = append(aid1, byte(len(dataPlain)))
	aid1 = append(aid1, dataPlain...)
	aid1 = append(aid1, 0x00)

	return aid1
}

//ApduDecipher_Data
func ApduDecipher_Data(last bool, mifare int, cipher []byte) []byte {
	p1 := byte(0x00)
	if !last {
		p1 = byte(0xAF)
	}
	aid1 := []byte{0x80, 0xDD, byte(p1), 0x00}
	length := len(cipher)
	if p1 == byte(0x00) || mifare <= 0 {
		length = length + 3
	}
	aid1 = append(aid1, byte(length))
	aid1 = append(aid1, cipher...)
	aid1 = append(aid1, 0x00)

	return aid1
}

//ApduEncipherOffline_Data SAM_EncipherOffile_Data command encrypts data received from any other system based on the given cipher text data andt the current valid cryptographic OfflineCrypto Key.
func ApduEncipherOffline_Data(last bool, dataPlain []byte) []byte {
	p1 := byte(0x00)
	if !last {
		p1 = byte(0xAF)
	}
	aid1 := []byte{0x80, 0x0E, byte(p1), 0x00}
	aid1 = append(aid1, byte(len(dataPlain)))
	aid1 = append(aid1, dataPlain...)
	aid1 = append(aid1, 0x00)

	return aid1
}

//ApduDecipherOffline_Data
func ApduDecipherOffline_Data(last bool, cipher []byte) []byte {
	p1 := byte(0x00)
	if !last {
		p1 = byte(0xAF)
	}
	aid1 := []byte{0x80, 0x0D, byte(p1), 0x00}
	aid1 = append(aid1, byte(len(cipher)))
	aid1 = append(aid1, cipher...)
	aid1 = append(aid1, 0x00)

	return aid1
}

//apduChangeKeyEntry create APDU to SAM_ApduChangeKeyEntry
func apduChangeKeyEntryAv1(hostMode, keyNbr, proMax, cmdCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC byte,
	dfAid, set []byte,
	kex []byte,
) ([]byte, error) {
	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0xC1,
		P1:  byte(keyNbr),
		P2:  byte(proMax),
		Le:  false,
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)

	payload := make([]byte, 0)
	payload = append(payload, keyVA...)
	payload = append(payload, keyVB...)
	payload = append(payload, keyVC...)

	payload = append(payload, dfAid...)
	payload = append(payload, dfKeyNr)
	payload = append(payload, ceKNo)
	payload = append(payload, ceKV)
	payload = append(payload, kuc)
	payload = append(payload, set...)
	payload = append(payload, verA)
	payload = append(payload, verB)
	payload = append(payload, verC)

	crc16 := tools.Crc16(payload)

	payload = append(payload, crc16...)

	//padding
	payload = append(payload, make([]byte, 2)...)

	log.Printf("payload chankeKeyAv1: [ %X ], len: %v", payload, len(payload))

	rand.Seed(time.Now().UnixNano())
	iv := make([]byte, 8)
	block, err := des.NewCipher(kex)
	if err != nil {
		return nil, err
	}

	modeE := cipher.NewCBCEncrypter(block, iv)

	payloadC := make([]byte, len(payload))
	modeE.CryptBlocks(payloadC, payload)

	apdu = append(apdu, byte(len(payloadC)))
	apdu = append(apdu, payloadC...)

	return apdu, nil
}

//ChangeKeyEntry SAM_ApduChangeKeyEntry command
func (sam *samAv2) ChangeKeyEntryAv1(keyNbr, proMax int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC byte,
	dfAid, set []byte,
) ([]byte, error) {

	apdu, err := apduChangeKeyEntryAv1(sam.HostMode, keyNbr, proMax, sam.CmdCtr, keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc,
		verA, verB, verC, dfAid, set,
		sam.Kex)
	if err != nil {
		return nil, err
	}

	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	return response, nil
}

func newEntryKey(keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set []byte) []byte {

	payload := make([]byte, 0)
	payload = append(payload, keyVA...)
	payload = append(payload, keyVB...)
	payload = append(payload, keyVC...)

	payload = append(payload, dfAid...)
	payload = append(payload, dfKeyNr)
	payload = append(payload, ceKNo)
	payload = append(payload, ceKV)
	payload = append(payload, kuc)
	payload = append(payload, set...)
	payload = append(payload, verA)
	payload = append(payload, verB)
	payload = append(payload, verC)
	payload = append(payload, extSet)

	return payload
}

//ApduChangeKeyEntryOffline create APDU to SAM_ApduChangeKeyEntry
func ApduChangeKeyEntryOffline(keyNbr, proMax, changeCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set []byte,
	kc, samUID []byte,
) ([]byte, error) {
	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0xC1,
		P1:  byte(keyNbr),
		P2:  byte(proMax),
		Le:  false,
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)

	changeCtrSlice := make([]byte, 2)
	binary.BigEndian.PutUint16(changeCtrSlice, uint16(changeCtr))

	payload := newEntryKey(keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet,
		dfAid, set)

	encPayload, err := tools.OfflineChangeKeyEncrypt(payload, kc, samUID, changeCtr)
	if err != nil {
		return nil, err
	}

	log.Printf("payload   : [ %X ]", payload)
	log.Printf("encPayload: [ %X ]", encPayload)

	apdu = append(apdu, byte(len(encPayload)+len(changeCtrSlice))+8)
	apdu = append(apdu, changeCtrSlice...)
	apdu = append(apdu, encPayload...)

	macT, err := tools.OfflineChangeKeyMac(apdu, kc, changeCtr)
	if err != nil {
		return nil, err
	}
	apdu = append(apdu, macT...)

	return apdu, nil
}

//apduChangeKeyEntry create APDU to SAM_ApduChangeKeyEntry
func apduChangeKeyEntry(hostMode, keyNbr, proMax, cmdCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set []byte,
	ke, km []byte,
) ([]byte, error) {
	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0xC1,
		P1:  byte(keyNbr),
		P2:  byte(proMax),
		Le:  false,
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)

	payload := newEntryKey(keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet,
		dfAid, set)

	switch hostMode {
	case 0:
		apdu = append(apdu, byte(len(payload)))
		apdu = append(apdu, payload...)
		return apdu, nil
	case 1:
		macT, err := tools.MacFullProtection(cmd, cmdCtr, payload, km)
		if err != nil {
			return nil, err
		}
		log.Printf("MACt: [ %X ]", macT)
		apdu = append(apdu, byte(len(payload)+len(macT)))
		apdu = append(apdu, payload...)
		apdu = append(apdu, macT...)
		return apdu, nil
	case 2:
		encD, err := tools.EncryptFullProtection(cmdCtr, payload, ke)
		if err != nil {
			return nil, err
		}
		log.Printf("encD: [ %X ]", encD)
		macT, err := tools.MacFullProtection(cmd, cmdCtr, encD, km)
		if err != nil {
			return nil, err
		}
		log.Printf("MACt: [ %X ]", macT)
		apdu = append(apdu, byte(len(encD)+len(macT)))
		apdu = append(apdu, encD...)
		apdu = append(apdu, macT...)
		return apdu, nil
	}

	return nil, fmt.Errorf("hostMode incorrect")
}

//ApduChangeKeyEntryPlainMode create APDU to SAM_ApduChangeKeyEntry
func ApduChangeKeyEntryPlainMode(keyNbr, proMax int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set []byte,
) ([]byte, error) {
	return apduChangeKeyEntry(0, keyNbr, proMax, 0, keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc,
		verA, verB, verC, extSet, dfAid, set,
		nil, nil)
}

//ApduChangeKeyEntryMacMode create APDU to SAM_ApduChangeKeyEntry
func ApduChangeKeyEntryMacMode(keyNbr, proMax, cmdCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set, km []byte,
) ([]byte, error) {
	return apduChangeKeyEntry(1, keyNbr, proMax, cmdCtr, keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc,
		verA, verB, verC, extSet, dfAid, set,
		nil, km)
}

//ApduChangeKeyEntryFullMode create APDU to SAM_ApduChangeKeyEntry
func ApduChangeKeyEntryFullMode(keyNbr, proMax, cmdCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set, kex, ke, km []byte,
) ([]byte, error) {
	return apduChangeKeyEntry(2, keyNbr, proMax, cmdCtr, keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc,
		verA, verB, verC, extSet, dfAid, set,
		ke, km)
}

//ChangeKeyEntry SAM_ApduChangeKeyEntry command
func (sam *samAv2) ChangeKeyEntry(keyNbr, proMax int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set []byte,
) ([]byte, error) {

	apdu, err := apduChangeKeyEntry(sam.HostMode, keyNbr, proMax, sam.CmdCtr, keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc,
		verA, verB, verC, extSet, dfAid, set,
		sam.Ke, sam.Km)
	if err != nil {
		return nil, err
	}
	sam.CmdCtr++
	log.Printf("apud: [ %X ]", apdu)

	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	return response, nil
}

//ChangeKeyEntryOffline SAM_ApduChangeKeyEntry command
func (sam *samAv2) ChangeKeyEntryOffline(keyNbr, proMax, changeCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	dfAid, set []byte,
	kc, samUID []byte,
) ([]byte, error) {

	apdu, err := ApduChangeKeyEntryOffline(keyNbr, proMax, changeCtr, keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc,
		verA, verB, verC, extSet, dfAid, set,
		kc, samUID)
	if err != nil {
		return nil, err
	}
	log.Printf("apud: [ %X ]", apdu)

	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	return response, nil
}

//ApduActivateOfflineKey create apdu for SAM_ActiveOfflineKey command
func ApduActivateOfflineKey(keyNo, keyVer int, divInput []byte,
) []byte {
	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x01,
		P1:  byte(0x00),
		P2:  byte(0x00),
		Le:  false,
	}

	if divInput != nil {
		cmd.P1 = 0x01
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)

	//len [Lc]
	if divInput != nil {
		apdu = append(apdu, byte(len(apdu))+2)

	} else {
		apdu = append(apdu, byte(2))
	}

	apdu = append(apdu, byte(keyNo))
	apdu = append(apdu, byte(keyVer))
	if divInput != nil {
		apdu = append(apdu, divInput...)
	}

	return apdu
}

//ActiveOfflineKey SAM_ActiveOfflineKey command
func (sam *samAv2) ActivateOfflineKey(keyNo, keyVer int,
	divInput []byte,
) ([]byte, error) {
	apdu := ApduActivateOfflineKey(keyNo, keyVer, divInput)
	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		log.Printf("apdu: [ % X ] ", apdu)
		return nil, err
	}

	return response, nil
}

type TypeMFPdata int

const (
	MFP_Command         TypeMFPdata = 0x00
	MFP_Response        TypeMFPdata = 0x01
	MFP_CommandResponse TypeMFPdata = 0x02
)

func ApduSAMCombinedReadMFP(typeMFPdata TypeMFPdata, isLastFrame bool, data []byte,
) []byte {

	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x33,
		P1:  byte(0x00) | byte(typeMFPdata),
		P2:  byte(0x00),
		Le:  true,
	}

	if !isLastFrame {
		cmd.P2 |= byte(0xAF)
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)

	apdu = append(apdu, byte(len(data)))
	apdu = append(apdu, data...)
	apdu = append(apdu, 0x00)

	return apdu
}

//SAMCombinedReadMFP SAM_CombinedReadMFP command
func (sam *samAv2) SAMCombinedReadMFP(typeMFPdata TypeMFPdata, isLastFrame bool, data []byte,
) ([]byte, error) {
	apdu := ApduSAMCombinedReadMFP(typeMFPdata, isLastFrame, data)
	log.Printf("apdu: [ % X ] ", apdu)
	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {

		return nil, err
	}

	return response, nil
}

func ApduSAMCombinedWriteMFP(typeMFPdata TypeMFPdata, data []byte,
) []byte {
	if data == nil {
		return nil
	}
	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x34,
		P1:  byte(0x00) | byte(typeMFPdata),
		P2:  byte(0x00),
		Le:  true,
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)
	apdu = append(apdu, byte(len(data)))
	apdu = append(apdu, data...)
	apdu = append(apdu, 0x00)

	return apdu
}

//SAMCombinedWriteMFP SAM_CombinedWriteMFP command
func (sam *samAv2) SAMCombinedWriteMFP(typeMFPdata TypeMFPdata, data []byte,
) ([]byte, error) {
	apdu := ApduSAMCombinedWriteMFP(typeMFPdata, data)
	if apdu == nil {
		return nil, fmt.Errorf("bad frame: [% X]", data)
	}
	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		log.Printf("apdu: [ % X ] ", apdu)
		return nil, err
	}

	return response, nil
}
