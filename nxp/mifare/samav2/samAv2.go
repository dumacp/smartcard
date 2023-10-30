package samav2

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/aead/cmac"
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

type CrytoAlgorithm int

const (
	AES_ALG CrytoAlgorithm = iota
	DES_ALG
)

// SamAv2 Interface
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
	DumpSecretKey(keyNo, keyVer int, divInput []byte) ([]byte, error)
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
	SAMGetKeyEntry(keyNo int) ([]byte, error)
	ActivateOfflineKey(keyNo, keyVer int,
		divInput []byte,
	) ([]byte, error)
	SAMCombinedWriteMFP(typeMFPdata TypeMFPdata, data []byte,
	) ([]byte, error)
	SAMCombinedReadMFP(typeMFPdata TypeMFPdata, isLastFrame bool, data []byte,
	) ([]byte, error)
	SAMEncipherData(alg CrytoAlgorithm, data []byte) ([]byte, error)
	SAMGenerateMAC(alg CrytoAlgorithm, data []byte) ([]byte, error)
	SAMEncipherOfflineData(alg CrytoAlgorithm, data []byte) ([]byte, error)
	SAMDecipherData(alg CrytoAlgorithm,
		data []byte) ([]byte, error)
	SAMDecipherOfflineData(alg CrytoAlgorithm, data []byte) ([]byte, error)
	PKIGenerateKeyPair(pkiE []byte, pkiSET []byte,
		pkiKeyNo, pkiKeyNoCEK, pkikeVCEK, pkiRefNoKUC, pkiNLen int) ([]byte, error)
	PKIExportPublicKey(pkiKeyNo int) ([]byte, error)
	PKIUpdateKeyEntries(hashing HashingAlgorithm, keyEntrysNo int,
		pkiKeyNoEnc, pkiKeyNoSign int, pkiEncKeyFrame, pkiSignature []byte) ([]byte, error)
	SAMLoadInitVector(alg CrytoAlgorithm, data []byte) ([]byte, error)
	PKIImportKey(pkiKeyNo, pkiKeyNoCEK, pkiKeyVCEK, pkiRefNoKUC int,
		pkiSET, pkie, pkiN, pkip, pkiq, pkidP, pkidQ, pkiipq []byte) ([]byte, error)
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

// ConnectSamAv2 Create SamAv2 interface
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

// ConnectSam Create SamAv2 interface
func ConnectSam(r smartcard.IReader) (SamAv2, error) {

	c, err := r.ConnectSamCard()
	if err != nil {
		return nil, err
	}
	sam := &samAv2{
		ICard: c,
	}
	return sam, nil
}

// SamAV2 Create SAM from Card
func SamAV2(c smartcard.ICard) SamAv2 {
	sam := new(samAv2)
	sam.ICard = c
	return sam
}

// ApduGetVersion SAM_GetVersion
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

	if len(ver) > 20 {
		return ver[14:21], nil
	}
	return nil, fmt.Errorf("bad formed response, [ %X ]", ver)
}

// rotate(2)
func rotate(data []byte, rot int) []byte {
	res := make([]byte, 0)
	res = append(res, data[rot:]...)
	res = append(res, data[0:rot]...)
	return res
}

// AuthHostAV2 SAM_AuthenticationHost AV2 mode
func (sam *samAv2) AuthHostAV1(block cipher.Block, keyNo, keyVer, authMode int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	iv := make([]byte, block.BlockSize())

	modeE := cipher.NewCBCEncrypter(block, iv)
	modeD := cipher.NewCBCDecrypter(block, iv)

	aid1 := []byte{0x80, 0xa4, byte(authMode), 0x00, 0x02, byte(keyNo), byte(keyVer), 0x00}

	response, err := sam.Apdu(aid1)
	if err != nil {
		// log.Printf("fail response: [ %X ], apdu: [ %X ]", response, aid1)
		return nil, err
	}
	if response[len(response)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response)
	}
	// log.Printf("aid1 response: [ %X ], apdu: [ %X ]", response, aid1)
	rndBC := response[0 : len(response)-2]

	rndB := make([]byte, len(rndBC))
	modeD.CryptBlocks(rndB, rndBC)
	rndBr := rotate(rndB, 1)
	// log.Printf("rotate rndB: [ %X ], [ %X ]", rndB, rndBr)
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

// ApduLockUnlock Apdu LockUnlock
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

// ApduLockUnlockPart2 APDU LockUnlock part2
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
	// modeD := cipher.NewCBCDecrypter(block, iv)

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
		// log.Printf("fail response: [ %X ]", response)
		return nil, err
	}
	// log.Printf("fail response: [ %X ], apdu: [ %X ]", response, aid1)

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
	// log.Printf("fail aid response: [ %X ], apdu: [ %X ]", response, aid2)
	if response[len(response)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response)
	}

	rndBc := response[8 : len(response)-2]

	aXor := make([]byte, 5)
	for i := range aXor {
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
	modeD := cipher.NewCBCDecrypter(block, iv)
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

// AuthHostAV2 SAM_AuthenticationHost AV2 modeAuthHostAV2
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
	// modeD := cipher.NewCBCDecrypter(block, iv)

	aid1 := []byte{0x80, 0xa4, 0x00, 0x00, 0x03, byte(keyNo), byte(keyVer), byte(hostMode), 0x00}

	response1, err := sam.Apdu(aid1)
	if err != nil {
		return nil, err
	}
	// response, _ = hex.DecodeString("994E8B254E1B48AFBCE38A8190AF")
	// fmt.Printf("aid response1: [ %X ], apdu: [ %X ]\n", response1, aid1)
	if response1[len(response1)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response1: [% X]", response1)
	}
	rnd2 := make([]byte, 12)
	copy(rnd2, response1[0:len(response1)-2])
	// rnd2 := response1[0 : len(response1)-2]
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
	// rnd1, _ = hex.DecodeString("A408BEB67688B37328DDBF82")

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
	// fmt.Printf("aid2: [% X]\n", aid2)
	response2, err := sam.Apdu(aid2)
	if err != nil {
		return nil, err
	}
	// response, _ = hex.DecodeString("17A9822892E3EFAF51C9541C72B16092BA76A46F2594154990AF")
	// fmt.Printf("aid response: [ %X ], apdu: [ %X ]\n", response2, aid2)

	if response2[len(response2)-1] != byte(0xAF) {
		return nil, fmt.Errorf("bad formed response: [% X]", response2)
	}

	rndBc := make([]byte, 16)
	copy(rndBc, response2[8:len(response2)-2])

	aXor := make([]byte, 5)
	for i := range aXor {
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
	modeD := cipher.NewCBCDecrypter(block, iv)
	modeD.CryptBlocks(rndB, rndBc)

	rndA := make([]byte, len(rndB))
	rand.Read(rndA)
	// rndA, _ = hex.DecodeString("861799E95701CC49A1A3C18FCDC95D64")
	/**
	fmt.Printf("rndBc: [% X]\n", rndBc)
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

	// fmt.Printf("rndB2: [% X]\n", rndBr)

	rndD := make([]byte, 0)
	rndD = append(rndD, rndA...)
	rndD = append(rndD, rndBr...)

	// fmt.Printf("rndD: [% X]\n", rndD)

	ecipher := make([]byte, len(rndD))
	modeE = cipher.NewCBCEncrypter(block, iv)
	modeE.CryptBlocks(ecipher, rndD)

	aid3 := []byte{0x80, 0xa4, 0x00, 0x00, 0x20}
	aid3 = append(aid3, ecipher...)
	aid3 = append(aid3, byte(0x00))

	// fmt.Printf("aid3: [% X]\n", aid3)
	response3, err := sam.Apdu(aid3)
	if err != nil {
		return nil, err
	}

	if err := mifare.VerifyResponseIso7816(response3); err != nil {
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
		// log.Printf("SV2: [ %X ]", sv2)
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
		// log.Printf("km: [ %X ]", km)

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
		// log.Printf("ke: [ %X ]", ke)

		sam.Ke = ke
	}

	sam.CmdCtr = 0
	return response3, nil
}

// ApduNonXauthMFPf1 SAM_AuthenticationMFP (non-X-mode) first part
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
	// fmt.Printf("aid: [% X]\n", aid1)
	return aid1
}

// NonXauthMFPf1 SAM_AuthenticationMFP (non-X-mode) first part
func (sam *samAv2) NonXauthMFPf1(first bool, sl, keyNo, keyVer int, data, dataDiv []byte) ([]byte, error) {
	return sam.Apdu(ApduNonXauthMFPf1(first, sl, keyNo, keyVer, data, dataDiv))
}

// ApduNonXauthMFPf2 SAM_AuthenticationMFP (non-X-mode) second part
func ApduNonXauthMFPf2(data []byte) []byte {

	aid1 := []byte{0x80, 0xA3, 0x00, 0x00, byte(len(data))}
	aid1 = append(aid1, data...)
	aid1 = append(aid1, byte(0x00))

	// fmt.Printf("aid: [% X]\n", aid1)
	return aid1
}

// NonXauthMFPf2 SAM_AuthenticationMFP (non-X-mode) second part
func (sam *samAv2) NonXauthMFPf2(data []byte) ([]byte, error) {
	return sam.Apdu(ApduNonXauthMFPf2(data))
}

// ApduDumpSessionKey SAM_DumpSessionKey (session key of an established authentication with a DESFire or MIFARE Plus PICC)
func ApduDumpSessionKey() []byte {
	return []byte{0x80, 0xD5, 0x00, 0x00, 0x00}
}

// ApduDumpSecretKey SAM_DumpSecretKey (allows dumping any of PICC keys or OfflineCrypto keys)
func ApduDumpSecretKey(keyNo, keyVer int, divInput []byte) []byte {
	p1 := byte(0x00)
	if len(divInput) > 0 {
		p1 = 0x02
	}
	apdu := []byte{0x80, 0xD6, p1, 0x00}

	if len(divInput) <= 0 {
		apdu = append(apdu, 0x02)
	} else {
		apdu = append(apdu, 0x02+byte(len(divInput)))
	}

	apdu = append(apdu, byte(keyNo))
	apdu = append(apdu, byte(keyVer))

	if len(divInput) > 0 {
		apdu = append(apdu, divInput...)
	}

	apdu = append(apdu, 0x00)
	return apdu
}

// DumpSessionKey SAM_DumpSessionKey (session key of an established authentication with a DESFire or MIFARE Plus PICC)
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

// DumpSecretKey SAM_DumpSecretKey (allows dumping any of PICC keys or OfflineCrypto keys)
func (sam *samAv2) DumpSecretKey(keyNo, keyVer int, divInput []byte) ([]byte, error) {
	response, err := sam.Apdu(ApduDumpSecretKey(keyNo, keyVer, divInput))
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return nil, err
	}
	return response, nil
}

// ApduSamKillAuthPICC SAM_KillAuthentication invalidates any kind authentication PICC
func ApduSamKillAuthPICC() []byte {
	return []byte{0x80, 0xCA, 0x01, 0x00}
}
