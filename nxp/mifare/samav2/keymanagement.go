package samav2

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/nxp/mifare/tools"
)

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
		return response, err
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
		return response, err
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
		return response, err
	}

	return response, nil
}

//GetKeyEntry SAM_GetKeyEntry command allows reading the contents of the key entry
func (sam *samAv2) SAMGetKeyEntry(keyNo int) ([]byte, error) {

	response, err := sam.Apdu(sam.ApduSAMGetKeyEntry(keyNo))
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return response, err
	}

	return response, nil

}

//ApduSAMGetKeyEntry ApduSAMGetKeyEntry command allows reading the contents of the key entry
func (sam *samAv2) ApduSAMGetKeyEntry(keyNo int) []byte {
	cmd := smartcard.ISO7816cmd{
		CLA: 0x80,
		INS: 0x64,
		P1:  byte(keyNo),
		P2:  byte(0x00),
		Le:  true,
	}

	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)

	if cmd.Le {
		apdu = append(apdu, 0x00)
	}

	return apdu

}
