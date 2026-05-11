package samav3

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/nxp/mifare/samav2"
	"github.com/dumacp/smartcard/nxp/mifare/tools"
)

// SamAv3 Interface
type SamAv3 interface {
	samav2.SamAv2
	// smartcard.ICard
	// GetVersion() ([]byte, error)
	// /*AuthHost SAM_AuthenticationHost AV2 mode
	// key, key to Authentication
	// keyNo, key entry number in SAM key storage
	// keyVr, key version used
	// hostMode, hostMode (0: plain, 1: Mac, 2: Full)*/
	AuthHost(key []byte, keyNo, keyVr, hostMode int) ([]byte, error)
	// NonXauthMFPf1(first bool, sl, keyNo, keyVer int, data, dataDiv []byte) ([]byte, error)
	// NonXauthMFPf2(data []byte) ([]byte, error)
	// DumpSessionKey() ([]byte, error)
	// LockUnlock(key, maxchainBlocks []byte, keyNr, keyVr, unlockKeyNo, unlockKeyVer, p1 int) ([]byte, error)
	// ChangeKeyEntry(keyNbr, proMax int,
	// 	keyVA, keyVB, keyVC []byte,
	// 	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	// 	dfAid, set []byte,
	// ) ([]byte, error)
	// ChangeKeyEntryOffline(keyNbr, proMax, changeCtr int,
	// 	keyVA, keyVB, keyVC []byte,
	// 	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet byte,
	// 	dfAid, set []byte,
	// 	kc, samUID []byte,
	// ) ([]byte, error)
	// ActivateOfflineKey(keyNo, keyVer int,
	// 	divInput []byte,
	// ) ([]byte, error)
	ChangeKeyEntryAv3(keyNbr, proMax int,
		keyVA, keyVB, keyVC []byte,
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet, kNoAEK, kVerAEK byte,
		dfAid, set []byte,
	) ([]byte, error)
}

type CsamAv3 struct {
	*samav2.CsamAv2
}

// SamAV3 Create SAM from Card
func SamAV3(c smartcard.ICard) *CsamAv3 {
	samv2 := samav2.SamAV2(c)
	sam := new(CsamAv3)
	sam.CsamAv2 = samv2
	return sam
}

// ConnectSam Create SamAv2 interface
func ConnectSam(r smartcard.IReader) (SamAv3, error) {

	// c, err := r.ConnectCard()
	// if err != nil {
	// 	return nil, err
	// }
	sam2, err := samav2.ConnectSam(r)
	if err != nil {
		return nil, err
	}

	sam3 := &CsamAv3{
		sam2,
	}

	return sam3, nil
}

// AuthHost SAM_AuthenticationHost
func (sam *CsamAv3) AuthHost(key []byte, keyNo, keyVer, hostMode int) ([]byte, error) {
	return sam.CsamAv2.AuthHostAV2(key, keyNo, keyVer, hostMode)
}

// ChangeKeyEntry SAM_ApduChangeKeyEntry command
func (sam *CsamAv3) ChangeKeyEntryAv3(keyNbr, proMax int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet, kNoAEK, kVerAEK byte,
	dfAid, set []byte,
) ([]byte, error) {

	apdu, err := apduChangeKeyEntry(sam.HostMode, keyNbr, proMax, sam.CmdCtr, keyVA, keyVB, keyVC,
		dfKeyNr, ceKNo, ceKV, kuc,
		verA, verB, verC, extSet, kNoAEK, kVerAEK,
		dfAid, set,
		sam.Ke, sam.Km)
	if err != nil {
		return nil, err
	}
	sam.CmdCtr++
	// log.Printf("apud: [ %X ]", apdu)

	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		return response, err
	}
	return response, nil
}

// apduChangeKeyEntry create APDU to SAM_ApduChangeKeyEntry
func apduChangeKeyEntry(hostMode, keyNbr, proMax, cmdCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet, kNoAEK, kVerAEK byte,
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
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet, kNoAEK, kVerAEK,
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

func newEntryKey(keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet, kNoAEK, kVerAEK byte,
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
	payload = append(payload, 0x00) // TODO: replace extSet to support AV3
	payload = append(payload, kNoAEK)
	payload = append(payload, kVerAEK)
	return payload
}

// ApduChangeKeyEntryOffline create APDU to SAM_ApduChangeKeyEntry
func ApduChangeKeyEntryOffline(keyNbr, proMax, changeCtr int,
	keyVA, keyVB, keyVC []byte,
	dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet, kNoAEK, kVerAEK byte,
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
		dfKeyNr, ceKNo, ceKV, kuc, verA, verB, verC, extSet, kNoAEK, kVerAEK,
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
