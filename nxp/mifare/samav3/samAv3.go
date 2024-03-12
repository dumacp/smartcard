package samav3

import (
	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare/samav2"
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
}

type samAv3 struct {
	samav2.SamAv2
}

// SamAV3 Create SAM from Card
func SamAV3(c smartcard.ICard) SamAv3 {
	samv2 := samav2.SamAV2(c)
	sam := new(samAv3)
	sam.SamAv2 = samv2
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

	sam3 := &samAv3{
		sam2,
	}

	return sam3, nil
}

// AuthHost SAM_AuthenticationHost
func (sam *samAv3) AuthHost(key []byte, keyNo, keyVer, hostMode int) ([]byte, error) {
	return sam.SamAv2.AuthHostAV2(key, keyNo, keyVer, hostMode)
}
