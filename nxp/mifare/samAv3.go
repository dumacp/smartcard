package mifare

import (
	"github.com/dumacp/smartcard"
)

//SamAv3 Interface
type SamAv3 interface {
	smartcard.ICard
	GetVersion() ([]byte, error)
	/*AuthHost SAM_AuthenticationHost AV2 mode
	key, key to Authentication
	keyNo, key entry number in SAM key storage
	keyVr, key version used
	hostMode, hostMode (0: plain, 1: Mac, 2: Full)*/
	AuthHost(key []byte, keyNo, keyVr, hostMode int) ([]byte, error)
	NonXauthMFPf1(first bool, sl, keyNo, keyVer int, data, dataDiv []byte) ([]byte, error)
	NonXauthMFPf2(data []byte) ([]byte, error)
	DumpSessionKey() ([]byte, error)
	LockUnlock(key, maxchainBlocks []byte, keyNr, keyVr, unlockKeyNo, unlockKeyVer, p1 int) ([]byte, error)
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
}

type samAv3 struct {
	*samAv2
}

//ConnectSamAv3 Create SamAv2 interface
func ConnectSamAv3(r smartcard.IReader) (SamAv3, error) {

	c, err := r.ConnectCard()
	if err != nil {
		return nil, err
	}
	sam2 := &samAv2{
		ICard: c,
	}

	sam3 := &samAv3{
		samAv2: sam2,
	}

	return sam3, nil
}

//AuthHost SAM_AuthenticationHost
func (sam *samAv3) AuthHost(key []byte, keyNo, keyVer, hostMode int) ([]byte, error) {
	return sam.samAv2.AuthHostAV2(key, keyNo, keyVer, hostMode)
}
