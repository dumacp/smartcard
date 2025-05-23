package samav2

import (
	"encoding/binary"
	"reflect"
)

type KeyType int
type KeyClass int

const (
	HOST_KEY          KeyClass = 0
	PICC_KEY          KeyClass = 1
	OfflineChange_KEY KeyClass = 2
	OfflineCrypto_KEY KeyClass = 4
)

func KeyClassByName(v string) KeyClass {
	switch v {
	case "HOST_KEY":
		return HOST_KEY
	case "PICC_KEY":
		return PICC_KEY
	case "OfflineChange_KEY":
		return OfflineChange_KEY
	case "OfflineCrypto_KEY":
		return OfflineCrypto_KEY
	}
	return -1
}

const (
	TDEA_DESFire_4                 KeyType = 0
	TDEA_ISO_10116                 KeyType = 1
	MIFARE                         KeyType = 2
	TripleTDEA_ISO_10116           KeyType = 3
	AES_128                        KeyType = 4
	AES_192                        KeyType = 5
	TDEA_ISO_10116__32CRC_8byteMAC KeyType = 6
)

func push(data uint64, bitwise int, input interface{}) uint64 {

	inputdata := uint64(0)
	switch v := input.(type) {
	case bool:
		if v {
			inputdata = 1
		}
	case int:
		inputdata = uint64(v)
	default:
		inputdata = uint64(reflect.ValueOf(v).Int())
	}

	data = (data << bitwise) | inputdata

	return data
}

func SETConfigurationSettings(allowDumpSessionKey bool,
	keepIV bool, keyType KeyType, requireAuth, authKey bool, disableKeyEntry bool,
	lockKey bool, disableWritingKeyPICC bool, disableDecryption bool,
	disableEncryption bool, disableVerifyMAC bool, disableGenMAC bool) []byte {

	setdata := uint64(0x0000)

	setdata = push(setdata, 1, disableGenMAC)         //15
	setdata = push(setdata, 1, disableVerifyMAC)      //14
	setdata = push(setdata, 1, disableEncryption)     //13
	setdata = push(setdata, 1, disableDecryption)     //12
	setdata = push(setdata, 1, disableWritingKeyPICC) //11
	setdata = push(setdata, 1, lockKey)               //10
	setdata = push(setdata, 1, disableKeyEntry)       //9
	setdata = push(setdata, 1, authKey)               //8
	setdata = push(setdata, 1, requireAuth)           //7 Authhost required Plc
	setdata = push(setdata, 1, 0)                     //6
	// setdata = push(setdata, 2, 0)                     //6 7
	setdata = push(setdata, 3, int(keyType))        //3 4 5
	setdata = push(setdata, 1, keepIV)              //2
	setdata = push(setdata, 1, 0)                   //1
	setdata = push(setdata, 1, allowDumpSessionKey) //0

	result := make([]byte, 2)
	binary.LittleEndian.PutUint16(result, uint16(setdata))

	return result
}

func SETConfigurationSettingsPKI(privKeyInclude bool,
	allowPrivKeyExport bool, disableKeyEntry bool,
	disableEncryptionHandl bool, disableSignatureHandl bool,
	enablePKIUpdateKeyentry bool, privKeyRepresentation int,
) []byte {

	setdata := uint64(0x0000)

	setdata = push(setdata, 9, 0)                       //7 8 9 10 11 12 13 14 15
	setdata = push(setdata, 1, privKeyRepresentation)   //6
	setdata = push(setdata, 1, enablePKIUpdateKeyentry) //5
	setdata = push(setdata, 1, disableSignatureHandl)   //4
	setdata = push(setdata, 1, disableEncryptionHandl)  //3
	setdata = push(setdata, 1, disableKeyEntry)         //2
	setdata = push(setdata, 1, allowPrivKeyExport)      //1
	setdata = push(setdata, 1, privKeyInclude)          //0

	result := make([]byte, 2)
	binary.LittleEndian.PutUint16(result, uint16(setdata))

	return result
}

// ExtSETConfigurationSettings
// keyClass: KeyClass Type, multiple types support (example: OfflineChange_KEY | PICC_KEY)
func ExtSETConfigurationSettings(keyClass KeyClass,
	allowDumpSecretKey bool, restrictToDiversifiedUse bool) byte {

	setdata := uint64(0x0000)

	setdata = push(setdata, 3, 0)                        //5 6 7
	setdata = push(setdata, 1, restrictToDiversifiedUse) //4
	setdata = push(setdata, 1, allowDumpSecretKey)       //3
	setdata = push(setdata, 3, keyClass)                 //0 1 2

	return byte(setdata)
}
