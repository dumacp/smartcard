package mifare

import (
	"fmt"
)

type INS byte
const (
	SamAuthMFP INS = 0xA3
	SamAuthHAv2 INS = 0xA4
	SamDumpSessKey INS = 0xD5
	SamGetVers INS = 0x60
	MfpFirstAuthf1 INS = 0x70
	MfpFirstAuthf2 INS = 0x72
)

func VerifyResponseIso7816(response []byte) error {
	if response[len(response)-1] != byte(0x00) || response[len(response)-2] != byte(0x90) {
		return fmt.Errorf("error in response [%X %X]; response: [% X]\n", response[len(response)-2], response[len(response)-1], response)
	}
	return nil
}

