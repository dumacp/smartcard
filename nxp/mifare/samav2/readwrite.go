package samav2

import (
	"fmt"

	"github.com/nmelo/smartcard"
	"github.com/nmelo/smartcard/nxp/mifare"
)

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
	// log.Printf("apdu: [ % X ], time: %f", apdu, float64(time.Now().UnixNano())/1000000000)
	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {

		return response, err
	}
	// log.Printf("resp: [ % X ], time: %f", response, float64(time.Now().UnixNano())/1000000000)

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
	// log.Printf("debuggg drop, ApduSAMCombinedWriteMFP: [% X]", apdu)
	if apdu == nil {
		return nil, fmt.Errorf("bad frame: [% X]", data)
	}
	response, err := sam.Apdu(apdu)
	if err != nil {
		return nil, err
	}
	if err := mifare.VerifyResponseIso7816(response); err != nil {
		// log.Printf("apdu: [ % X ] ", apdu)
		return response, err
	}

	return response, nil
}
