package samav2

import (
	"fmt"

	"github.com/dumacp/smartcard/nxp/mifare"
)

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

//SAMEncipherData SAM_Encipher_Data
func (sam *samAv2) SAMEncipherData(alg CrytoAlgorithm, data []byte) ([]byte, error) {

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	switch {
	case alg == DES_ALG && len(data)%8 != 0:
		return nil, fmt.Errorf("data len is invalid, len = %d", len(data))
	case alg == AES_ALG && len(data)%8 != 0:
		return nil, fmt.Errorf("data len is invalid, len = %d", len(data))
	case alg != AES_ALG && alg != DES_ALG:
		return nil, fmt.Errorf("ALGORITM is not valid")
	}

	divisor := 1
	switch alg {
	case AES_ALG:
		divisor = 0xF0
	default:
		divisor = 0xF8
	}

	fragments := make([][]byte, 0)

	for len(dataCopy) > divisor {
		fragments = append(fragments, dataCopy[:divisor])
		dataCopy = dataCopy[divisor:]
	}
	fragments = append(fragments, dataCopy[:])

	result := make([]byte, 0)

	for i, v := range fragments {
		lastBlock := true
		if len(fragments)-1 != i {
			lastBlock = false
		}
		response := ApduEncipher_Data(lastBlock, 0x00, v)
		if err := mifare.VerifyResponseIso7816(response); err != nil {
			return nil, err
		}
		result = append(result, response[:len(response)-2]...)
	}

	return result, nil
}

//SAMEncipherOfflineData SAM_EncipherOffline_Data
func (sam *samAv2) SAMEncipherOfflineData(alg CrytoAlgorithm, data []byte) ([]byte, error) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	switch {
	case alg == DES_ALG && len(data)%8 != 0:
		return nil, fmt.Errorf("data len is invalid, len = %d", len(data))
	case alg == AES_ALG && len(data)%16 != 0:
		return nil, fmt.Errorf("data len is invalid, len = %d", len(data))
	case alg != DES_ALG && alg != AES_ALG:
		return nil, fmt.Errorf("ALGORITM is not valid")
	}

	divisor := 1
	switch alg {
	case AES_ALG:
		divisor = 0xF0
	default:
		divisor = 0xF8
	}

	fragments := make([][]byte, 0)

	for len(dataCopy) > divisor {
		fragments = append(fragments, dataCopy[:divisor])
		dataCopy = dataCopy[divisor:]
	}
	fragments = append(fragments, dataCopy[:])

	result := make([]byte, 0)

	for i, v := range fragments {
		lastBlock := true
		if len(fragments)-1 != i {
			lastBlock = false
		}
		response := ApduEncipherOffline_Data(lastBlock, v)
		if err := mifare.VerifyResponseIso7816(response); err != nil {
			return nil, err
		}
		result = append(result, response[:len(response)-2]...)
	}

	return result, nil
}

//SAMDecipherData SAM_Decipher_Data
func (sam *samAv2) SAMDecipherData(alg CrytoAlgorithm, data []byte) ([]byte, error) {

	return nil, fmt.Errorf("not support")
}

//SAMDecipherOfflineData SAM_DecipherOffline_Data
func (sam *samAv2) SAMDecipherOfflineData(alg CrytoAlgorithm, data []byte) ([]byte, error) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	switch {
	case alg == DES_ALG && len(data)%8 != 0:
		return nil, fmt.Errorf("data len is invalid, len = %d", len(data))
	case alg == AES_ALG && len(data)%16 != 0:
		return nil, fmt.Errorf("data len is invalid, len = %d", len(data))
	case alg != DES_ALG && alg != AES_ALG:
		return nil, fmt.Errorf("ALGORITM is not valid")
	}

	divisor := 1
	switch alg {
	case AES_ALG:
		divisor = 0xF0
	default:
		divisor = 0xF8
	}

	fragments := make([][]byte, 0)

	for len(dataCopy) > divisor {
		fragments = append(fragments, dataCopy[:divisor])
		dataCopy = dataCopy[divisor:]
	}
	fragments = append(fragments, dataCopy[:])

	result := make([]byte, 0)

	for i, v := range fragments {
		lastBlock := true
		if len(fragments)-1 != i {
			lastBlock = false
		}
		response := ApduDecipherOffline_Data(lastBlock, v)
		if err := mifare.VerifyResponseIso7816(response); err != nil {
			return nil, err
		}
		result = append(result, response[:len(response)-2]...)
	}

	return result, nil
}
