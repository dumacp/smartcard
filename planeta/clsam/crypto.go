package clsam

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
)

func keypinsam() []byte {
	key, _ := hex.DecodeString("56970ab5418eacc10d03547454090524")
	return key
}
func calcpin(data, key []byte) ([]byte, error) {

	keyx := make([]byte, 0)
	keyx = append(keyx, key...)

	if len(keyx) < 24 {
		keyx = append(keyx, key[:8]...)
	}

	// fmt.Printf("keyx: [% X]\n", keyx)

	block, err := des.NewTripleDESCipher(keyx)
	if err != nil {
		return nil, fmt.Errorf("key len: %d, %w", len(key[:8]), err)
	}

	// fmt.Printf("block size: %d, data size: %d\n", block.BlockSize(), len(data))

	cb := cipher.NewCBCEncrypter(block, make([]byte, block.BlockSize()))

	dst := make([]byte, len(data))

	// if mod := len(dst) % 8; mod != 0 {
	// 	dst = append(dst, make([]byte, 16-mod)...)
	// }

	cb.CryptBlocks(dst, data)

	return dst, nil
}
