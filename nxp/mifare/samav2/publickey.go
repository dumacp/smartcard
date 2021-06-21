package samav2

import (
	"encoding/binary"
	"errors"
	"math/big"
)

type PKIPubKey struct {
	PKISet      []byte
	PKIKeyNoCEK int
	PKIKeyVCEK  int
	PKIRefNoKUC int
	PKINLen     int
	PKIeLen     int
	PKIN        *big.Int
	PKIe        *big.Int
}

func ParseResponseToPKIPubKey(data []byte) (*PKIPubKey, error) {

	prefixDataLen := 2 + 1 + 1 + 1 + 2 + 2
	if len(data) < prefixDataLen {
		return nil, errors.New("lendata ins invalid")
	}

	pkiNLen := binary.LittleEndian.Uint16(data[5:7])
	pkieLen := binary.LittleEndian.Uint16(data[7:9])

	if len(data) < prefixDataLen+int(pkiNLen)+int(pkieLen) {
		return nil, errors.New("lendata ins invalid")
	}

	setBytes := make([]byte, 2)
	setBytes = append(setBytes, data[0:2]...)
	pkiKeyNoCEK := int(data[2])
	pkiKeyVCEK := int(data[3])
	pkiRefNoKUC := int(data[4])

	pkiN := new(big.Int)
	pkie := new(big.Int)

	pkiNbytes := reverseBytes(data[9 : 9+pkiNLen])
	pkkiebytes := reverseBytes(data[9+pkiNLen : 9+pkiNLen+pkieLen])

	pkiN.SetBytes(pkiNbytes)
	pkie.SetBytes(pkkiebytes)

	pubKey := new(PKIPubKey)

	pubKey.PKISet = setBytes
	pubKey.PKIKeyNoCEK = pkiKeyNoCEK
	pubKey.PKIKeyVCEK = pkiKeyVCEK
	pubKey.PKIRefNoKUC = pkiRefNoKUC
	pubKey.PKINLen = int(pkiNLen)
	pubKey.PKIeLen = int(pkieLen)
	pubKey.PKIN = pkiN
	pubKey.PKIe = pkie

	return pubKey, nil
}

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
