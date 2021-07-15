package samav2

import (
	"encoding/binary"
	"fmt"
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
	PKIe        int
}

func ParseResponseToPKIPubKey(data []byte) (*PKIPubKey, error) {

	prefixDataLen := 2 + 1 + 1 + 1 + 2 + 2
	if len(data) < prefixDataLen {
		return nil, fmt.Errorf("len data is invalid, len: %d", len(data))
	}

	pkiNLen := binary.BigEndian.Uint16(data[5:7])
	pkieLen := binary.BigEndian.Uint16(data[7:9])

	if len(data) < prefixDataLen+int(pkiNLen)+int(pkieLen) {
		return nil, fmt.Errorf("lendata is invalid, len: %d", len(data))
	}

	setBytes := make([]byte, 2)
	setBytes = append(setBytes, data[0:2]...)
	pkiKeyNoCEK := int(data[2])
	pkiKeyVCEK := int(data[3])
	pkiRefNoKUC := int(data[4])

	pkiN := new(big.Int)
	pkie := new(big.Int)

	pkiNbytes := data[9 : 9+pkiNLen]
	pkkiebytes := data[9+pkiNLen : 9+pkiNLen+pkieLen]

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
	pubKey.PKIe = int(pkie.Uint64())

	return pubKey, nil
}

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
