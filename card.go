/*
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	    https://github.com/LudovicRousseau/PCSC
		https://github.com/ebfe/scard
*/
package smartcard

import (
	"errors"
)

// ICard Interface
type ICard interface {
	Apdu(apdu []byte) ([]byte, error)
	ATR() ([]byte, error)
	GetData(byte) ([]byte, error)
	UID() ([]byte, error)
	ATS() ([]byte, error)
	SAK() byte
	DisconnectCard() error
	DisconnectResetCard() error
	EndTransactionResetCard() error
}

var ErrComm = Error(errors.New("error communication"))
var ErrNoSmartcard = Error(errors.New("error no smartcard"))
var ErrTransmit = Error(errors.New("error transmit"))
var ErrSharingViolation = Error(errors.New("error sharing violation"))

type SmartcardError struct {
	Err error
}

func Error(e error) error {
	return &SmartcardError{Err: e}
}

func (e *SmartcardError) Error() string {
	return e.Err.Error()
}
