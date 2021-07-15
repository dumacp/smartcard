/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package smartcard

import (
	"errors"
)

//ICard Interface
type ICard interface {
	Apdu(apdu []byte) ([]byte, error)
	ATR() ([]byte, error)
	UID() ([]byte, error)
	ATS() ([]byte, error)
	DisconnectCard() error
}

var ErrComm = Error(errors.New("error communication"))

type SmartcardError struct {
	Err error
}

func Error(e error) error {
	return &SmartcardError{Err: e}
}

func (e *SmartcardError) Error() string {
	return e.Err.Error()
}

func (e *SmartcardError) Unwrap() error {
	return e.Err
}
