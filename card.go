/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

        https://github.com/LudovicRousseau/PCSC
        github.com/ebfe/scard

/**/
package smartcard

//ICard Interface
type ICard interface {
	Apdu(apdu []byte) ([]byte, error)
	ATR() ([]byte, error)
	UID() ([]byte, error)
	ATS() ([]byte, error)
	DisconnectCard() error
}

type Error struct {
	Data string
}

func (e *Error) Error() string {
	return e.Data
}
