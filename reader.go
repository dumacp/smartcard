/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	https://github.com/ebfe/scard

/**/
package smartcard

//IReader Interface to Reader device
type IReader interface {
	ConnectCard() (ICard, error)
	ConnectSamCard() (ICard, error)
}
