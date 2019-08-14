/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	github.com/ebfe/scard

/**/
package smartcard

//Interface to Reader device
type IReader interface {
	ConnectCard()	(Card, error)
}

