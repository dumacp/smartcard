/*
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	https://github.com/ebfe/scard
*/
package smartcard

// IReader Interface to Reader device
type IReader interface {
	//ConnectCard connect card with protocol T=1
	ConnectCard() (ICard, error)
	//ConnectCard connect card with protocol T=1.
	//Some readers distinguish between the flow to connect a contact-based smart card and a contactless smart card.
	ConnectSamCard() (ICard, error)
	//ConnectSamCard_T0 ConnectCard connect card with protocol T=1.
	ConnectSamCard_T0() (ICard, error)
	//ConnectSamCard_Tany ConnectCard connect card with protocol T=any.
	ConnectSamCard_Tany() (ICard, error)
}
