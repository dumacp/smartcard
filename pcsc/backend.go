package pcsc

type shareMode int

const (
	shareExclusive shareMode = iota + 1
	shareShared
	shareDirect
)

type protocolType int

const (
	protocolT0 protocolType = iota + 1
	protocolT1
	protocolAny
	protocolUndefined
)

type dispositionType int

const (
	dispositionLeaveCard dispositionType = iota + 1
	dispositionResetCard
	dispositionUnpowerCard
	dispositionEjectCard
)

type cardStatus struct {
	Atr []byte
}

type backendCard interface {
	Disconnect(disposition dispositionType) error
	Transmit(apdu []byte) ([]byte, error)
	Control(ioctl uint32, apdu []byte) ([]byte, error)
	EndTransaction(disposition dispositionType) error
	Status() (*cardStatus, error)
}

type backendContext interface {
	IsValid() (bool, error)
	ListReaders() ([]string, error)
	Connect(readerName string, share shareMode, protocol protocolType) (backendCard, error)
	Release() error
}
