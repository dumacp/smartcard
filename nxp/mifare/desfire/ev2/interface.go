package ev2

type IDesfire interface {
	AuthenticateEV2First(targetKey SecondAppIndicator, keyNumber int, pcdCap2 []byte) ([]byte, error)
	AuthenticateEV2FirstPart2(key, response []byte) ([]byte, error)
	AuthenticateEV2NonFirst() ([]byte, error)
	AuthenticateEV2NonFirstPart2() ([]byte, error)
	GetApplicationsID() ([]byte, error)
	SelectApplication(aid1, aid2 []byte) error
	AuthenticateISO(targetKey SecondAppIndicator, keyNumber int) ([]byte, error)
	AuthenticateISOPart2(key, response []byte) ([]byte, error)
	// ChangeKey depensing on the currently selectd AID, this command
	// update a key of the PICC or of an application AKS.
	ChangeKey(keyNo, keyVersion int,
		keyType KeyType, secondAppIndicator SecondAppIndicator,
		newKey, oldKey []byte) error
	ChangeKeyEV2(keyNo, keySetNo, keyVersion int,
		keyType KeyType, secondAppIndicator SecondAppIndicator,
		newKey, oldKey []byte) error
	GetCardUID() ([]byte, error)
}
