package ev2

type Desfire interface {
	AuthenticateEV2First(targetKey int, keyNumber int, pcdCap2 []byte) ([]byte, error)
	AuthenticateEV2FirstPart2(key, response []byte) ([]byte, error)
	AuthenticateEV2NonFirst() ([]byte, error)
	AuthenticateEV2NonFirstPart2() ([]byte, error)
	GetApplicationsID() ([]byte, error)
	SelectApplication(aid1, aid2 []byte) ([]byte, error)
	AuthenticateISO(targetKey int, keyNumber int) ([]byte, error)
	AuthenticateISOPart2(key, response []byte) ([]byte, error)
	// ChangeKey depensing on the currently selectd AID, this command
	// update a key of the PICC or of an application AKS.
	ChangeKey(keyNo, keyVersion int,
		keyType KeyType, secondAppIndicator SecondAppIndicator,
		newKey, oldKey []byte) ([]byte, error)
}
