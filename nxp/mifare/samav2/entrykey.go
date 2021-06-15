package samav2

type EntryKey struct {
	Va       byte
	Vb       byte
	Vc       byte
	DfAID    []byte
	DfKeyNo  byte
	KeyNoCEK byte
	KeyVCEK  byte
	RefNoKUC byte
	Set      []byte
	ExtSet   byte
}

func NewEntryKey(data []byte) *EntryKey {
	ek := &EntryKey{}
	ek.Va = data[0]
	ek.Vb = data[1]
	ek.Vc = data[2]
	ek.DfAID = data[3:6]
	ek.DfKeyNo = data[6]
	ek.KeyNoCEK = data[7]
	ek.KeyVCEK = data[8]
	ek.RefNoKUC = data[9]
	ek.Set = data[10:12]
	ek.ExtSet = data[12]
	return ek
}

func (ek *EntryKey) Bytes() []byte {
	apdu := make([]byte, 0)
	apdu = append(apdu, ek.Va)
	apdu = append(apdu, ek.Vb)
	apdu = append(apdu, ek.Vc)
	apdu = append(apdu, ek.DfAID...)
	apdu = append(apdu, ek.DfKeyNo)
	apdu = append(apdu, ek.KeyNoCEK)
	apdu = append(apdu, ek.KeyVCEK)
	apdu = append(apdu, ek.RefNoKUC)
	apdu = append(apdu, ek.Set...)
	apdu = append(apdu, ek.ExtSet)

	return apdu
}
