package samav2

type EntryKey struct {
	KeyVA []byte
	KeyVB []byte
	KeyVC []byte

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

type EntryKeyData struct {
	Va       byte
	Vb       byte
	Vc       byte
	DfAID    []byte
	DfKeyNo  byte
	KeyNoCEK byte
	KeyVCEK  byte
	RefNoKUC byte
	Set      []byte
}

func NewEntryKeyData(data []byte, alg KeyType) *EntryKeyData {
	ek := &EntryKeyData{}
	switch alg {
	case AES_128:
		ek.Va = data[0]
		ek.Vb = data[1]
		ek.Vc = data[2]
	default:
		ek.Va = data[0]
		ek.Vb = data[1]
	}
	ek.DfAID = data[3:6]
	ek.DfKeyNo = data[6]
	ek.KeyNoCEK = data[7]
	ek.KeyVCEK = data[8]
	ek.RefNoKUC = data[9]
	ek.Set = data[10:12]

	return ek
}

func NewEntryKey(data []byte, alg KeyType) *EntryKey {
	ek := &EntryKey{}
	switch alg {
	case AES_128:
		ek.KeyVA = data[0:16]
		ek.KeyVB = data[16:32]
		ek.KeyVC = data[32:48]
		ek.Va = data[57]
		ek.Vb = data[58]
		ek.Vc = data[59]
		ek.ExtSet = data[60]
	default:
		ek.KeyVA = data[0:24]
		ek.KeyVB = data[24:48]
		ek.Va = data[57]
		ek.Vb = data[58]
	}
	ek.DfAID = data[48:51]
	ek.DfKeyNo = data[51]
	ek.KeyNoCEK = data[52]
	ek.KeyVCEK = data[53]
	ek.RefNoKUC = data[54]
	ek.Set = data[55:57]
	ek.ExtSet = data[60]

	return ek
}

func (ek *EntryKey) Bytes() []byte {
	apdu := make([]byte, 0)
	apdu = append(apdu, ek.KeyVA...)
	apdu = append(apdu, ek.KeyVB...)
	apdu = append(apdu, ek.KeyVC...)
	apdu = append(apdu, ek.DfAID...)
	apdu = append(apdu, ek.DfKeyNo)
	apdu = append(apdu, ek.KeyNoCEK)
	apdu = append(apdu, ek.KeyVCEK)
	apdu = append(apdu, ek.RefNoKUC)
	apdu = append(apdu, ek.Set...)
	apdu = append(apdu, ek.Va)
	apdu = append(apdu, ek.Vb)
	apdu = append(apdu, ek.Vc)
	apdu = append(apdu, ek.ExtSet)
	return apdu
}

type ProMasEntryKey byte

func (p ProMasEntryKey) UpdateKeyVa() ProMasEntryKey {
	return p | 0x80
}
func (p ProMasEntryKey) UpdateKeyVb() ProMasEntryKey {
	return p | 0x40
}
func (p ProMasEntryKey) UpdateKeyVc() ProMasEntryKey {
	return p | 0x20
}
func (p ProMasEntryKey) UpdateDFAidDFKey() ProMasEntryKey {
	return p | 0x10
}
func (p ProMasEntryKey) UpdateKeyNoCEJKeyVCEK() ProMasEntryKey {
	return p | 0x08
}
func (p ProMasEntryKey) UpdateRefKUC() ProMasEntryKey {
	return p | 0x04
}
func (p ProMasEntryKey) UpdateSET() ProMasEntryKey {
	return p | 0x02
}
func (p ProMasEntryKey) UpdateKeyVerSentSep() ProMasEntryKey {
	return p | 0x01
}
func (p ProMasEntryKey) UpdateAll() ProMasEntryKey {
	return p | 0xFF
}
