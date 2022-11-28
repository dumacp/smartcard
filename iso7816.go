package smartcard

// ISO7816cmd command ISO7816
type ISO7816cmd struct {
	CLA byte
	INS byte
	P1  byte
	P2  byte
	Le  bool
}

func (cmd *ISO7816cmd) PrefixApdu() []byte {
	apdu := make([]byte, 0)
	apdu = append(apdu, cmd.CLA)
	apdu = append(apdu, cmd.INS)
	apdu = append(apdu, cmd.P1)
	apdu = append(apdu, cmd.P2)
	return apdu
}
