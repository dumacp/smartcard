package smartcard

//ISO7816cmd command ISO7816
type ISO7816cmd struct {
	CLA byte
	INS byte
	P1  byte
	P2  byte
	Le  bool
}
