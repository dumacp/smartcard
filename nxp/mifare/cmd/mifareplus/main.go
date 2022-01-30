package main

import (
	"encoding/hex"
	"log"
	"strings"

	"github.com/nmelo/smartcard/nxp/mifare"
	"github.com/nmelo/smartcard/pcsc"
)

func main() {
	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal(err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatal(err)
	}

	var reader pcsc.Reader
	for i, r := range readers {
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "PICC") {
			reader = pcsc.NewReader(ctx, r)
		}
	}

	direct, err := reader.ConnectDirect()
	if err != nil {
		log.Fatal(err)
	}
	resp1, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp1: [% X]", resp1)
	}
	resp2, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x01, 0x8F})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp2: [% X]", resp2)
	}

	direct.DisconnectCard()

	cardi, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatal(err)
	}

	// cardi.TransparentSessionStart()
	// cardi.Switch1444_4()
	// cardi.TransparentSessionEnd()

	cardm := mifare.Mplus(cardi)

	ats, err := cardm.ATS()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("ats: [% X]", ats)
	uid, err := cardm.UID()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("uid: [% X]", uid)
	atr, err := cardm.ATR()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("atr: [% X]", atr)

	/**/
	// keyA, err := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	// keyA, err := hex.DecodeString("11B03568513C473EB1250E4E581D2E81")
	keyA, err := hex.DecodeString("24534D288BB938F0054E4A3A23420152")
	if err != nil {
		log.Fatal(err)
	}

	res, err := cardm.FirstAuth(0x4004, keyA)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("res: [% X]", res)

	res, err = cardm.ReadEncMacMac(20, 1)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("res: [% X]", res)

	block14 := []byte{0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00}
	// block16 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// block17 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	if err := cardm.WriteEncMacMac(20, block14); err != nil {
		log.Fatal(err)
	}
	if err := cardm.WriteEncMacMac(21, block14); err != nil {
		log.Fatal(err)
	}
	if err := cardm.WriteEncMacMac(22, block14); err != nil {
		log.Fatal(err)
	}
	// if err := cardm.IncTransfEncMacMac(20, []byte{1, 0, 0, 0}); err != nil {
	// 	log.Fatal(err)
	// }

	res, err = cardm.ReadEncMacMac(20, 1)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("res: [% X]", res)
	/**/

}
