package main

import (
	"encoding/hex"
	"log"
	"strings"

	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/pcsc"
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

	cardi, err := reader.ConnectCard()
	if err != nil {
		log.Fatal(err)
	}

	cardm := mifare.Mplus(cardi)

	keyb, err := hex.DecodeString("00000000000000000000000000000000")
	if err != nil {
		log.Fatal(err)
	}

	res, err := cardm.FirstAuth(0x4004, keyb)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("res: [% X]", res)

	res, err = cardm.ReadEncMacMac(20, 1)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("res: [% X]", res)

	if err := cardm.IncTransfEncMacMac(20, []byte{1, 0, 0, 0}); err != nil {
		log.Fatal(err)
	}

	res, err = cardm.ReadEncMacMac(20, 1)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("res: [% X]", res)

}
