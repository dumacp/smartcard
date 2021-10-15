package main

import (
	"log"
	"strings"

	"github.com/dumacp/smartcard/nxp/mifare/desfire/ev2"
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

	cardi, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	d := ev2.NewDesfire(cardi)

	_, err = d.SelectApplication(make([]byte, 3), nil)
	if err != nil {
		log.Fatalln(err)
	}

	auth1, err := d.AuthenticateEV2First(0, 0, nil)
	if err != nil {
		log.Fatalln(err)
	}
	auth2, err := d.AuthenticateEV2FirstPart2(make([]byte, 16), auth1)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("**** auth sucess: [% X]", auth2)

	// changekey, err := d.ChangeKey(0x00, 0x00, ev2.TDEA2, 0x00, make([]byte, 16), nil)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// log.Printf("**** changekey sucess: [% X]", changekey)

}
