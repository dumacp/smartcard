package main

import (
	"log"
	"strings"

	"github.com/dumacp/smartcard/nxp/mifare/desfire/ev2"
	"github.com/dumacp/smartcard/pcsc"
)

func main() {

	//// Detectar lectora y tarjeta //////
	//////////////////////////////////////
	/**/
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
			log.Printf("reader PICC detected %q", r)
			break
		}
	}

	if reader == nil {
		log.Fatalln(err)
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

	/**
	/////////////////// MULTI_ISO  ///////

	dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "multiiso", 1)
	readerSam := reader
	/**/

	cardi, err := reader.ConnectCard()
	if err != nil {
		log.Fatalln(err)
	}

	d := ev2.NewDesfire(cardi)

	uid, err := d.UID()
	if err != nil {
		log.Fatalf("GetCardUID() error: %s", err)
	}

	log.Printf("UID(): [% X]", uid)

	uuid, err := d.GetCardUID()
	if err != nil {
		log.Fatalf("GetCardUID() error: %s", err)
	}

	log.Printf("UID(): [% X]", uuid)

}
