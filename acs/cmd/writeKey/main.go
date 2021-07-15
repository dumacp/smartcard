package main

import (
	"log"
	"strings"

	"github.com/dumacp/go-appliance-contactless/business/card/mifareplus"
	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/nxp/mifare/samav3"
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

	var readerSAM pcsc.Reader
	for i, r := range readers {
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "SAM") {
			readerSAM = pcsc.NewReader(ctx, r)
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

	// cardo, err := mifare.ConnectMplus(reader)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// sam, err := samav3.ConnectSam(readerSAM)

	// dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// reader := multiiso.NewReader(dev, "multiiso", 1)

	//cardi, err := reader.ConnectSamCard()
	cardi, err := readerSAM.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	sam := samav3.SamAV3(cardi)

	// keyMaster := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	keyMaster := make([]byte, 16)
	if resp, err := sam.AuthHost(keyMaster, 0, 0, 0); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("Auth SAM resp: [% X]", resp)
	}

	cardp, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	cardo := mifare.Mplus(cardp)
	cardm := mifareplus.NewCard(cardo, sam)

	atr, err := cardm.ATR()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ATR: [% X], %s", atr, atr)

	if err := cardm.Auth(0x9000, 10); err != nil {
		log.Fatal(err)
	}

	log.Println("success Auth!!!")

	key := make([]byte, 16)
	for i := range key {
		key[i] = 0xFF
	}
	if err := cardm.WriteBlock(0x9000, key); err != nil {
		log.Fatal(err)
	}
	log.Println("write Key!!!")

}
