package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/nmelo/smartcard/nxp/mifare/samav2"
	"github.com/nmelo/smartcard/pcsc"
)

func main() {

	/**/
	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatalln(err)
	}
	rs, err := ctx.ListReaders()
	if err != nil {
		log.Fatalln(err)
	}

	funcExtractReader := func() []byte {

		for _, v := range rs {
			fmt.Printf("reader: %q\n", v)
			if bytes.Contains([]byte(v), []byte("SAM")) {
				return []byte(v)
			}
		}
		return nil
	}

	rext := funcExtractReader()
	if rext == nil {
		log.Fatalln("reader not found")
	}

	reader := pcsc.NewReader(ctx, string(rext))
	/**/

	/**
	dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "multiiso", 1)


	/**/

	// direct, err := reader.ConnectDirect()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// resp1, err := direct.ControlApdu(0x42000000+2079,
	// 	[]byte{0xE0, 0x00, 0x13, 0x11, 0x04, 0xFF, 0x11, 0x86, 0x68})
	// if err != nil {
	// 	log.Fatal(err)
	// } else {
	// 	log.Printf("pps: [% X]", resp1)
	// }
	// direct.DisconnectCard()

	cardi, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	samAv2 := samav2.SamAV2(cardi)

	samAtr, err := samAv2.ATR()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("ATR: [ %X ]\n", samAtr)
	log.Printf("ascii ATR: %q\n", samAtr)

	samUID, err := samAv2.UID()
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("sam UID: [% X]", samUID)

	version, err := samAv2.GetVersion()
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("sam Version: [% X], ASCII: %s", version, version)

	// keyAuth := make([]byte, 16)
	// block, err := aes.NewCipher(keyAuth)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// res1, err := samAv2.AuthHostAV1(block, 0, 0, 0)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("Auth hosts response: [% X]", res1)

	/**
	keyMaster := make([]byte, 16)
	// keyMaster := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	// res1, err = samAv2.ChangeKeyEntryAv1(0, 0xFF, keyMaster,
	// 	keyMaster, keyMaster, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x01, 0x02,
	// 	[]byte{0, 0, 0}, []byte{0x20, 0x00})
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("changeKeyAv1 response: [% X]", res1)

	var res1 []byte
	// res1, err = samAv2.LockUnlock(keyMaster, make([]byte, 3), 0, 0, 0, 0, 0x03)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("Active response: [% X]", res1)


	res1, err = samAv2.AuthHostAV2(keyMaster, 0, 0, 0)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Auth hosts response: [% X]", res1)

	key1 := 102
	for i := range keyMaster {
		keyMaster[i] = 0x00
	}

	keys := []byte{0x5F, 0x14, 0xBA, 0x8B, 0x87, 0xF5, 0x05, 0x67, 0xD2, 0xEE, 0x05, 0xDF, 0x80, 0x2B, 0xA7, 0x7D, 0xBA, 0xC6, 0x57, 0x92, 0xFD, 0xAF, 0xEA, 0x8B, 0xC4, 0xDF, 0xFA, 0x01, 0x81, 0xCC, 0x2E, 0xE0, 0x98, 0x21, 0x87, 0x32, 0x56, 0xDB, 0xF1, 0x29, 0x40, 0x9D, 0xA1, 0x97, 0xEC, 0x39, 0x4F, 0xF6}

	res1, err = samAv2.ChangeKeyEntry(key1, 0xFF, keys[0:16], keys[16:32], keys[32:48],
		0x00, 0x00, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x0C,
		[]byte{0, 0, 0}, []byte{0x24, 0x00})
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("change key [ %v ] response: [% X]", key1, res1)

	// key2 := 102

	// for i := range keyMaster {
	// 	keyMaster[i] = 0xFF
	// }
	// res1, err = samAv2.ChangeKeyEntry(key2, 0x00, keyMaster, keyMaster, keyMaster,
	// 	0x00, 0x00, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x0C,
	// 	[]byte{0, 0, 0}, []byte{0x24, 0x00})
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// log.Printf("change key [ %v ] response: [% X]", key2, res1)

	res1, err = samAv2.ActivateOfflineKey(key1, 0x00, nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("ActivateOfflineKey response: [% X]", res1)

	// key3 := 0x03
	// res1, err = samAv2.ChangeKeyEntryOffline(key3, 0xFF, 00, keyMaster, keyMaster, keyMaster,
	// 	0x00, 0x01, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x01,
	// 	[]byte{0, 0, 0}, []byte{0x20, 0x00},
	// 	keyMaster, samUID)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// log.Printf("ChangeOffline hosts response: [% X]", res1)
	/**/
}
