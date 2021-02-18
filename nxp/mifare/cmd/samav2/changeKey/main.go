package main

import (
	"bytes"
	"log"

	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/pcsc"
)

func main() {

	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatalln(err)
	}
	rs, err := ctx.ListReaders()

	funcExtractReader := func() []byte {
		for _, v := range rs {
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

	samAv2, err := mifare.ConnectSamAv2(reader)
	if err != nil {
		log.Fatalln(err)
	}

	samAtr, err := samAv2.ATR()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("ATR: [ %X ]\n", samAtr)

	samUID, err := samAv2.UID()
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("sam UID: [% X]", samUID)

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

	keyMaster := make([]byte, 16)
	// res1, err = samAv2.ChangeKeyEntryAv1(0, 0xFF, keyMaster,
	// 	keyMaster, keyMaster, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x01, 0x02,
	// 	[]byte{0, 0, 0}, []byte{0x20, 0x00})
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("changeKeyAv1 response: [% X]", res1)

	// res1, err = samAv2.SwitchToAV2(keyMaster, 0, 0)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("switch response: [% X]", res1)

	var res1 []byte
	res1, err = samAv2.AuthHostAV2(keyMaster, 0, 0, 2)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Auth hosts response: [% X]", res1)

	key1 := 0x01
	res1, err = samAv2.ChangeKeyEntry(key1, 0xFF, keyMaster, keyMaster, keyMaster,
		0x00, 0x00, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x02,
		[]byte{0, 0, 0}, []byte{0x20, 0x00})
	if err != nil {
		log.Fatalln(err)
	}

	// log.Printf("change key [ %v ] response: [% X]", key1, res1)

	// key2 := 0x02

	// res1, err = samAv2.ChangeKeyEntry(key2, 0xFF, keyMaster, keyMaster, keyMaster,
	// 	0x00, 0x01, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x01,
	// 	[]byte{0, 0, 0}, []byte{0x20, 0x00})
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// log.Printf("change key [ %v ] response: [% X]", key2, res1)

	// res1, err = samAv2.ActivateOfflineKey(0x01, 0x00, nil)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("ActivateOfflineKey response: [% X]", res1)

	// key3 := 0x03
	// res1, err = samAv2.ChangeKeyEntryOffline(key3, 0xFF, 00, keyMaster, keyMaster, keyMaster,
	// 	0x00, 0x01, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x01,
	// 	[]byte{0, 0, 0}, []byte{0x20, 0x00},
	// 	keyMaster, samUID)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// log.Printf("ChangeOffline hosts response: [% X]", res1)
}
