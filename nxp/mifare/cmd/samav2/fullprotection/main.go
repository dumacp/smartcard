package main

import (
	"bytes"
	"crypto/aes"
	"log"

	"github.com/nmelo/smartcard/nxp/mifare/samav2"
	"github.com/nmelo/smartcard/pcsc"
	"golang.org/x/exp/errors/fmt"
)

func main() {

	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatalln(err)
	}
	rs, err := ctx.ListReaders()

	funcExtractReader := func() []byte {
		for i, v := range rs {
			log.Printf("reader %d -> %s", i, v)
			if bytes.Contains([]byte(v), []byte("00 00")) {
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

	samAv2, err := samav2.ConnectSamAv2(reader)
	if err != nil {
		log.Fatalln(err)
	}

	samAtr, err := samAv2.ATR()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("ATR: [ %X ]\n", samAtr)
	fmt.Printf("HIST: %q\n", samAtr)

	keyAuth := make([]byte, 16)
	block, err := aes.NewCipher(keyAuth)
	if err != nil {
		log.Fatalln(err)
	}

	res1, err := samAv2.AuthHostAV1(block, 0, 0, 0)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Auth hosts response: [% X]", res1)

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

	res1, err = samAv2.AuthHostAV2(keyMaster, 0, 0, 1)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Auth hosts response: [% X]", res1)

	////res1, err = samAv2.ChangeKeyEntry(0, 0xFF, keyMaster, keyMaster, keyMaster,
	////	0x00, 0x00, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x00,
	////	[]byte{0, 0, 0}, []byte{0x20, 0x00})
	////if err != nil {
	////	log.Fatalln(err)
	////}
	////log.Printf("Auth hosts response: [% X]", res1)
}
