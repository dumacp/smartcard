package main

import (
	"encoding/hex"
	"flag"
	"log"
	"strings"

	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/pcsc"
)

var keyS string
var keyNbr int

func init() {
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
	flag.IntVar(&keyNbr, "keyNbr", 0x4002, "key Number")
}

func main() {
	flag.Parse()

	key, err := hex.DecodeString(keyS)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("key: [% X]\n", key)

	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal("Not connection")
	}
	defer ctx.Release()
	readers, err := pcsc.ListReaders(ctx)
	for i, el := range readers {
		log.Printf("reader %v: %s\n", i, el)
	}
	mplusReaders := make([]pcsc.Reader, 0)
	for _, el := range readers {
		if strings.Contains(el, "PICC") {
			mplusReaders = append(mplusReaders, pcsc.NewReader(ctx, el))
		}
	}
	for _, mplusReader := range mplusReaders {
		mplus, err := mifare.ConnectMplus(mplusReader)
		if err != nil {
			log.Printf("%s\n", err)
			continue
		}
		uid, err := mplus.UID()
		if err != nil {
			log.Fatalln("ERROR: ", err)
		}
		log.Printf("card UID: % X\n", uid)

		ats, err := mplus.ATS()
		if err != nil {
			log.Println("ERROR: ", err)
		}
		log.Printf("card ATS: % X\n", ats)

		resp, err := mplus.FirstAuth(keyNbr, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("Auth: % X\n", resp)

		resp3, err := mplus.ReadEncMacMac(8, 4)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		log.Printf("read 8 resp: [% X]\n", resp3)
	}
}
