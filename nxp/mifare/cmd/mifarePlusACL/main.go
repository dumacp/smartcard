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
var keyType string
var sectorInitial int
var sectorFinal int

func init() {
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
	flag.StringVar(&keyType, "keyType", "A", "key type (\"A\"|\"B\")")
	flag.IntVar(&sectorInitial, "sectorInitial", 1, "sector Number initial")
	flag.IntVar(&sectorFinal, "sectorFinal", 1, "sector Number final")
}

func main() {
	flag.Parse()

	keyDir := 0
	switch keyType {
	case "A":
	case "B":
		keyDir = 1
	default:
		log.Fatalln("wrong key type")
	}

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
	if err != nil {
		log.Fatal("Not connection")
	}
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

		resp, err := mplus.FirstAuth(0x4000+2*sectorInitial+keyDir, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("Auth: % X\n", resp)

		// //read sector trailer
		// resp3, err := mplus.ReadEncMacMac(sectorInitial*4+3, 1)
		// if err != nil {
		// 	log.Fatalf("%s\n", err)
		// }
		// log.Printf("sector trailer, sector %d,  resp: [% X]\n", sectorInitial, resp3)

		sectorTrailer := mifare.NewAccessBitsSectorTrailer().KeyB__WriteA_ReadWriteACL_WriteB___KeyA_readACL().SetPlain()
		block2 := mifare.NewAccessBits().Whole_AB().SetPlain()
		block1 := mifare.NewAccessBits().Whole_AB().SetPlain()
		block0 := mifare.NewAccessBits().Whole_AB().SetPlain()

		dataBlock3 := mifare.AccessConditions(sectorTrailer, block2, block1, block0, true)

		keyA := make([]byte, 16)
		for i := range keyA {
			keyA[i] = 0xFF
		}
		keyB := make([]byte, 16)
		for i := range keyB {
			keyB[i] = 0xFF
		}

		for i := sectorInitial; i <= sectorFinal; i++ {

			//write sector trailer
			err = mplus.WriteEncMacMac(i*4+3, dataBlock3)
			if err != nil {
				log.Fatalf("%s\n", err)
			}
			log.Printf("sector trailer written")

			//write keyA

			err = mplus.WriteEncMacMac(0x4000+2*i+0, keyA)
			if err != nil {
				log.Fatalf("%s\n", err)
			}
			log.Printf("keyA written")

			//write keyB

			err = mplus.WriteEncMacMac(0x4000+2*i+1, keyB)
			if err != nil {
				log.Fatalf("%s\n", err)
			}
			log.Printf("keyB written")

			log.Printf("sector %d success", i)
		}

	}
}
