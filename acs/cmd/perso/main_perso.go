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

// var keyNbr int

func init() {
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
	// flag.IntVar(&keyNbr, "keyNbr", 0x4000, "key Number")
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
		// cardi, err := mplusReader.ConnectDirect()
		// if err != nil {
		// 	log.Fatalf("%s\n", err)
		// }
		// repi, err := cardi.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
		// if err != nil {
		// 	log.Fatalf("%s\n", err)
		// }
		// log.Printf("card control: % X\n", repi)
		// repi, err = cardi.ControlApdu(0x42000000+2079, []byte{0x23, 0x01, 0x80})
		// if err != nil {
		// 	log.Fatalf("%s\n", err)
		// }
		// log.Printf("card control: % X\n", repi)
		cardPCsc, err := mplusReader.ConnectCardPCSC()
		if err != nil {
			log.Fatalf("%s\n", err)
		}

		resp, err := cardPCsc.TransparentSessionStart()
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("resp Switch1444_4: % X\n", resp)

		resp, err = cardPCsc.Switch1444_4()
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("resp Switch1444_4: % X\n", resp)

		mplus, err := mifare.Mplus(cardPCsc)
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

		atr, err := mplus.ATR()
		if err != nil {
			log.Println("ERROR: ", err)
		}
		log.Printf("card ATR: % X\n", atr)

		/**
		// resp, err := mplus.WritePerso(keyNbr, key)
		// if err != nil {
		// 	log.Fatalf("Error: %s\n", err)
		// }
		// log.Printf("WritePerso resp: % X\n", resp)

		resp, err := mplus.WritePerso(0x9001, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("WritePerso resp: % X\n", resp)


		resp, err = mplus.WritePerso(0x9000, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("WritePerso resp: % X\n", resp)

		resp, err = mplus.WritePerso(0x9002, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("WritePerso resp: % X\n", resp)

		resp, err = mplus.WritePerso(0x9003, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("WritePerso resp: % X\n", resp)

		for i := 0; i < 32; i++ {
			keyN := 0x4000 + i
			resp, err = mplus.WritePerso(keyN, key)
			if err != nil {
				log.Fatalf("Error: %s\n", err)
			}
			log.Printf("WritePerso resp: % X\n", resp)
		}

		resp, err = mplus.CommitPerso()
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("Commit Perso resp: % X\n", resp)
		/**/

		/**/

		resp, err = mplus.FirstAuth(0x9003, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("Auth: resp: % X\n", resp)
		// resp, err = mplus.TransparentSessionEnd()
		// if err != nil {
		// 	log.Fatalf("Error: %s\n", err)
		// }
		/**
		resp, err := mplus.FirstAuth(keyNbr,key)
		if err != nil {
			log.Fatalf("Error: %s\n",err)
		}
		log.Printf("Auth: % X\n", resp)
		/**/
		mplus.DisconnectCard()
	}
}
