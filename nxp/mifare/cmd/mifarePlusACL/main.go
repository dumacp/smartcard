package main

import (
	"crypto/aes"
	"encoding/hex"
	"flag"
	"log"
	"strings"

	"github.com/aead/cmac"
	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/pcsc"
)

var keyS string
var keyType string
var sectorInitial int
var sectorFinal int
var div bool

func init() {
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
	flag.BoolVar(&div, "div", false, "enable diverfisied key?")
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

		if div {
			divData := []byte{0x01}
			divData = append(divData, uid[:7]...)
			for i := 0; i < len(uid[:7]); i++ {
				divData = append(divData, uid[:7][len(uid[:7])-1-i])
			}

			log.Printf("data diversified: % X\n", divData)

			block, err := aes.NewCipher(key)
			if err != nil {
				log.Fatalln(err)
			}
			if len(divData)%block.BlockSize() != 0 {
				divData = append(divData, 0x80)
				if len(divData)%block.BlockSize() != 0 {
					divData = append(divData,
						make([]byte, block.BlockSize()-len(divData)%block.BlockSize())...)
				}
			}
			log.Printf("data diversified: % X\n", divData)
			mac, err := cmac.Sum(divData, block, block.BlockSize())
			if err != nil {
				log.Fatalln(err)
			}
			key = mac
			log.Printf("key diversified: % X\n", key)
		}

		/**/
		// key = []byte{0xC0, 0xA3, 0xD0, 0x80, 0x87, 0xE1, 0x84, 0xB6, 0x2B, 0xD1, 0xE1, 0x35, 0x5B, 0x68, 0x9C, 0x43}
		resp, err := mplus.FirstAuth(0x4000+2*sectorInitial+keyDir, key)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("Auth: % X\n", resp)

		//read sector trailer
		resp3, err := mplus.ReadEncMacMac(sectorInitial*4+0, 1)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		log.Printf("sector trailer, sector %d,  resp: [% X]\n", sectorInitial, resp3)

		sectorTrailer := mifare.NewAccessBitsSectorTrailer().KeyB__WriteA_ReadWriteACL_WriteB___KeyA_readACL().SetPlain()
		block2 := mifare.NewAccessBits().Whole_AB().SetPlain()
		block1 := mifare.NewAccessBits().Whole_AB().SetPlain()
		block0 := mifare.NewAccessBits().Whole_AB().SetPlain()

		dataBlock3 := mifare.AccessConditions(sectorTrailer, block2, block1, block0, true)
		log.Printf("sector trailer: [% X]  ==============\n", dataBlock3)

		keyA := make([]byte, 16)
		for i := range keyA {
			keyA[i] = 0xFF
		}
		keyB := make([]byte, 16)
		for i := range keyB {
			keyB[i] = 0xFF
		}
		// keyA := []byte{0xC0, 0xA3, 0xD0, 0x80, 0x87, 0xE1, 0x84, 0xB6, 0x2B, 0xD1, 0xE1, 0x35, 0x5B, 0x68, 0x9C, 0x43}
		// keyB := []byte{0xC0, 0xA3, 0xD0, 0x80, 0x87, 0xE1, 0x84, 0xB6, 0x2B, 0xD1, 0xE1, 0x35, 0x5B, 0x68, 0x9C, 0x43}

		for i := sectorInitial; i <= sectorFinal; i++ {

			resp, err := mplus.FirstAuth(0x4000+2*i+keyDir, key)
			if err != nil {
				log.Fatalf("Error: %s\n", err)
				continue
			}
			log.Printf("====== Auth: [% X]  ==============\n", resp)

			/**/
			//read sector trailer
			for _, j := range []int{3} {
				resp3, err := mplus.ReadEncMacMac(i*4+j, 1)
				if err != nil {
					log.Fatalf("%s\n", err)
				}
				log.Printf("sector %d, bloque %d,  resp: [% X]\n", i, i*4+j, resp3)
			}

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
			/**/

			/**/
			//write sector trailer
			err = mplus.WriteEncMacMac(i*4+3, dataBlock3)
			if err != nil {
				log.Fatalf("%s\n", err)
			}
			log.Printf("sector trailer written")

			/**/
		}

	}
}
