package main

import (
	"encoding/hex"
	"flag"
	_ "fmt"
	"log"
	"strings"

	"github.com/nmelo/smartcard/nxp/mifare/samav2"
	"github.com/nmelo/smartcard/pcsc"
)

var keyS string

func init() {
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
}

/**/
func main() {
	flag.Parse()
	log.Println("Start Logs")
	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal("Not connection")
	}
	defer ctx.Release()

	readers, err := pcsc.ListReaders(ctx)
	for i, el := range readers {
		log.Printf("reader %v: %s\n", i, el)
	}

	samReaders := make([]pcsc.Reader, 0)
	for _, el := range readers {
		if strings.Contains(el, "SAM") {
			samReaders = append(samReaders, pcsc.NewReader(ctx, el))
		}
		for _, samReader := range samReaders {
			sam, err := samav2.ConnectSamAv2(samReader)
			if err != nil {
				log.Printf("%s\n", err)
				continue
			}
			version, err := sam.GetVersion()
			if err != nil {
				log.Println("Not GetVersion: ", err)
			}
			log.Printf("GetVersion sam: % X\n", version)
			log.Printf("GetVersion sam: %s\n", string(version))
			atr, err := sam.ATR()
			if err != nil {
				log.Println("Not ATR: ", err)
			}
			log.Printf("ATR sam: % X\n", atr)

			key, err := hex.DecodeString(keyS)
			if err != nil {
				log.Fatal(err)
			}

			resp1, err := sam.AuthHostAV2(key, 100, 0, 0)
			if err != nil {
				log.Println("Not Auth: ", err)
				continue
			}
			log.Printf("auth sam: [% X]\n", resp1)

			//cipher, err := hex.DecodeString("40E20100942600004E61BC0064000000")
			cipher, err := hex.DecodeString("13120F009617E3050E000000983A0000")
			if err != nil {
				log.Fatal(err)
			}
			apdu2 := samav2.ApduActivateOfflineKey(72, 0x00, nil)
			log.Printf("active cipher: [% X]\n", apdu2)
			resp2, err := sam.Apdu(apdu2)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("active cipher: [% X]\n", resp2)
			apdu3 := samav2.ApduEncipherOffline_Data(true, cipher)
			log.Printf("apdu cipher: [% X]\n", apdu3)
			resp3, err := sam.Apdu(apdu3)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("encipher sam: [% X]\n", resp3)

			apdu4 := samav2.ApduDecipherOffline_Data(true, resp3[0:len(resp3)-2])
			log.Printf("apdu decipher: [% X]\n", apdu4)
			resp4, err := sam.Apdu(apdu4)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("decipher sam: [% X]\n", resp4)

			sam.DisconnectCard()
		}
	}
}

/**/
