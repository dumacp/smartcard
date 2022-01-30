package main

import (
	"encoding/hex"
	"flag"
	_ "fmt"
	"log"
	"strings"

	"github.com/nmelo/smartcard/nxp/mifare"
	"github.com/nmelo/smartcard/nxp/mifare/samav2"
	"github.com/nmelo/smartcard/pcsc"
)

var keyS string

func init() {
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
}

/**/
func main() {
	log.Println("Start Logs")
	flag.Parse()
	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal("Not connection")
	}
	defer ctx.Release()

	readers, err := pcsc.ListReaders(ctx)
	for i, el := range readers {
		log.Printf("reader %v: %s\n", i, el)
	}

	var sam samav2.SamAv2
	var mplus mifare.MifarePlus
	samReaders := make([]pcsc.Reader, 0)
	for _, el := range readers {
		if strings.Contains(el, "SAM") {
			samReaders = append(samReaders, pcsc.NewReader(ctx, el))
		}
	}

	for _, samReader := range samReaders {
		log.Printf("sam reader: %s\n", samReader)
		//sam, err := samReader.ConnectSamAv2()
		sam, err = samav2.ConnectSamAv2(samReader)
		if err != nil {
			log.Println("%s\n", err)
		}
		version, err := sam.GetVersion()
		if err != nil {
			log.Println("Not GetVersion: ", err)
		}
		log.Printf("GetVersion sam: % X\n", version)

		key, err := hex.DecodeString(keyS)
		if err != nil {
			log.Fatal(err)
		}

		resp, err := sam.AuthHostAV2(key, 100, 0, 0)
		if err != nil {
			log.Println("Not Auth: ", err)
		}
		log.Printf("auth sam: [% X]\n", resp)

		//sam.DisconnectCard()
	}

	mplusReaders := make([]pcsc.Reader, 0)
	for _, el := range readers {
		if strings.Contains(el, "PICC") {
			mplusReaders = append(mplusReaders, pcsc.NewReader(ctx, el))
		}
	}

	for _, mplusReader := range mplusReaders {
		rCounter := 0
		// wCounter := 0
		log.Printf("mplus reader: %s\n", mplusReader)
		mplus, err = mifare.ConnectMplus(mplusReader)
		if err != nil {
			log.Printf("%s\n", err)
		}
		resp, err := mplus.UID()
		log.Printf("mplus uuid: % X\n", resp)
		if err != nil {
			log.Println("%s\n", err)
		}
		dataDiv := make([]byte, 4)
		dataDiv = append(dataDiv, resp[0:4]...)

		//resp, err = mplus.FirstAuthf1(0x4002)
		resp, err = mplus.FirstAuthf1(0x4005)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		//resp, err = sam.NonXauthMFPf1(true,3,0x07,0x00,resp,nil)
		resp, err = sam.NonXauthMFPf1(true, 3, 0x01, 0x00, resp, dataDiv)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		log.Printf("aid f2: [% X]\n", resp)
		resp, err = mplus.FirstAuthf2(resp[0 : len(resp)-2])
		if err != nil {
			log.Printf("%s\n", err)
		}
		resp, err = sam.NonXauthMFPf2(resp)
		if err != nil {
			log.Printf("%s\n", err)
		}
		log.Printf("auth mplus: [% X]\n", resp)

		resp, err = sam.DumpSessionKey()
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		log.Printf("sessionKey mplus: [% X]\n", resp)

		// keyEnc := resp[0:16]
		keyMac := resp[16:32]
		log.Printf("key Mac: [% X]\n", keyMac)
		Ti := resp[32:36]
		log.Printf("Ti: [% X]\n", Ti)
		readCounter := resp[36:38]
		log.Printf("Read Counter: [% X]\n", readCounter)

		//resp, err = mplus.ReadEncMacMac(4,1,rCounter,wCounter,Ti,keyMac,keyEnc)
		resp, err = mplus.ReadEncMacMac(11, 1)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		log.Printf("read 4 resp: [% X]\n", resp)

		rCounter++
		resp[5] = 0x0F
		resp[6] = 0x7F
		resp[7] = 0x07
		resp[8] = 0x88
		resp[9] = 0xFF

		/**/
		err = mplus.WriteEncMacMac(11, resp)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		/**/

		//mplus.DisconnectCard()
	}
	sam.DisconnectCard()
	mplus.DisconnectCard()
}

/**/
