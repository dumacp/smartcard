package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/dumacp/smartcard/nxp/mifare/samav2"
	"github.com/dumacp/smartcard/pcsc"
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
	//dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
	dev, err := multiiso.NewDevice("/dev/ttymxc4", 460800, 300*time.Millisecond)
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

	cardi, err := reader.ConnectSamCard()
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

	/**

		samAv2.ActivateOfflineKey(31, 0, []byte{0x01, 0x04, 0x28, 0x0D, 0x4A, 0x45, 0x62, 0x80, 0x80, 0x62, 0x45, 0x4A, 0x0D, 0x28, 0x04})

		samAv2.SAMDecipherOfflineData(samav2.AES_ALG, []byte{0x2E, 0xB2, 0xD8, 0x94, 0x16, 0x35, 0x61, 0x4C, 0xF7, 0x23, 0x6E, 0x51, 0xD8, 0x4C, 0x2B, 0x5D})
		fmt.Println(`-> [02 01 1D 65 16 DF 00 13 86 00 80 0D 00 00 10 2E B2 D8 94 16 35 61 4C F7 23 6E 51 D8 4C 2B 5D 00 6F 03]
	<- [02 00 15 00 00 12 43 BA 86 41 D8 A7 D9 09 22 13 1D 15 B5 05 85 AF 90 00 A5 03]`)
		samAv2.SAMEncipherOfflineData(samav2.AES_ALG, []byte{0x9E, 0x40, 0x92, 0xE2, 0x97, 0x6C, 0xBA, 0x65, 0x68, 0x2B, 0xC2, 0x79, 0x19, 0xB3, 0x4A, 0x9A, 0xBA, 0x86, 0x41, 0xD8, 0xA7, 0xD9, 0x09, 0x22, 0x13, 0x1D, 0x15, 0xB5, 0x05, 0x85, 0xAF, 0x43})
		fmt.Println(`-> [02 01 2D 65 26 DF 00 13 86 00 80 0E 00 00 20 9E 40 92 E2 97 6C BA 65 68 2B C2 79 19 B3 4A 9A BA 86 41 D8 A7 D9 09 22 13 1D 15 B5 05 85 AF 43 00 B1 03]
	<- [02 00 25 00 00 22 C9 16 85 45 ED 99 67 CE EB BE 2F A9 CE 4E EF CF 94 4B 1B 79 51 97 A4 66 1E 70 FF BA 9B 60 4B AF 90 00 AB 03]`)
		samAv2.SAMDecipherOfflineData(samav2.AES_ALG, []byte{0x3A, 0x20, 0x82, 0xB3, 0x86, 0xC3, 0x23, 0x8C, 0x6E, 0x54, 0xB3, 0x5C, 0x24, 0xB3, 0x2D, 0xCA, 0x29, 0x7C, 0xCA, 0xA8, 0xA8, 0x8C, 0x4F, 0xE5, 0x70, 0x50, 0xB4, 0x5B, 0x3F, 0xEF, 0x5F, 0x64})
		fmt.Println(`-> [02 01 2D 65 26 DF 00 13 86 00 80 0D 00 00 20 3A 20 82 B3 86 C3 23 8C 6E 54 B3 5C 24 B3 2D CA 29 7C CA A8 A8 8C 4F E5 70 50 B4 5B 3F EF 5F 64 00 71 03]
	<- [02 00 25 00 00 22 1D 36 61 3F 40 92 E2 97 6C BA 65 68 2B C2 79 19 B3 4A 9A 9E 00 00 00 00 00 00 00 00 00 00 00 00 90 00 EA 03]`)

		samAv2.SAMLoadInitVector(samav2.AES_ALG, make([]byte, 16))
		cmac, err := samAv2.SAMGenerateMAC(samav2.AES_ALG, []byte{0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80, 0x9E, 0x40, 0xD1, 0x58, 0x11, 0x2D, 0x62, 0xC2, 0xD9, 0x09, 0x22, 0x13, 0x1D, 0x15, 0xB5, 0x05, 0x85, 0xAF, 0x68, 0x2B, 0xC2, 0x79, 0x19, 0xB3, 0x4A, 0x9A})
		fmt.Println(`-> [02 01 2D 65 26 DF 00 13 86 00 80 7C 00 10 20 A5 5A 00 01 00 80 9E 40 D1 58 11 2D 62 C2 D9 09 22 13 1D 15 B5 05 85 AF 68 2B C2 79 19 B3 4A 9A 00 AD 03]
	<- [02 00 15 00 00 12 EE 8F E6 A2 54 E0 0A 9F EA 4C CF F3 E2 2C DB A2 90 00 BE 03]`)
		if err != nil {
			log.Panicln(err)
		}
		log.Printf("cmac: [% X]\n", cmac)
		cmac, err = samAv2.SAMGenerateMAC(samav2.AES_ALG, []byte{
			0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80, 0x16, 0x70, 0x3A, 0x1F, 0x0F, 0x88, 0x05, 0x22, 0x69, 0xCD,
			0x7B, 0x7D, 0x07, 0x79, 0xA6, 0xF2, 0x0E, 0x2E, 0x73, 0xE7, 0x6A, 0xB4, 0xF2, 0x2A, 0x70, 0x43,
		})
		if err != nil {
			log.Panicln(err)
		}
		log.Printf("cmac: [% X]\n", cmac)

		**/

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

	/**/
	// keyMaster := make([]byte, 16)
	keyMaster, _ := hex.DecodeString("4F8DF779A7809E97F362C5C376176CD7")
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

	res1, err = samAv2.AuthHostAV2(keyMaster, 100, 0, 0)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Auth hosts response: [% X]", res1)

	/**

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
