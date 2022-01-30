package main

import (
	"bytes"
	"log"

	"github.com/nmelo/smartcard/nxp/mifare/samav3"
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
	log.Printf("readers: %q\n", rs)

	funcExtractReader := func() []byte {
		// count := 0
		for _, v := range rs {
			log.Println(v)
			if bytes.Contains([]byte(v), []byte("00 02")) {
				// if count > 0 {
				return []byte(v)
				// }
				// count++
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

	sam, err := reader.ConnectSamCard()
	if err != nil {
		log.Fatalln(err)
	}

	samAv2 := samav3.SamAV3(sam)

	samAtr, err := samAv2.ATR()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("ATR: [ %X ], ASCII: %s\n", samAtr, samAtr)

	version, _ := samAv2.GetVersion()
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("Version: [ %X ]\n", version)

	/**/

	keyMaster := make([]byte, 16)

	if version[len(version)-3] == 0x03 {
		if _, err := samAv2.LockUnlock(keyMaster,
			make([]byte, 3), 0x00, 0x00, 0x00, 0x00, 0x03); err != nil {
			log.Panicln(err)
		}
	}

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

	// res1, err := samAv2.LockUnlock(keyAuth, make([]byte, 3), 0, 0, 0, 0, 0x03)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("Active response: [% X]", res1)

	// res1, err = samAv2.AuthHostAV1(block, 0, 0, 0)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// log.Printf("Auth hosts response: [% X]", res1)

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

	// var res1 []byte
	// for i := range keyMaster {
	// 	keyMaster[i] = 0xFF
	// }
	// keyMaster = []byte{0x70, 0x64, 0xE2, 0x1A, 0xA4, 0xFE, 0x40, 0xE2, 0x37, 0x55, 0x44, 0xED, 0x70, 0x2E, 0xB0, 0x0B}
	// keyMaster = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	// keyMaster = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	res1, err := samAv2.AuthHost(keyMaster, 0, 0, 0)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("Auth hosts response: [% X]", res1)

	// key1 := 0x0A

	// set1 := samav2.SETConfigurationSettings(false, false, samav2.AES_128,
	// 	true, false, false, false, false, false, false, false)
	// extSet1 := samav2.ExtSETConfigurationSettings(
	// 	samav2.HOST_KEY, false, false)
	// res1, err = samAv2.ChangeKeyEntry(key1, 0xFF, keyMaster, keyMaster, keyMaster,
	// 	0x00, 0x00, 0x00, 0xFF, 0x00, 0x01, 0x02, extSet1,
	// 	[]byte{0, 0, 0}, set1)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// log.Printf("change key [ %v ] response: [% X]", key1, res1)

	/**
	key2 := 22
	for i := range keyMaster {
		keyMaster[i] = 0x00
	}

	//keyQR, err := hex.DecodeString("06B30E65723E3C96488ED405F1242E88")
	//keyQR, err := hex.DecodeString("19BD370B9994E25A239B06DC9BA5531B")
	if err != nil {
		log.Fatalln(err)
	}
	set2 := samav2.SETConfigurationSettings(false, false, samav2.AES_128,
		false, false, false, false, false, false, false, false)
	extSet2 := samav2.ExtSETConfigurationSettings(
		samav2.HOST_KEY, false, false)
	res1, err = samAv2.ChangeKeyEntry(key2, 0xFF, keyMaster, keyMaster, keyMaster,
		0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, extSet2,
		[]byte{0, 0, 0}, set2)
	if err != nil {
		log.Println(err)
	}

	log.Printf("change key [ %v ] response: [% X]", key2, res1)

	/**

	// log.Printf("change key [ %v ] response: [% X]", key2, res1)

	// res1, err = samAv2.ActivateOfflineKey(0, 0x00, nil)
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
	/**/
}
