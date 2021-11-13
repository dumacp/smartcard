package main

import (
	"encoding/hex"
	"log"
	"time"

	"github.com/dumacp/smartcard/multiiso"
	"github.com/dumacp/smartcard/nxp/mifare/samav3"
)

func main() {

	/**
	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal(err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatal(err)
	}

	var reader pcsc.Reader
	for i, r := range readers {

		if strings.Contains(r, "01") {
			log.Printf("reader PICC%q: %s", i, r)
			reader = pcsc.NewReader(ctx, r)
			break
		}
	}

	var readerSAM pcsc.Reader
	for i, r := range readers {

		if strings.Contains(r, "00") {
			log.Printf("reader SAM %q: %s", i, r)
			readerSAM = pcsc.NewReader(ctx, r)
			break
		}
	}

	direct, err := reader.ConnectDirect()
	if err != nil {
		log.Fatal(err)
	}
	resp1, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp1: [% X]", resp1)
	}
	resp2, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x01, 0x8F})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp2: [% X]", resp2)
	}

	direct.DisconnectCard()

	// cardo, err := mifare.ConnectMplus(reader)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// sam, err := samav3.ConnectSam(readerSAM)

	/**/
	dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "multiiso", 1)

	cardi, err := reader.ConnectSamCard()
	// cardi, err := readerSAM.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	sam := samav3.SamAV3(cardi)

	// keyMaster := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	// keyMaster := make([]byte, 16)
	keyMaster, _ := hex.DecodeString("AF000000000000000000000000000000")
	if resp, err := sam.AuthHost(keyMaster, 0, 0, 0); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("Auth SAM resp: [% X]", resp)
	}

	/**
	cardp, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	cardo := mifare.Mplus(cardp)
	// cardm := mifareplus.NewCard(cardo, sam)

	atr, err := cardo.ATR()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ATR: [% X], %s", atr, atr)
	respuid, err := cardo.UID()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("UID: [% X]", respuid)

	uid := make([]byte, len(respuid[:len(respuid)-2]))
	copy(uid, respuid)

	div := make([]byte, 0)
	div = append(div, 0x01)
	div = append(div, uid...)

	for i := 0; i < len(uid); i++ {
		div = append(div, uid[len(uid)-1-i])
	}

	log.Printf("==== dataDiv: [% X]", div)

	/**
	keyDiv, err := sam.DumpSecretKey(102, 0, div)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("keyDiv: [% #X]", keyDiv)

	/**

	for _, i := range []int{1, 2, 3, 4, 5, 6, 7} {
		resp, err := cardo.FirstAuthf1(0x4000 + 2*i + 1)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("Auth f1: %X\n", resp)

		apdu1, err := sam.NonXauthMFPf1(true, 3, 11, 0x00, resp, div)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}

		apdu2, err := cardo.FirstAuthf2(apdu1[:len(apdu1)-2])
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}

		apdu3, err := sam.NonXauthMFPf2(apdu2)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}

		log.Printf("====  auth mplus: [% #X]", apdu3)
	}

	// if _, err := sam.ActivateOfflineKey(102, 0, div); err != nil {
	// 	log.Fatalln(err)
	// }

	/**
	keyDiv, err := sam.DumpSecretKey(101, 0, div)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("keyDiv: [% #X]", keyDiv)

	/**
	if _, err := sam.ActivateOfflineKey(101, 0, div); err != nil {
		log.Fatalln(err)
	}

	payload := make([]byte, 0)
	payload = append(payload, 0x01)
	payload = append(payload, div...)
	// payload = append(payload, 0x80)
	// payload[len(payload)-1] |= 0x40
	// payload = append(payload, make([]byte, 32-len(payload))...)

	cmac1, err := sam.SAMGenerateMAC(samav2.AES_ALG, payload)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("cmac1: [% X]", cmac1)

	/**
	blockMac, err := aes.NewCipher(keyMaster)
	if err != nil {
		log.Fatalln(err)
	}

	data := make([]byte, 0)
	data = append(data, 0x01)
	data = append(data, div...)
	data = append(data, 0x80)
	// data[len(data)-1] |= 0x40
	data = append(data, make([]byte, 32-len(data))...)
	log.Printf("data: [% X]", data)

	cmacS, err := cmac.Sum(data, blockMac, 16)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("cmac2: [% X]", cmacS)

	log.Println("success Auth!!!")
	/**/

}
