package main

import (
	"log"
	"time"

	"github.com/nmelo/smartcard/multiiso"
	"github.com/nmelo/smartcard/nxp/mifare/samav2"
	"github.com/nmelo/smartcard/nxp/mifare/samav3"
)

func main() {
	//// Detectar lectora y tarjeta //////
	//////////////////////////////////////
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
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "PICC") {
			reader = pcsc.NewReader(ctx, r)
			log.Printf("reader PICC detected %q", r)
			break
		}
	}

	var readerSam pcsc.Reader
	for i, r := range readers {
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "SAM") {
			readerSam = pcsc.NewReader(ctx, r)
			break
		}
	}

	if reader == nil || readerSam == nil {
		log.Fatalln(err)
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

	/**/
	/////////////////// MULTI_ISO  ///////

	dev, err := multiiso.NewDevice("/dev/ttymxc4", 460800, 300*time.Millisecond)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "multiiso", 1)

	/**/

	readerSam := reader
	/**/

	///// SAM

	sami, err := readerSam.ConnectSamCard()
	if err != nil {
		log.Fatal(err)
	}

	samCard := samav3.SamAV3(sami)

	if atr, err := samCard.ATR(); err == nil {
		log.Printf("ATR: [%X], %s", atr, atr)
	}
	if atr, err := samCard.ATS(); err == nil {
		log.Printf("ATR: [%X], %s", atr, atr)
	}
	if atr, err := samCard.UID(); err == nil {
		log.Printf("UID: [%X], %s", atr, atr)
	}
	if atr, err := samCard.GetVersion(); err == nil {
		log.Printf("GetVersion: [%X], %s", atr, atr)
	}

	slot := 20

	divInput := []byte{0, 1, 2, 3}
	iv := make([]byte, 16)
	data := make([]byte, 16)

	// if slot != s.keyCrypto {
	if _, err := samCard.ActivateOfflineKey(slot, 0, divInput); err != nil {
		log.Printf("err: %s", err)
	}
	// 	s.keyCrypto = slot
	// }

	if _, err := samCard.SAMLoadInitVector(samav2.AES_ALG, iv); err != nil {
		log.Printf("err: %s", err)
	}

	resp, err := samCard.SAMDecipherOfflineData(samav2.AES_ALG, data)
	if err != nil {
		// logs.LogBuild.Printf("decipher err: %s, %X", err, data)
		log.Printf("err: %s", err)
	}

	log.Printf("sam decipher: %X", resp)

	// if slot != s.keyCrypto {
	if _, err := samCard.ActivateOfflineKey(32, 0, divInput); err != nil {
		log.Printf("err: %s", err)
	}
	// 	s.keyCrypto = slot
	// }

	if _, err := samCard.SAMLoadInitVector(samav2.AES_ALG, iv); err != nil {
		log.Printf("err: %s", err)
	}

	resp1, err := samCard.SAMDecipherOfflineData(samav2.AES_ALG, data)
	if err != nil {
		// logs.LogBuild.Printf("decipher err: %s, %X", err, data)
		log.Printf("err: %s", err)
	}
	log.Printf("sam  32: %X", resp1)

	// if slot != s.keyCrypto {
	resp2, err := samCard.NonXauthMFPf1(true, 3, 20, 0, make([]byte, 16), nil)
	if err != nil {
		log.Printf("err: %s", err)
	}

	log.Printf("sam  NonXauthMFPf1: %X", resp2)
}
