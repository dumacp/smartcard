package main

import (
	"log"
	"time"

	"github.com/dumacp/smartcard/multiiso"
	"github.com/dumacp/smartcard/nxp/mifare/samav3"
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

	dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
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

	uid := []byte{0x04, 0x13, 0x33, 0xB2, 0xF2, 0x61, 0x80}

	bytesUid := make([]byte, len(uid))
	copy(bytesUid, uid[:])
	divData := make([]byte, 0)
	divData = append(divData, 0x01)
	divData = append(divData, bytesUid...)
	for i := 0; i < len(bytesUid); i++ {
		divData = append(divData, bytesUid[len(bytesUid)-1-i])
	}

	// if slot != s.keyCrypto {
	resp, err := samCard.DumpSecretKey(20, 0, divData)
	if err != nil {
		log.Printf("err: %s", err)
	}

	log.Printf("sam QR: %X", resp)

	resp1, err := samCard.DumpSecretKey(32, 0, divData)
	if err != nil {
		log.Printf("err: %s", err)
	}

	log.Printf("sam Credito: %X", resp1)

	resp2, err := samCard.DumpSecretKey(31, 0, divData)
	if err != nil {
		log.Printf("err: %s", err)
	}

	log.Printf("sam debito: %X", resp2)

	resp3, err := samCard.DumpSecretKey(30, 0, divData)
	if err != nil {
		log.Printf("err: %s", err)
	}

	log.Printf("sam publica: %X", resp3)

	resp4, err := samCard.DumpSecretKey(40, 0, divData)
	if err != nil {
		log.Printf("err: %s", err)
	}

	log.Printf("sam app: %X", resp4)

	resp5, err := samCard.DumpSecretKey(41, 0, divData)
	if err != nil {
		log.Printf("err: %s", err)
	}

	log.Printf("sam operacion: %X", resp5)
}
