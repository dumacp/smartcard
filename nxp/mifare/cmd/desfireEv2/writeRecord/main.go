package main

import (
	"encoding/hex"
	"log"
	"time"

	"github.com/dumacp/smartcard/multiiso"
	"github.com/dumacp/smartcard/nxp/mifare/desfire/ev2"
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
	readerSam := reader
	/**/

	cardi, err := reader.ConnectCard()
	if err != nil {
		log.Fatalln(err)
	}

	///// SAM

	sami, err := readerSam.ConnectSamCard()
	if err != nil {
		log.Fatal(err)
	}

	samCard := samav3.SamAV3(sami)

	//////////////////////////////////////////////////
	//////////////////////////////////////////////////

	//// Se instancia la tarjeta Desfire

	d := ev2.NewDesfire(cardi)

	uid, err := d.UID()
	if err != nil {
		log.Fatalf("GetCardUID() error: %s", err)
	}

	log.Printf("UID(): [% X]", uid)

	bytesUid := make([]byte, len(uid))
	copy(bytesUid, uid[:])
	divData := make([]byte, 0)
	divData = append(divData, 0x01)
	divData = append(divData, bytesUid...)
	for i := 0; i < len(bytesUid); i++ {
		divData = append(divData, bytesUid[len(bytesUid)-1-i])
	}

	log.Printf("DIV(): [% X]", divData)

	keyCredito := ev2.KeyID_0x04

	// samCard.DumpSecretKey()

	/**/
	aid := []byte{0x01, 0x00, 0x00}

	// // se selecciona la app 0x0000001 (antes estab seleccionado todo el PICC)
	// if err := d.SelectApplication(aid, nil); err != nil {
	// 	log.Fatalf("SelectApplication error: %s", err)
	// }

	// se selecciona la app 0x0000001 (antes estab seleccionado todo el PICC)
	if err := d.SelectApplication(aid, nil); err != nil {
		log.Fatalf("SelectApplication error: %s", err)
	}

	/**/
	// auth con la app seleccionada
	authApp, err := d.AuthenticateEV2First(0, int(keyCredito), nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	keyBytesOp, err := samCard.DumpSecretKey(41, 0, divData)
	if err != nil {
		log.Fatalf("DumpSecretKey error: %s", err)
	}
	log.Printf("DumpSecretKey  operation: %X", keyBytesOp)

	keyBytesCredit, err := samCard.DumpSecretKey(32, 0, divData)
	if err != nil {
		log.Fatalf("DumpSecretKey error: %s", err)
	}
	log.Printf("DumpSecretKey: %X", keyBytesCredit)

	authApp2, err := d.AuthenticateEV2FirstPart2(keyBytesCredit[:16], authApp)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authApp2)

	datafile_03, _ := hex.DecodeString("000100000000000000")

	if err := d.WriteData(0x03, ev2.TargetPrimaryApp, 0x00, datafile_03,
		ev2.FULL); err != nil {
		log.Fatalf("WriteData error: %s", err)
	}

	dataRecord_01, _ := hex.DecodeString("42DE8F6143010000300100002C01000001000000000000000000000000000000")
	log.Printf("dataRecord: %X, len: %d", dataRecord_01, len(dataRecord_01))
	// dataRecord_01[0] = 0x20

	for range []int{1} {
		// dataRecord_01[0] = byte(i)
		if err := d.WriteRecord(0x07, ev2.TargetPrimaryApp, 0x00, dataRecord_01,
			ev2.FULL); err != nil {
			log.Fatalf("WriteRecord error: %s", err)
		}
		// if data, err := d.CommitTransaction(true); err != nil {
		// 	log.Fatalf("CommitTransaction error: %s", err)
		// } else {
		// 	log.Printf("CommitTransaction: %X, len: %d", data, len(data))
		// }
	}

	if data, err := d.ReadRecords(0x07, ev2.TargetPrimaryApp, 0x00, 0x00, 32,
		ev2.FULL); err != nil {
		log.Fatalf("ReadRecords error: %s", err)
	} else {
		log.Printf("ReadRecords 07: %X, len: %d", data, len(data))
	}

}
