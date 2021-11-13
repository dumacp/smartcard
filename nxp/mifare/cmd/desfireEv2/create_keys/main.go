package main

import (
	"encoding/hex"
	"log"
	"sort"
	"strings"

	"github.com/dumacp/smartcard/nxp/mifare/desfire/ev2"
	"github.com/dumacp/smartcard/nxp/mifare/samav3"
	"github.com/dumacp/smartcard/pcsc"
)

func main() {

	//// Detectar lectora y tarjeta //////
	//////////////////////////////////////
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

	cardi, err := reader.ConnectCardPCSC()
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

	bytesUid := make([]byte, len(uid)-2)
	copy(bytesUid, uid[:len(uid)-2])
	divData := make([]byte, 0)
	divData = append(divData, 0x01)
	divData = append(divData, bytesUid...)
	for i := 0; i < len(bytesUid); i++ {
		divData = append(divData, bytesUid[len(bytesUid)-1-i])
	}

	// keyBytesOp, err := samCard.DumpSecretKey(30, 0, divData)
	// if err != nil {
	// 	log.Fatalf("DumpSecretKey error: %s", err)
	// }
	keyBytesAppMaster, err := samCard.DumpSecretKey(40, 0, divData)
	if err != nil {
		log.Fatalf("DumpSecretKey error: %s", err)
	}
	log.Printf("DumpSecretKey: %X", keyBytesAppMaster)
	keyBytesOp, err := samCard.DumpSecretKey(41, 0, divData)
	if err != nil {
		log.Fatalf("DumpSecretKey error: %s", err)
	}

	keyBytesPublic, err := samCard.DumpSecretKey(30, 0, divData)
	if err != nil {
		log.Fatalf("DumpSecretKey error: %s", err)
	}
	keyBytesDebit, err := samCard.DumpSecretKey(31, 0, divData)
	if err != nil {
		log.Fatalf("DumpSecretKey error: %s", err)
	}
	log.Printf("DumpSecretKey: %X", keyBytesDebit)
	keyBytesCredit, err := samCard.DumpSecretKey(32, 0, divData)
	if err != nil {
		log.Fatalf("DumpSecretKey error: %s", err)
	}
	log.Printf("DumpSecretKey: %X", keyBytesCredit)

	keyPublic := ev2.KeyID_0x02
	keyDebito := ev2.KeyID_0x03
	keyCredito := ev2.KeyID_0x04
	keyOperation := ev2.KeyID_0x01
	keyAppMaster := ev2.KeyID_0x00

	keyToUpdate := map[int][]byte{
		int(keyPublic):    keyBytesPublic,
		int(keyOperation): keyBytesOp,
		int(keyCredito):   keyBytesCredit,
		int(keyDebito):    keyBytesDebit,
		int(keyAppMaster): keyBytesAppMaster,
	}

	keyIndexes := make([]int, 0)
	for k := range keyToUpdate {
		keyIndexes = append(keyIndexes, k)
	}

	sort.Sort(sort.Reverse(sort.IntSlice(keyIndexes)))

	/**/

	aidPICC := []byte{0x01, 0x00, 0x00}

	err = d.SelectApplication(aidPICC, nil)
	if err != nil {
		log.Fatalln(err)
	}

	//llave persistina en un paso anterior
	keyDefault, err := hex.DecodeString("3ED6B7C6823D442D7783F8B3A0B1C9C659E7D8BDDF7FCD6A")
	if err != nil {
		log.Fatalln(err)
	}
	// Auth en modo EV2 (AES). si no se ha seleccionando ninguna aplicación
	// la auth es contra el PICC (también se puede seleccionar el contexto PICC
	// con el comando selectApplication(aid=0x000000)).
	auth3, err := d.AuthenticateEV2First(ev2.TargetPrimaryApp, int(keyAppMaster), nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	auth4, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], auth3)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth AES sucess: [% X]", auth4)

	for _, idx := range keyIndexes {

		v := keyToUpdate[idx]
		log.Printf("ChangeKeyEV2 key: %d", idx)
		log.Printf("ChangeKeyEV2 keyBytes: %X", v)
		// Cambio del contenido y tipo de la llave maestra del PICC
		err = d.ChangeKeyEV2(idx, 0x00, 0x00, ev2.AES, ev2.TargetPrimaryApp,
			v[:len(v)-2], keyDefault[0:16])
		if err != nil {
			log.Println(err)
		} else {
			log.Printf("**** ChangeKeyEV2 key: %d sucess  ****", idx)
		}
	}

}
