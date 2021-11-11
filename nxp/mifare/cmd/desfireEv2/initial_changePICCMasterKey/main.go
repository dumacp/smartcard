package main

import (
	"encoding/hex"
	"log"
	"strings"

	"github.com/dumacp/smartcard/nxp/mifare/desfire/ev2"
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

	cardi, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	/////////////////////////////////////////////
	/////////////////////////////////////////////

	//// Se instancia la tarjeta Desfire

	d := ev2.NewDesfire(cardi)

	// se selecciona el nivel PICC (la aplicación []byte{0,0,0})

	aidPICC := make([]byte, 3)

	err = d.SelectApplication(aidPICC, nil)
	if err != nil {
		log.Fatalln(err)
	}

	keyMaster := make([]byte, 16)

	//////////////////////////////////////////
	// Auth inicial con un PICC desde fabrica
	/////////////////////////////////////////
	/**/
	auth1, err := d.AuthenticateISO(0, 0)
	if err != nil {
		log.Println(err)
	}

	auth2, err := d.AuthenticateISOPart2(keyMaster, auth1)
	if err != nil {
		auth1, err = d.AuthenticateEV2First(0, 0, nil)
		if err != nil {
			log.Fatalln(err)
		}
		keyMaster, _ = hex.DecodeString("AF000000000000000000000000000001")

		auth2, err = d.AuthenticateEV2FirstPart2(keyMaster, auth1)
		if err != nil {
			log.Fatalln(err)
		}
	}

	log.Printf("**** auth sucess: [% X]", auth2)

	keyMaster, _ = hex.DecodeString("AF000000000000000000000000000001")

	// Cambio del contenido y tipo de la llave maestra del PICC
	err = d.ChangeKey(0x00, 0x00, ev2.AES, 0x00, keyMaster, nil)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("**** changekey sucess ****")
	/**/

	// Auth en modo EV2 (AES). si no se ha seleccionando ninguna aplicación
	// la auth es contra el PICC (también se puede seleccionar el contexto PICC
	// con el comando selectApplication(aid=0x000000)).
	auth3, err := d.AuthenticateEV2First(0, 0, nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	auth4, err := d.AuthenticateEV2FirstPart2(keyMaster, auth3)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth AES sucess: [% X]", auth4)

	// Se obtiene el UID (el UID puede ser obtenido desde ATS si está permitido en la conf)
	if uid, err := d.GetCardUID(); err != nil {
		log.Fatalf("GetCardUID error: %s", err)
	} else {
		log.Printf("UID: [% X]", uid)
	}

	// comando para borrar toda la tarjeta
	if err := d.Format(); err != nil {
		log.Fatalf("Format error: %s", err)
	}

	keyDefault, err := hex.DecodeString("3ED6B7C6823D442D7783F8B3A0B1C9C659E7D8BDDF7FCD6A")
	if err != nil {
		log.Fatalln(err)
	}
	keyVersion := 0x00

	keyDefault = append(keyDefault, byte(keyVersion))

	// Se persiste una llave por defecto para las applicaciones que se creen
	if err := d.SetConfiguration(ev2.DEFAULT_KEYS_UPDATE, keyDefault); err != nil {
		log.Fatalf("SetConfiguration error: %s", err)
	}

}
