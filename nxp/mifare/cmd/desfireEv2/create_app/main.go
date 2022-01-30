package main

import (
	"encoding/hex"
	"log"
	"strings"

	"github.com/nmelo/smartcard/nxp/mifare/desfire/ev2"
	"github.com/nmelo/smartcard/pcsc"
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

	//////////////////////////////////////////////////
	//////////////////////////////////////////////////

	//// Se instancia la tarjeta Desfire

	d := ev2.NewDesfire(cardi)

	keyMaster := make([]byte, 16)

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

	// se selecciona el nivel PICC (la aplicación []byte{0,0,0})

	aidPICC := make([]byte, 3)

	err = d.SelectApplication(aidPICC, nil)
	if err != nil {
		log.Fatalln(err)
	}

	/////////////////////////////////////////////////
	/////////////////////////////////////////////////

	// se crea la aplicación 0x000001

	aid := []byte{0x01, 0x00, 0x00}
	if err := d.CreateApplication(aid, ev2.AES, ev2.KeyID_0x00, 10,
		true, true, true, true, true, false, false, true, false,
		ev2.KeyID_0x00, 0x00, 3, 16, nil, nil); err != nil {
		log.Fatalf("CreateApplication error: %s", err)
	}

	// keyPublic := ev2.KeyID_0x01
	keyDebito := ev2.KeyID_0x02
	keyCredito := ev2.KeyID_0x03
	keyOperation := ev2.KeyID_0x04

	// se selecciona la app 0x0000001 (antes estab seleccionado todo el PICC)
	if err := d.SelectApplication(aid, nil); err != nil {
		log.Fatalf("SelectApplication error: %s", err)
	}

	// auth con la app seleccionada
	authApp, err := d.AuthenticateEV2First(0, 0, nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	//llave persistina en un paso anterior
	keyDefault, err := hex.DecodeString("3ED6B7C6823D442D7783F8B3A0B1C9C659E7D8BDDF7FCD6A")
	if err != nil {
		log.Fatalln(err)
	}

	authApp2, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], authApp)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authApp2)

	// se crea un archivo en la app seleccionada
	if err := d.CreateStdDataFile(0x01, ev2.TargetPrimaryApp, nil, false, ev2.MAC,
		keyDebito, keyOperation, ev2.NO_ACCESS, ev2.KeyID_0x00, 128); err != nil {
		log.Fatalf("CreateStdDataFile error: %s", err)
	}
	/**/
	// se crea un archivo en la app seleccionada
	if err := d.CreateBackupDataFile(0x02, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyOperation, keyCredito, ev2.KeyID_0x00, 64); err != nil {
		log.Fatalf("CreateBackupDataFile error: %s", err)
	}
	// se crea un archivo en la app seleccionada
	if err := d.CreateBackupDataFile(0x03, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00, 64); err != nil {
		log.Fatalf("CreateBackupDataFile error: %s", err)
	}
	// se crea un archivo en la app seleccionada
	if err := d.CreateValueFile(0x04, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00,
		-100_000, 10_000_000, 1_000_000, true, false); err != nil {
		log.Fatalf("CreateValueFile error: %s", err)
	}
	// se crea un archivo en la app seleccionada
	if err := d.CreateCyclicRecorFile(0x05, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00,
		64, 3); err != nil {
		log.Fatalf("CreateCyclicRecorFile error: %s", err)
	}
	// se crea un archivo en la app seleccionada
	if err := d.CreateCyclicRecorFile(0x06, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00,
		64, 3); err != nil {
		log.Fatalf("CreateCyclicRecorFile error: %s", err)
	}

	// se crea un archivo para verificar la integridad d elas transacciones en la tarjeta
	keyTMAC, err := hex.DecodeString("3012ED2C749C06A034F7030FECC17906")
	if err != nil {
		log.Fatalf("CreateTransactionMACFile error: %s", err)
	}
	if err := d.CreateTransactionMACFile(0x0A, ev2.TargetPrimaryApp, nil, ev2.FULL,
		keyOperation, ev2.NO_ACCESS, ev2.KeyID_0x00, keyTMAC, 0x00,
		ev2.AES); err != nil {
		log.Fatalf("CreateTransactionMACFile error: %s", err)
	}

	/**/
	// se listas los archivos creados en la tarjeta
	fileIDs, err := d.GetFileIDs()
	if err != nil {
		log.Fatalf("GetFileIDs error: %s", err)
	}

	log.Printf("file IDs response: [% X]", fileIDs)
	/**/
}
