package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/nmelo/smartcard/nxp/mifare/desfire/ev2"
	"github.com/nmelo/smartcard/pcsc"
)

func main() {

	//// Detectar lectora y tarjeta //////
	//////////////////////////////////////
	/**/
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

	/**
	/////////////////// MULTI_ISO  ///////

	dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "multiiso", 1)

	/**/

	cardi, err := reader.ConnectCard()
	if err != nil {
		log.Fatalln(err)
	}

	//////////////////////////////////////////////////
	//////////////////////////////////////////////////

	//// Se instancia la tarjeta Desfire

	d := ev2.NewDesfire(cardi)

	keyPublic := ev2.KeyID_0x02
	// keyDebito := ev2.KeyID_0x03
	keyCredito := ev2.KeyID_0x04
	keyOperation := ev2.KeyID_0x01
	// keyAppMaster := ev2.KeyID_0x00

	//llave persistina en un paso anterior
	keyDefault, err := hex.DecodeString("3ED6B7C6823D442D7783F8B3A0B1C9C659E7D8BDDF7FCD6A")
	if err != nil {
		log.Fatalln(err)
	}

	// samCard.DumpSecretKey()

	/**/

	aidPICC := make([]byte, 3)

	err = d.SelectApplication(aidPICC, nil)
	if err != nil {
		log.Fatalln(err)
	}

	keyMaster, _ := hex.DecodeString("AF000000000000000000000000000001")

	// Auth en modo EV2 (AES). si no se ha seleccionando ninguna aplicación
	// la auth es contra el PICC (también se puede seleccionar el contexto PICC
	// con el comando selectApplication(aid=0x000000)).
	auth3, err := d.AuthenticateEV2First(0, 0, nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	auth4, err := d.AuthenticateEV2FirstPart2(keyMaster, auth3)
	if err != nil {

		auth3, err = d.AuthenticateEV2First(0, 0, nil)
		if err != nil {
			log.Fatalln(err)
		}

		keyMaster, _ = hex.DecodeString("AFFAAF00000000000000000000030201")

		fmt.Println("////////////////// 1  ")
		auth4, err = d.AuthenticateEV2FirstPart2(keyMaster, auth3)
		if err != nil {
			log.Fatalln(err)
		}
	}

	log.Printf("**** auth AES sucess: [% X]", auth4)

	// se selecciona el nivel PICC (la aplicación []byte{0,0,0})

	/////////////////////////////////////////////////
	/////////////////////////////////////////////////

	// se crea la aplicación 0x000001

	/**/
	aid := []byte{0x01, 0x00, 0x00}

	// // se selecciona la app 0x0000001 (antes estab seleccionado todo el PICC)
	// if err := d.SelectApplication(aid, nil); err != nil {
	// 	log.Fatalf("SelectApplication error: %s", err)
	// }

	if err := d.DeleteApplication(aid); err != nil {
		log.Printf("DeleteApplication error: %s", err)
	}

	/**/
	if err := d.CreateApplication(aid, ev2.AES, ev2.KeyID_0x00, 10,
		true, true, true, true, true, false, false, true, false,
		ev2.KeyID_0x00, 0x00, 3, 16, nil, nil); err != nil {
		log.Fatalf("CreateApplication error: %s", err)
	}

	keyDebito := ev2.KeyID_0x03
	/**/

	// se selecciona la app 0x0000001 (antes estab seleccionado todo el PICC)
	if err := d.SelectApplication(aid, nil); err != nil {
		log.Fatalf("SelectApplication error: %s", err)
	}

	/**/
	// auth con la app seleccionada
	authApp, err := d.AuthenticateEV2First(0, 0, nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	authApp2, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], authApp)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authApp2)

	accessRights := uint16(0)

	accessRights |= (uint16(keyCredito) << 12)
	accessRights |= (uint16(keyOperation) << 8)
	accessRights |= (uint16(keyOperation) << 4)
	accessRights |= (uint16(0x0F) << 0)

	accessRightsBytes := make([]byte, 2)

	binary.LittleEndian.PutUint16(accessRightsBytes, accessRights)

	// se crea un archivo en la app seleccionada
	if err := d.CreateStdDataFile(0x01, ev2.TargetPrimaryApp, nil, false, ev2.MAC,
		keyPublic, ev2.NO_ACCESS, keyOperation, ev2.KeyID_0x00, 64); err != nil {
		log.Fatalf("CreateStdDataFile error: %s", err)
	}
	if err := d.ChangeFileSettings(0x01, ev2.TargetPrimaryApp, nil, false, ev2.MAC,
		keyPublic, ev2.NO_ACCESS, keyOperation, ev2.KeyID_0x00, 1,
		accessRightsBytes); err != nil {
		log.Fatalf("ChangeFileSettings error: %s", err)
	}

	// se crea un archivo en la app seleccionada
	if err := d.CreateBackupDataFile(0x02, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyOperation, keyOperation, ev2.KeyID_0x00, 32); err != nil {
		log.Fatalf("CreateBackupDataFile error: %s", err)
	}
	if err := d.ChangeFileSettings(0x02, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyOperation, keyOperation, ev2.KeyID_0x00, 1,
		accessRightsBytes); err != nil {
		log.Fatalf("ChangeFileSettings error: %s", err)
	}

	accessRights = uint16(0)

	accessRights |= (uint16(keyOperation) << 12)
	accessRights |= (uint16(keyOperation) << 8)
	accessRights |= (uint16(keyOperation) << 4)
	accessRights |= (uint16(0x0F) << 0)

	// se crea un archivo en la app seleccionada
	if err := d.CreateBackupDataFile(0x03, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyCredito, keyCredito, ev2.KeyID_0x00, 32); err != nil {
		log.Fatalf("CreateBackupDataFile error: %s", err)
	}
	if err := d.ChangeFileSettings(0x03, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyCredito, keyCredito, ev2.KeyID_0x00, 1,
		accessRightsBytes); err != nil {
		log.Fatalf("ChangeFileSettings error: %s", err)
	}
	// se crea un archivo en la app seleccionada
	if err := d.CreateValueFile(0x05, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyCredito, keyCredito, ev2.KeyID_0x00,
		-30_000, 1_000_000, 0, true, false); err != nil {
		log.Fatalf("CreateValueFile error: %s", err)
	}
	if err := d.ChangeFileSettings(0x05, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyCredito, keyCredito, ev2.KeyID_0x00, 1,
		accessRightsBytes); err != nil {
		log.Fatalf("ChangeFileSettings error: %s", err)
	}
	// se crea un archivo en la app seleccionada
	if err := d.CreateCyclicRecorFile(0x06, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00,
		32, 3); err != nil {
		log.Fatalf("CreateCyclicRecorFile error: %s", err)
	}
	if err := d.ChangeFileSettings(0x06, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00, 1,
		accessRightsBytes); err != nil {
		log.Fatalf("ChangeFileSettings error: %s", err)
	}
	// se crea un archivo en la app seleccionada
	if err := d.CreateCyclicRecorFile(0x07, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00,
		32, 7); err != nil {
		log.Fatalf("CreateCyclicRecorFile error: %s", err)
	}
	if err := d.ChangeFileSettings(0x07, ev2.TargetPrimaryApp, nil, false, ev2.FULL,
		keyDebito, keyDebito, keyCredito, ev2.KeyID_0x00, 1,
		accessRightsBytes); err != nil {
		log.Fatalf("ChangeFileSettings error: %s", err)
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

	// se listas los archivos creados en la tarjeta
	fileIDs, err := d.GetFileIDs()
	if err != nil {
		log.Fatalf("GetFileIDs error: %s", err)
	}

	log.Printf("file IDs response: [% X]", fileIDs)
	/**/

	// // file 0x01
	// NOMBREUSUARIO: {FileID: 1, Type: desfire.STRING32, Offset: 0},
	// TIPODOCUMENTO: {FileID: 1, Type: desfire.UINT8, Offset: 32},
	// DocID:         {FileID: 1, Type: desfire.STRING16, Offset: 33},
	// NUMEROTARJETA: {FileID: 1, Type: desfire.UINT32, Offset: 49},
	// VERSIONLAYOUT: {FileID: 1, Type: desfire.UINT8, Offset: 53},

	// auth con la app seleccionada
	authApp3, err := d.AuthenticateEV2First(0, int(keyOperation), nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	authApp4, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], authApp3)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authApp4)

	datafile_01 := make([]byte, 54)

	offset := 0
	for i, v := range []byte("JUAN PEREZ PEREZ") {
		datafile_01[i+offset] = v
	}
	offset = 32
	for i, v := range []byte{0x01} {
		datafile_01[i+offset] = v
	}
	offset = 33
	for i, v := range []byte("9999999") {
		datafile_01[i+offset] = v
	}
	offset = 49
	for i, v := range []byte{0x00, 0x01, 0x01, 0x01} {
		datafile_01[i+offset] = v
	}
	offset = 53
	for i, v := range []byte{0x01} {
		datafile_01[i+offset] = v
	}

	log.Printf("len datafile_01: %d", len(datafile_01))

	if err := d.WriteData(0x01, ev2.TargetPrimaryApp, 0x00, datafile_01,
		ev2.MAC); err != nil {
		log.Fatalf("WriteData error: %s", err)
	}

	// // file 0x02

	// PERFIL:               {FileID: 2, Type: desfire.UINT8, Offset: 0},
	// PMR:                  {FileID: 2, Type: desfire.UINT8, Offset: 1},
	// AC:                   {FileID: 2, Type: desfire.UINT8, Offset: 2},
	// VERSIONLAYOUT_BACKUP: {FileID: 2, Type: desfire.UINT8, Offset: 3},
	// NUMEROTARJETA_BACKUP: {FileID: 2, Type: desfire.UINT32, Offset: 4},

	datafile_02 := make([]byte, 8)
	offset = 0
	for i, v := range []byte{0x04} {
		datafile_02[i+offset] = v
	}
	offset = 1
	for i, v := range []byte{0x00} {
		datafile_02[i+offset] = v
	}
	offset = 2
	for i, v := range []byte{0x00} {
		datafile_02[i+offset] = v
	}
	offset = 3
	for i, v := range []byte{0x01} {
		datafile_02[i+offset] = v
	}
	offset = 4
	for i, v := range []byte{0x00, 0x01, 0x01, 0x01} {
		datafile_02[i+offset] = v
	}

	if err := d.WriteData(0x02, ev2.TargetPrimaryApp, 0x00, datafile_02,
		ev2.FULL); err != nil {
		log.Fatalf("WriteData error: %s", err)
	}

	// auth con la app seleccionada
	authApp5, err := d.AuthenticateEV2First(0, int(keyCredito), nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	authApp6, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], authApp5)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authApp6)

	// // file 0x03

	// BLOQUEO:              {FileID: 3, Type: desfire.UINT8, Offset: 0},
	// ConsecutivoTarjeta:   {FileID: 3, Type: desfire.UINT32, Offset: 1},
	// FechaValidezMonedero: {FileID: 3, Type: desfire.UINT32, Offset: 5},

	datafile_03 := make([]byte, 9)
	offset = 0
	for i, v := range []byte{0x00} {
		datafile_03[i+offset] = v
	}
	offset = 1
	for i, v := range []byte{0x00, 0x00, 0x00, 0x00} {
		datafile_03[i+offset] = v
	}
	offset = 5
	for i, v := range []byte{0x00, 0x00, 0x00, 0x00} {
		datafile_03[i+offset] = v
	}
	if err := d.WriteData(0x03, ev2.TargetPrimaryApp, 0x00, datafile_03,
		ev2.FULL); err != nil {
		log.Fatalf("WriteData 03 error: %s", err)
	}

	dataRecord_01 := make([]byte, 32)
	// dataRecord_01[0] = 0x20

	for i := range []int{1, 2, 3} {
		if err := d.WriteRecord(0x06, ev2.TargetPrimaryApp, 0x00, dataRecord_01,
			ev2.FULL); err != nil {
			log.Fatalf("WriteRecord 06 (%d) error: %s", i, err)

		}
		if data, err := d.CommitTransaction(true); err != nil {
			log.Fatalf("CommitTransaction error: %s", err)
		} else {
			log.Printf("CommitTransaction: %X, len: %d", data, len(data))
		}
	}
	for i := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9} {
		// dataRecord_01[0] = byte(i)
		if err := d.WriteRecord(0x07, ev2.TargetPrimaryApp, 0x00, dataRecord_01,
			ev2.FULL); err != nil {
			log.Fatalf("WriteRecord 07 (%d) error: %s", i, err)
		}
		if data, err := d.CommitTransaction(true); err != nil {
			log.Fatalf("CommitTransaction error: %s", err)
		} else {
			log.Printf("CommitTransaction: %X, len: %d", data, len(data))
		}
	}

	if data, err := d.ReadData(0x02, ev2.TargetPrimaryApp, 0x00, 0x00,
		ev2.MAC); err != nil {
		log.Fatalf("ReadData error: %s", err)
	} else {
		log.Printf("ReadData file 02: %X, len: %d", data, len(data))
	}

	if data, err := d.ReadData(0x03, ev2.TargetPrimaryApp, 0x00, 0x00,
		ev2.MAC); err != nil {
		log.Fatalf("ReadData error: %s", err)
	} else {
		log.Printf("ReadData file 03: %X, len: %d", data, len(data))
	}

	if data, err := d.GetValue(0x05, ev2.TargetPrimaryApp,
		ev2.FULL); err != nil {
		log.Fatalf("GetValue error: %s", err)
	} else {

		dataInt := binary.LittleEndian.Uint32(data[:4])
		log.Printf("GetValue: %d, %X, len: %d", dataInt, data, len(data))
	}

	if data, err := d.ReadRecords(0x07, ev2.TargetPrimaryApp, 0x00, 0x00, 32,
		ev2.FULL); err != nil {
		log.Fatalf("ReadRecords error: %s", err)
	} else {
		log.Printf("ReadRecords 06: %X, len: %d", data, len(data))
	}
	if data, err := d.ReadRecords(0x06, ev2.TargetPrimaryApp, 0x00, 0x00, 32,
		ev2.FULL); err != nil {
		log.Fatalf("ReadRecords error: %s", err)
	} else {
		log.Printf("ReadRecords 07: %X, len: %d", data, len(data))
	}

	// auth con la app seleccionada
	authApp7, err := d.AuthenticateEV2First(0, int(keyPublic), nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	authApp8, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], authApp7)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authApp8)

	if data, err := d.ReadData(0x01, ev2.TargetPrimaryApp, 0x00, 0x00,
		ev2.MAC); err != nil {
		log.Fatalf("ReadData error: %s", err)
	} else {
		log.Printf("ReadData file 01: %s, len: %d", data, len(data))
	}

}
