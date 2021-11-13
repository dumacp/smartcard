package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

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

	aid := []byte{0x01, 0x00, 0x00}

	keyDefault, err := hex.DecodeString("3ED6B7C6823D442D7783F8B3A0B1C9C659E7D8BDDF7FCD6A")
	if err != nil {
		log.Fatalln(err)
	}
	keyVersion := 0x00

	// keyPublic := ev2.KeyID_0x01
	keyDebito := ev2.KeyID_0x02
	// keyCredito := ev2.KeyID_0x03
	keyOperation := ev2.KeyID_0x04

	keyDefault = append(keyDefault, byte(keyVersion))

	// se selecciona la app 0x0000001 (antes estab seleccionado todo el PICC)
	if err := d.SelectApplication(aid, nil); err != nil {
		log.Fatalf("SelectApplication error: %s", err)
	}

	// auth con la app seleccionada
	authApp, err := d.AuthenticateEV2First(ev2.TargetPrimaryApp, int(keyOperation), nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}

	authApp2, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], authApp)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authApp2)

	datafile_01 := []byte("camilo zapata\n99999999")
	if err := d.WriteData(0x01, ev2.TargetPrimaryApp, 0x00, datafile_01,
		ev2.MAC); err != nil {
		log.Fatalf("WriteData error: %s", err)
	}

	datafile_02 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if err := d.WriteData(0x02, ev2.TargetPrimaryApp, 0x00, datafile_02,
		ev2.FULL); err != nil {
		log.Fatalf("WriteData error: %s", err)
	}

	// auth con la app seleccionada
	authAppDebito, err := d.AuthenticateEV2First(ev2.TargetPrimaryApp, int(keyDebito), nil)
	if err != nil {
		log.Fatalf("AuthenticateEV2First error: %s", err)
	}
	authAppDebito2, err := d.AuthenticateEV2FirstPart2(keyDefault[0:16], authAppDebito)
	if err != nil {
		log.Fatalf("AuthenticateEV2FirstPart2 error: %s", err)
	}

	log.Printf("**** auth APP AES sucess: [% X]", authAppDebito2)

	datafile_03 := []byte(fmt.Sprintf("date: %s", time.Now()))
	if err := d.WriteRecord(0x05, ev2.TargetPrimaryApp, 0x00, datafile_03,
		ev2.FULL); err != nil {
		log.Fatalf("WriteData error: %s", err)
	}

	if err := d.Debit(0x04, ev2.TargetPrimaryApp, uint(1000),
		ev2.FULL); err != nil {
		log.Fatalf("WriteData error: %s", err)
	}

	// if data, err := d.CommitReaderID([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}); err != nil {
	// 	log.Fatalf("CommitReaderID error: %s", err)
	// } else {
	// 	log.Printf("CommitReaderID: %s, len: %d", data, len(data))
	// }

	if data, err := d.CommitTransaction(true); err != nil {
		log.Fatalf("CommitTransaction error: %s", err)
	} else {
		log.Printf("CommitTransaction: %X, len: %d", data, len(data))
	}

	if data, err := d.ReadData(0x01, ev2.TargetPrimaryApp, 0x00, 0x00,
		ev2.MAC); err != nil {
		log.Fatalf("ReadData error: %s", err)
	} else {
		log.Printf("ReadData: %s, lenL %d", data, len(data))
	}

	if data, err := d.ReadRecords(0x05, ev2.TargetPrimaryApp, 0x00, 0x00, 64,
		ev2.FULL); err != nil {
		log.Fatalf("ReadRecords error: %s", err)
	} else {
		log.Printf("ReadRecords: %s, len: %d", data, len(data))
	}

	if data, err := d.GetValue(0x04, ev2.TargetPrimaryApp,
		ev2.FULL); err != nil {
		log.Fatalf("GetValue error: %s", err)
	} else {

		dataInt := binary.LittleEndian.Uint32(data[:4])
		log.Printf("GetValue: %d, %X, len: %d", dataInt, data, len(data))
	}

}
