package main

import (
	"log"
	"strings"

	"github.com/dumacp/smartcard/nxp/mifare/desfire/ev2"
	"github.com/dumacp/smartcard/nxp/mifare/samav2"
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

	aidPICC := []byte{0x01, 0x00, 0x00}

	err = d.SelectApplication(aidPICC, nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("SelectApplication")

	keyPublic := ev2.KeyID_0x02
	keyDebito := ev2.KeyID_0x03
	keyCredito := ev2.KeyID_0x04
	keyOperation := ev2.KeyID_0x01
	keyAppMaster := ev2.KeyID_0x00

	keySAMPublic := 32
	keySAMDebito := 33
	keySAMCredito := 34
	keySAMOperation := 31
	keySAMAppMaster := 30

	keyIndexes := map[int]int{
		int(keyAppMaster): keySAMAppMaster,
		int(keyOperation): keySAMOperation,
		int(keyPublic):    keySAMPublic,
		int(keyDebito):    keySAMDebito,
		int(keyCredito):   keySAMCredito,
	}

	for key_picc, key_sam := range keyIndexes {

		respAuth, err := d.AuthenticateEV2First(ev2.TargetPrimaryApp, key_picc, nil)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("AuthenticateEV2First")
		_, err = samCard.ActivateOfflineKey(key_sam, 0, divData)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("ActivateOfflineKey")

		rndB, err := samCard.SAMDecipherOfflineData(samav2.AES_ALG, respAuth[1:])
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("SAMDecipherOfflineData")

		rndD, err := d.AuthenticateEV2FirstPart2_block_1(rndB)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("AuthenticateEV2FirstPart2_block_1")
		rndDc, err := samCard.SAMEncipherOfflineData(samav2.AES_ALG, rndD)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("SAMEncipherOfflineData")
		lastResponse, err := d.AuthenticateEV2FirstPart2_block_2(rndDc)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("AuthenticateEV2FirstPart2_block_2")
		lastResponseD, err := samCard.SAMDecipherOfflineData(samav2.AES_ALG, lastResponse[:])
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("SAMDecipherOfflineData")
		sv1, sv2, err := d.AuthenticateEV2FirstPart2_block_3(lastResponseD)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("AuthenticateEV2FirstPart2_block_3")
		ksesAuthEnc, err := samCard.SAMGenerateMAC(samav2.AES_ALG, sv1)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("SAMGenerateMAC")
		ksesAuthMac, err := samCard.SAMGenerateMAC(samav2.AES_ALG, sv2)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("SAMGenerateMAC")
		if err := d.AuthenticateEV2FirstPart2_block_4(ksesAuthEnc, ksesAuthMac); err != nil {
			log.Fatalln(err)
		}

		if key_picc == int(keyDebito) {
			data, err := d.ReadData(0x02, ev2.TargetPrimaryApp, 0x00, 0x00, ev2.FULL)
			log.Println("/////////////////////////////////////////////////////")
			if err != nil {
				log.Printf("error read: %s", err)
			} else {
				log.Printf("data read: %s, %X", data, data)
			}
			log.Println("/////////////////////////////////////////////////////")
		}

		log.Printf("AUTH SUCESSSSSSSSSSSSSSSSSS, key -> %d", key_picc)
	}

}
