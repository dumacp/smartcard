package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dumacp/go-appliance-contactless/business/card/mifareplus"
	"github.com/dumacp/smartcard/nxp/mifare"
	"github.com/dumacp/smartcard/nxp/mifare/samav3"
	"github.com/dumacp/smartcard/pcsc"
)

func main() {

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

	var readerSAM pcsc.Reader
	for i, r := range readers {
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "SAM") {
			readerSAM = pcsc.NewReader(ctx, r)
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

	// dev, err := multiiso.NewDevice("/dev/ttyUSB0", 115200, 300*time.Millisecond)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// reader := multiiso.NewReader(dev, "multiiso", 1)

	//cardi, err := reader.ConnectSamCard()
	cardi, err := readerSAM.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	sam := samav3.SamAV3(cardi)

	// keyMaster := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	keyMaster := make([]byte, 16)
	if resp, err := sam.AuthHost(keyMaster, 0, 0, 0); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("Auth SAM resp: [% X]", resp)
	}

	cardp, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	cardo := mifare.Mplus(cardp)
	cardm := mifareplus.NewCard(cardo, sam)

	atr, err := cardm.ATR()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ATR: [% X], %s", atr, atr)

	if err := cardm.Auth(0x4040, 11); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("SUCESS AUTH")

		name := []byte("Leon Dario Garcia")
		for len(name)%32 != 0 {
			name = append(name, 0x00)
		}
		docID := []byte("9876543210")
		for len(docID)%16 != 0 {
			docID = append(docID, 0x00)
		}
		log.Printf("SUCESS AUTH")
		cardid := uint32(423155168)
		cardidbytes := make([]byte, 16)
		binary.LittleEndian.PutUint32(cardidbytes[0:4], cardid)

		b132bytes := make([]byte, 16)
		//perfil
		b132bytes[0] = byte(0)
		//version
		b132bytes[1] = byte(1)
		//prm
		b132bytes[2] = byte(0)
		//ac
		b132bytes[3] = byte(0)

		b133bytes := make([]byte, 16)
		//bloqueo
		b133bytes[0] = byte(0)
		//fecha bloqueo
		binary.LittleEndian.PutUint32(b133bytes[1:5], 0)

		b138bytes := make([]byte, 16)
		//fecha recarga
		binary.LittleEndian.PutUint32(b138bytes[0:4], uint32(time.Now().Unix()))
		//CONSECUTIVO recarga
		binary.LittleEndian.PutUint32(b138bytes[4:8], uint32(12345))
		//valor recargA
		binary.LittleEndian.PutUint32(b138bytes[8:12], uint32(100000))
		//id dev recarga
		iddev := make([]byte, 4)
		binary.LittleEndian.PutUint32(iddev, uint32(12345))
		b138bytes[12] = iddev[0]
		b138bytes[13] = iddev[1]
		b138bytes[14] = iddev[2]
		b138bytes[15] = byte(3)

		b139bytes := make([]byte, 16)
		//fecha recarga
		binary.LittleEndian.PutUint32(b139bytes[0:4], uint32(time.Now().Add(24*365*time.Hour).Unix()))

		mapdata := map[int][]byte{
			128: name,
			130: docID,
			131: cardidbytes,
			132: b132bytes,
			133: b133bytes,
			134: {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00},
			135: {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00},
			136: {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00},
			138: b138bytes,
			139: b139bytes,
			140: make([]byte, 16),
			141: make([]byte, 16),
			142: make([]byte, 16),
		}

		for k, v := range mapdata {
			//log.Printf("block: %d, len: %d, data: %X", k, len(v)/16, v)
			if resp0, err := cardm.Blocks(k, len(v)/16); err == nil {
				log.Printf("blocks %d: len = %d, [% X]", k, len(resp0), resp0)
				if err := cardm.WriteBlock(k, v); err != nil {
					log.Fatal(err)
				}
			} else {
				log.Fatal(err)
			}
			fmt.Printf("\n\n")
		}
		if err := cardm.Inc(134, 2000000); err != nil {
			log.Fatal(err)
		}
		if err := cardm.Inc(135, 2000000); err != nil {
			log.Fatal(err)
		}
	}
}
