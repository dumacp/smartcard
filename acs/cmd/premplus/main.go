package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"

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

	cardo, err := mifare.ConnectMplus(reader)
	if err != nil {
		log.Fatal(err)
	}

	sam, err := samav3.ConnectSam(readerSAM)

	if resp, err := sam.AuthHost(make([]byte, 16), 0, 0, 0); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("Auth SAM resp: [% X]", resp)
	}

	cardm := mifareplus.NewCard(cardo, sam)

	atr, err := cardm.ATR()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ATR: [% X], %s", atr, atr)

	if err := cardm.Auth(0x4040, 2); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("SUCESS AUTH")

		name := []byte("CAMILO ANDRES ZAPATA TORRES")
		for len(name)%32 != 0 {
			name = append(name, 0x00)
		}
		cardid := uint32(423155167)
		cardidbytes := make([]byte, 16)
		binary.LittleEndian.PutUint32(cardidbytes, cardid)
		mapdata := map[int][]byte{
			128: name,
			130: cardidbytes,
			131: {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00},
			132: {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00},
			133: {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00},
			134: make([]byte, 16),
			135: make([]byte, 16),
			136: make([]byte, 16),
			137: make([]byte, 16),
			138: make([]byte, 16),
			139: make([]byte, 16),
			140: make([]byte, 16),
			141: make([]byte, 16),
			142: make([]byte, 16),
		}

		for k, v := range mapdata {
			log.Printf("block: %d, len: %d, data: %X", k, len(v)/16, v)
			if resp0, err := cardm.Blocks(k, len(v)/16); err == nil {
				log.Printf("blocks: len = %d, [% X]", len(resp0), resp0)
				if err := cardm.WriteBlock(k, v); err != nil {
					log.Fatal(err)
				}
			} else {
				log.Fatal(err)
			}
			fmt.Printf("\n\n\n\n\n")
		}
	}
}
