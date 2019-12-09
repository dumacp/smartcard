package main

import (
	"encoding/hex"
	"flag"
	"log"
	"strings"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/nxp/mifare"
)

var op string
var bloq int
var keytype int
var data string
var key string
var isdatastring bool

func init() {
	flag.StringVar(&op, "op", "read", "operation in card: \"write\" or \"read\"")
	flag.IntVar(&bloq, "block", 0, "block to apply operation")
	flag.StringVar(&data, "data", "00000000000000000000000000000000", "data to write (hextring)")
	flag.StringVar(&key, "key", "000000000000", "key to Auth (hexstring)")
	flag.IntVar(&keytype, "keytype", 0, "key type")
	flag.BoolVar(&isdatastring, "isdatastring", false, "Is the data in string? / default: Not (false), it's in hexstring")
}

func main() {
	flag.Parse()

	ctx, err := smartcard.NewContext()
	if err != nil {
		log.Fatalln(err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatalln(err)
	}
	for i, v := range readers {
		log.Printf("reader %v: %v", i, v)
	}

	findPicc := func(listreaders []string) string {
		for _, v := range listreaders {
			if strings.Contains(v, "PICC") {
				return v
			}
		}
		return ""
	}

	picc := findPicc(readers)
	if len(picc) <= 0 {
		log.Fatalln("dont exist a PICC reader")
	}

	reader := smartcard.NewReader(ctx, picc)

	card, err := mifare.ConnectMclassic(reader)
	if err != nil {
		log.Fatalln(err)
	}

	keyB, err := hex.DecodeString(key)
	if err != nil {
		log.Fatal(err)
	}

	if len(keyB) != 6 {
		log.Fatalln("incorrect key len")
	}

	switch op {
	case "read":
		respAuth, err := card.Auth(bloq, keytype, keyB)
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("result Auth: [% X]", respAuth)
		respRead, err := card.ReadBlocks(bloq, 16)
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("result Read: [% X]", respRead)
		log.Printf("result Read in STRING: %s", respRead[:len(respRead)-2])
	case "write":

		var dataB []byte
		if !isdatastring {
			dataB, err = hex.DecodeString(data)
			if err != nil {
				log.Fatal(err)
			}
			if len(dataB) > 16 {
				log.Fatalf("incorrect len data: %v", len(dataB))
			}
			res := len(dataB) % 16
			if res != 0 {
				for i := 0; i < 16-res; i++ {
					dataB = append(dataB, byte(0))
				}
			}
		} else {
			dataB = []byte(data)
			if len(dataB) > 16 {
				log.Fatalf("incorrect len data: %v", len(dataB))
			}
			res := len(dataB) % 16
			if res != 0 {
				for i := 0; i < 16-res; i++ {
					dataB = append(dataB, byte(32))
				}
			}
		}
		respAuth, err := card.Auth(bloq, keytype, keyB)
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("result Auth: [% X]", respAuth)
		respWrite, err := card.WriteBlock(bloq, dataB)
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("result write: [% X]", respWrite)

	default:
	}
}
