# smartcard
smartcard devices under the PCSC implementation

Implementation for mifare smartcard family (Mifare Plus, Desfire, SamAV2, ...)

## example 1 (SAMav2)
```
package main

import (
  "log"
  "strings"
  "github.com/nmelo/smartcard"
  "github.com/nmelo/smartcard/nxp/mifare"
)

func main() {
  ctx, err := smartcard.NewContext()
  if err != nil {
    log.Fatal("Not connection")
  }
  defer ctx.Release()
  readers, err := smartcard.ListReaders(ctx)
  for i, el := range readers {
    log.Printf("reader %v: %s\n", i, el)
  }
  samReaders := make([]smartcard.Reader,0)
  for _, el := range readers {
    if strings.Contains(el, "SAM") {
      samReaders = append(samReaders, smartcard.NewReader(ctx, el))
    }
  }
  for _, samReader := range samReaders {
    sam, err := mifare.ConnectSamAv2(samReader)
    if err != nil {
      log.Printf("%s\n",err)
      continue
    }
    version, err := sam.GetVersion()
    if err != nil {
      log.Fatalln("Not GetVersion: ", err)
    }
    log.Printf("GetVersion sam: % X\n", version)
  }
}
```
## example 2 (Mifare Plus SL3 auth)
```
package main

import (
	"log"
	"flag"
	"strings"
	"encoding/hex"
	"github.com/nmelo/smartcard"
	"github.com/nmelo/smartcard/nxp/mifare"
)

var keyS string
var keyNbr int

func init() {
        flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
        flag.IntVar(&keyNbr, "keyNbr", 0x4002, "key Number")
}

func main() {
	flag.Parse()

	key, err := hex.DecodeString(keyS)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("key: [% X]\n", key)

	ctx, err := smartcard.NewContext()
	if err != nil {
		log.Fatal("Not connection")
	}
	defer ctx.Release()
	readers, err := smartcard.ListReaders(ctx)
	for i, el := range readers {
		log.Printf("reader %v: %s\n", i, el)
	}
	mplusReaders := make([]smartcard.Reader,0)
	for _, el := range readers {
		if strings.Contains(el, "PICC") {
			mplusReaders = append(mplusReaders, smartcard.NewReader(ctx, el))
		}
	}
	for _, mplusReader := range mplusReaders {
		mplus, err := mifare.ConnectMplus(mplusReader)
		if err != nil {
			log.Printf("%s\n",err)
			continue
		}
		uid, err := mplus.UID()
		if err != nil {
			log.Fatalln("ERROR: ", err)
		}
		log.Printf("card UID: % X\n", uid)

		ats, err := mplus.ATS()
		if err != nil {
			log.Println("ERROR: ", err)
		}
		log.Printf("card ATS: % X\n", ats)

		resp, err := mplus.FirstAuth(keyNbr,key)
		if err != nil {
			log.Fatalf("Error: %s\n",err)
		}
		log.Printf("Auth: % X\n", resp)
	}
}
```
