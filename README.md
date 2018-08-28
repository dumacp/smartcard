# smartcard
smartcard devices under the PCSC implementation

Implementation for mifare smartcard family (Mifare Plus, Desfire, SamAV2, ...)

## example
```
package main

import (
  "log"
  "strings"
  "github.com/dumacp/smartcard"
  "github.com/dumacp/smartcard/nxp/mifare"
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
