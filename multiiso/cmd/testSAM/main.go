package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/dumacp/smartcard/multiiso"
	"github.com/dumacp/smartcard/nxp/mifare/samav2"
)

var port string
var speed int
var mode int

func init() {
	flag.StringVar(&port, "port", "/dev/ttyS4", "port serial device")
	flag.IntVar(&speed, "speed", 460800, "port serial speed in bauds")
	flag.IntVar(&mode, "mode", 0, "modeo protocol (ascii(1) / binary(0))")
}
func main() {
	flag.Parse()
	dev, err := multiiso.NewDevice(port, speed, time.Millisecond*900)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "sam-reader", 1)

	resp, err := reader.Transmit([]byte("v"), nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("RESP: [ %X ]\n", resp)

	data0 := []byte{00, 0xD2, 0x00, 0x13, 0x11, 00}

	resp0, err := reader.Transmit([]byte{0x65}, data0)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("RESP: [ %X ], [ %s ]\n", resp0, resp0)

	data1 := []byte{0x65, 00, 0xD1, 0x00, 0x13, 0x11, 00}
	resp1, err := reader.Transmit(data1, nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("RESP: [ %X ], [ %s ]\n", resp1, resp1)

	samAv2, err := samav2.ConnectSamAv2(reader)
	if err != nil {
		log.Fatalln(err)
	}

	samAtr, err := samAv2.ATR()
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("ATR: [ %X ]\n", samAtr)

	samUID, err := samAv2.UID()
	if err != nil {
		log.Panicln(err)
	}
	log.Printf("sam UID: [% X]", samUID)

	// reader := multiiso.NewMifareClassicReader(dev, "lectora iso", 1)
	// if mode > 0 {
	// 	reader.SetModeProtocol(mode)
	// }

	// resp1, err := reader.Transmit([]byte("v"), nil)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// fmt.Printf("response: [% X]\n", resp1)
	// fmt.Printf("response: [%q]\n", resp1)

	// resp2, err := mifare.ConnectMclassic(reader)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// fmt.Printf("response: [% X]\n", resp2)

	fmt.Println("FIN")

}
