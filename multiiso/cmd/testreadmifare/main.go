package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/dumacp/smartcard/nxp/mifare"

	"github.com/dumacp/smartcard/multiiso"
)

var port string
var speed int
var mode int

func init() {
	flag.StringVar(&port, "port", "/dev/tty4", "port serial device")
	flag.IntVar(&speed, "speed", 115200, "port serial speed in bauds")
	flag.IntVar(&mode, "mode", 0, "modeo protocol (ascii(1) / binary(0))")
}
func main() {
	flag.Parse()
	dev, err := multiiso.NewDevice(port, speed, time.Millisecond*900)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewMifareClassicReader(dev, "lectora iso", 1)
	if mode > 0 {
		reader.SetModeProtocol(mode)
	}

	resp1, err := reader.Transmit([]byte("v"), nil)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("response: [% X]\n", resp1)
	fmt.Printf("response: [%q]\n", resp1)

	resp2, err := mifare.ConnectMclassic(reader)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("response: [% X]\n", resp2)

	fmt.Println("FIN")

}
