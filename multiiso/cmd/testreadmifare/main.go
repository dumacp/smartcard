package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/dumacp/smartcard/multiiso"
)

var port string
var speed int
var mode int

func init() {
	flag.StringVar(&port, "port", "/dev/tty4", "port serial device")
	flag.IntVar(&speed, "speed", 115200, "port serial speed in bauds")
	flag.IntVar(&mode, "mode", 0, "modeo protocol (ascii(0) / binary(1))")
}
func main() {
	flag.Parse()
	dev, err := multiiso.NewDevice(port, speed, time.Millisecond*300)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "lectora iso", 1)

	mreader, err := multiiso.NewReaderMClassic(reader)
	if err != nil {
		log.Fatalln(err)
	}

	resp1, err := mreader.ReadBlocks(0, 1)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("response: [% X]", resp1)
}
