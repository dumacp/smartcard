package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

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

	if !strings.Contains(string(resp1), "ISO") {
		log.Fatalln("already conf reader")
	}

	resp2, err := reader.GetRegister(0x0B)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x0B: [% X]\n", resp2)
	err = reader.SetRegister(0x0B, []byte{0xC2})

	resp2, err = reader.GetRegister(0x0C)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x0C: [% X]\n", resp2)
	err = reader.SetRegister(0x0C, []byte{0x06})

	resp2, err = reader.GetRegister(0x11)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x11: [% X]\n", resp2)
	err = reader.SetRegister(0x11, []byte{0x00})

	resp2, err = reader.GetRegister(0x10)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x10: [% X]\n", resp2)
	err = reader.SetRegister(0x10, []byte{0xA0})

	resp2, err = reader.GetRegister(0x14)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x14: [% X]\n", resp2)
	err = reader.SetRegister(0x14, []byte{0x08})

	resp2, err = reader.GetRegister(0x15)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x15: [% X]\n", resp2)
	err = reader.SetRegister(0x15, []byte{0x0A})

	resp2, err = reader.GetRegister(0x1B)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x1B: [% X]\n", resp2)
	err = reader.SetRegister(0x14, []byte{0x80})

	reader.Transmit([]byte("x"), nil)

	fmt.Println("FIN")

}
