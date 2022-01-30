package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/nmelo/smartcard/multiiso"
)

var port string
var speed int
var mode int

func init() {
	flag.StringVar(&port, "port", "/dev/ttymxc4", "port serial device")
	flag.IntVar(&speed, "speed", 460800, "port serial speed in bauds")
	flag.IntVar(&mode, "mode", 0, "modeo protocol (ascii(1) / binary(0))")
}
func main() {
	flag.Parse()
	dev, err := multiiso.NewDevice(port, speed, time.Millisecond*3000)
	if err != nil {
		log.Fatalln(err)
	}

	reader := multiiso.NewReader(dev, "sam-reader", 1)

	reader.SetModeProtocol(mode)

	resp, err := reader.Transmit([]byte("v"), nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("RESP initial: [ %s ]\n", resp)

	defer func() {

		data2 := []byte{00, 0x92, 0x00, 0x10, 0x11, 00}
		// data2 := []byte{00, 0x02, 0x10, 0x11}
		resp2, err := reader.SendSAMDataFrameTransfer(data2)
		if err != nil {
			log.Println(err)
		}

		log.Printf("RESP DEFER: [ %X ]\n", resp2)
	}()

	trama1 := []byte{00, 0x91, 0x00, 0x10, 0x11, 00}
	resp1, err := reader.SendSAMDataFrameTransfer(trama1)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("RESP ATR: [ %X ], %s\n", resp1, resp1)

	timeout := byte(0x11)
	FD := byte(0x86)

	trama2 := []byte{0x04, 0xE0, 0x00, timeout, 0x11, 0x04, 0xFF, 0x11, FD}
	// trama2 := []byte{0x04, 0xA0, 0x00, 0x00, 0x11, 0x04, 0xFF, 0x11, 0x18}
	csum := byte(0)

	for _, v := range trama2[len(trama2)-3:] {
		csum ^= v
	}
	trama2 = append(trama2, csum)
	log.Printf("TRAMA to send PPS: [ %X ]\n", trama2)

	// trama2 := []byte{0x04, 0xE0, 0x00, 0x13, 0x11, 0x04, 0xFF, 0x11, 0x01, 0xEF}
	resp2, err := reader.SendSAMDataFrameTransfer(trama2)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("RESP PPS: [ %X ]\n", resp2)

	data := []byte{0x80, 0x60, 0x00, 0x00, 0x00}

	trama := make([]byte, 0)

	trama = append(trama, byte(len(data)&0xFF))
	trama = append(trama, 0xDF)                    // APDU T=1 Transaction. OptionByte V2
	trama = append(trama, byte(len(data)>>8&0xFF)) // Downlink length MSB (1 byte)
	trama = append(trama, timeout)                 // Timeout
	trama = append(trama, FD)                      // Transmission factor byte (1 byte)
	trama = append(trama, 0x00)                    // Return length

	trama = append(trama, data...)

	t1 := time.Now()
	resp3, err := reader.SendSAMDataFrameTransfer(trama)
	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("RESP GETVERSION: [ %X ], diff time: %d\n", resp3, time.Since(t1).Milliseconds())

	fmt.Println("FIN")

}
