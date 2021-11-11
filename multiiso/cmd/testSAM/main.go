package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/dumacp/smartcard/multiiso"
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
	log.Printf("RESP: [ %s ]\n", resp)

	resp, err = reader.Transmit([]byte("poff"), nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("RESP: [ %s ]\n", resp)
	resp, err = reader.Transmit([]byte("pon"), nil)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("RESP: [ %s ]\n", resp)

	resp_0D, err := reader.GetRegister(0x0B)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("0x1E: [% X]\n", resp_0D)

	// err = reader.SetRegister(0x0B, []byte{0xC0})
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// _, err = reader.Transmit([]byte("x"), nil)
	// if err != nil {

	// 	log.Fatalln(err)
	// 	return
	// }

	defer func() {
		data1 := []byte{00, 0x93, 0x00, 0x10, 0x00, 00}
		resp1, err := reader.SendSAMDataFrameTransfer(data1)
		if err != nil {
			log.Println(err)
		}
		log.Printf("RESP DEFER: [ %X ], [ %s ]\n", resp1, resp1)
		data2 := []byte{00, 0x92, 0x00, 0x10, 0x00, 00}
		// data2 := []byte{00, 0x02, 0x10, 0x11}
		resp2, err := reader.SendSAMDataFrameTransfer(data2)
		if err != nil {
			log.Println(err)
		}
		// resp, err = reader.Transmit([]byte("x"), nil)
		// if err != nil {
		// 	log.Println(err)
		// }

		log.Printf("RESP DEFER: [ %X ], [ %s ]\n", resp2, resp2)
	}()

	// trama3 := []byte{00, 0x81, 0x00, 0x10, 0x11, 00}
	// if _, err := reader.SendSAMDataFrameTransfer(trama3); err != nil {
	// 	log.Println(err)
	// 	return
	// }

	// data0 := []byte{00, 0x01, 0x10, 0x11}

	var resp0 []byte
	count := 0
	for {
		data0 := [][]byte{
			{00, 0x92, 0x00, 0x10, 0x11, 00},
			{00, 0x91, 0x00, 0x10, 0x11, 00},
			{00, 0x93, 0x00, 0x10, 0x11, 00},
			{00, 0x96, 0x00, 0x10, 0x11, 00},
			{00, 0x96, 0x00, 0x10, 0x11, 00},
			{00, 0x96, 0x00, 0x10, 0x11, 00},
			{00, 0x96, 0x00, 0x10, 0x11, 00},
		}

		rand.Seed(time.Now().UnixNano())
		idx := rand.Intn(len(data0))
		resp0, err = reader.SendSAMDataFrameTransfer(data0[idx])
		if err != nil {
			time.Sleep(300 * time.Millisecond)
			count += 1
			if count%9 == 0 {
				resp, err = reader.Transmit([]byte("pon"), nil)
				if err != nil {
					log.Fatalln(err)
				}
				log.Printf("RESP: [ %s ]\n", resp)
				resp, err = reader.Transmit([]byte("poff"), nil)
				if err != nil {
					log.Fatalln(err)
				}
				log.Printf("RESP: [ %s ]\n", resp)
			}
			continue
		}
		break
	}

	log.Printf("RESP: [ %X ],\nascii: %s\n", resp0, resp0)
	time.Sleep(2 * time.Second)

	// data2 := []byte{0x04, 0xE0, 0x00, 0x13, 0x11, 0x04, 0xFF, 0x11, 0x86, 0x68}
	data2 := []byte{0x04, 0xE0, 0x00, 0x13, 0x11, 0x04, 0xFF, 0x11, 0x01, 0xEF}
	resp2, err := reader.SendSAMDataFrameTransfer(data2)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("RESP: [ %X ], [ %s ]\n", resp2, resp2)

	// card, err := reader.ConnectSamCard()
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	// samAv2 := samav2.SamAV2(card)

	// samAtr, err := samAv2.ATR()
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Printf("ATR: [ %X ]\n", samAtr)

	// samUID, err := samAv2.UID()
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// fmt.Printf("sam UID: [% X]\n", samUID)

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
