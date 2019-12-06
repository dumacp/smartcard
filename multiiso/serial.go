package multiiso

import (
	"bufio"
	"log"
	"time"

	"github.com/tarm/serial"
)

//Device struct
type Device struct {
	port *serial.Port
	ok   bool
}

//NewDevice create new serial device
func NewDevice(portName string, baudRate int) (*Device, error) {
	log.Println("port serial config ...")
	config := &serial.Config{
		Name: portName,
		Baud: baudRate,
		//ReadTimeout: time.Second * 3,
	}
	s, err := serial.OpenPort(config)
	if err != nil {
		return nil, err
	}
	dev := &Device{
		port: s,
		ok:   true,
	}
	log.Println("port serial Open!")
	return dev, nil
}

//Close close serial device
func (dev *Device) Close() bool {
	dev.ok = false
	if err := dev.port.Close(); err != nil {
		log.Println(err)
		return false
	}
	return true
}

//Read read serial device with a channel
func (dev *Device) Read() chan []byte {

	if !dev.ok {
		log.Println("Device is closed")
		return nil
	}
	ch := make(chan []byte)

	//buf := make([]byte, 128)

	go func() {
		defer close(ch)
		countError := 0
		funcerr := func(err error) {
			log.Println(err)
			if countError > 3 {
				dev.Close()
				return
			}
			time.Sleep(1 * time.Second)
			countError++
		}
		bf := bufio.NewReader(dev.port)
		tempb := make([]byte, 1024)
		indxb := 0
		for {
			b, err := bf.ReadByte()
			if err != nil {
				funcerr(err)
				continue
			}
			countError = 0
			if indxb <= 0 {
				if b == '\x02' {
					tempb[0] = b
					indxb = 0
				}
				continue
			}
			indxb++
			tempb[indxb] = b
			if indxb < 6 {
				continue
			}
			if b == '\x03' && (indxb >= int(tempb[2])+5) {
				select {
				case ch <- tempb[0:indxb]:
				case <-time.After(3 * time.Second):
				}
				indxb = 0
			}
		}
	}()
	log.Println("reading port")
	return ch
}
