package isoserial

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
	sentencesFilter := make([]string, 0)
	sentencesFilter = append(sentencesFilter, filters...)
	s, err := serial.OpenPort(config)
	if err != nil {
		return nil, err
	}
	dev := &Device{
		port:   s,
		filter: sentencesFilter,
		ok:     true,
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
		funcerr := func() {
			log.Println(err)
			if countError > 3 {
				dev.Close()
				return
			}
			time.Sleep(1 * time.Second)
			countError++
		}
		bf := bufio.NewReader(dev.port)
		lendata := make([]byte, 2)
		tempb := make([]byte, 1024)
		lenb := 0
		for {
			b, err := bf.ReadByte()
			if err != nil {
				funcerr()
				continue
			}
			countError = 0
			if lenb <= 0 {
				if b == '\x02' {
					tempb[0] = b
					lenb = 1
				}
				continue
			}
			lenb++
			tempb[lenb] = b
			if lenb < 6 {
				continue
			}
			if b == '\x03' && (lenb >= int(empb[2])+5) {
				ch <- tempb[0:lenb]
				lenb = 0
			}
		}
	}()
	log.Println("reading port")
	return ch
}
