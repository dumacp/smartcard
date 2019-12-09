package multiiso

import (
	"bufio"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/tarm/serial"
)

//Device struct
type Device struct {
	port    *serial.Port
	ok      bool
	mux     sync.Mutex
	timeout time.Duration
	chRecv  chan []byte
	mode    int
}

//NewDevice create new serial device
func NewDevice(portName string, baudRate int, timeout time.Duration) (*Device, error) {
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
		port:    s,
		ok:      true,
		timeout: timeout,
	}
	dev.read()
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
func (dev *Device) read() {
	if !dev.ok {
		log.Println("Device is closed")
		return
	}
	dev.chRecv = make(chan []byte, 0)
	go func() {
		defer close(dev.chRecv)
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
			if dev.mode != 0 {
				line, _, err := bf.ReadLine()
				if err != nil {
					funcerr(err)
					continue
				}
				select {
				case dev.chRecv <- line:
				case <-time.After(1 * time.Second):
				}
				continue
			}
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
				case dev.chRecv <- tempb[0:indxb]:
				case <-time.After(1 * time.Second):
				}
				indxb = 0
			}
		}
	}()
	log.Println("reading port")
}

//Send write data bytes in serial device
func (dev *Device) Send(data []byte) (int, error) {
	dev.mux.Lock()
	defer dev.mux.Unlock()
	n, err := dev.port.Write(data)

	return n, err
}

//SendRecv write daa bytes in serial device and wait by response
func (dev *Device) SendRecv(data []byte) ([]byte, error) {
	dev.mux.Lock()
	defer dev.mux.Unlock()
	var recv []byte
	if n, err := dev.port.Write(data); err != nil {
		return nil, err
	} else if n <= 0 {
		return nil, fmt.Errorf("dont write in SendRecv command")
	}
	select {
	case recv = <-dev.chRecv:
	case <-time.After(dev.timeout):
	}

	if recv == nil || len(recv) <= 0 {
		return nil, fmt.Errorf("timeout error in SendRecv command")
	}
	return recv[:], nil
}

//Recv read data bytes in serial device
func (dev *Device) Recv() ([]byte, error) {
	var recv []byte
	select {
	case recv = <-dev.chRecv:
	case <-time.After(dev.timeout):
	}
	if recv == nil || len(recv) <= 0 {
		return nil, fmt.Errorf("timeout error in Recv command")
	}
	return recv[:], nil
}
