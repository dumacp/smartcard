package multiiso

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/tarm/serial"
)

//Device struct
type Device struct {
	port    *serial.Port
	Ok      bool
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
		Ok:      true,
		timeout: timeout,
	}
	dev.read()
	log.Println("port serial Open!")
	return dev, nil
}

//Close close serial device
func (dev *Device) Close() bool {
	dev.Ok = false
	if err := dev.port.Close(); err != nil {
		log.Printf("close err: %s", err)
		return false
	}
	return true
}

//Read read serial device with a channel
func (dev *Device) read() {
	if !dev.Ok {
		log.Println("Device is closed")
		return
	}
	dev.chRecv = make(chan []byte, 0)
	go func() {
		defer func() {
			select {
			case _, ok := <-dev.chRecv:
				if !ok {
					break
				}
			default:
				close(dev.chRecv)
			}
		}()
		countError := 0
		funcerr := func(err error) error {
			log.Printf("funcread err: %s", err)
			if errors.Is(err, os.ErrClosed) {
				dev.Ok = false
				return err
			}
			if errors.Is(err, io.ErrClosedPipe) {
				dev.Ok = false
				return err
			}

			if countError > 3 {
				dev.Ok = false
				return err
			}
			time.Sleep(1 * time.Second)
			countError++
			return nil
		}
		bf := bufio.NewReader(dev.port)
		tempb := make([]byte, 1024)
		indxb := 0
		for {
			if dev.mode != 0 {
				line, _, err := bf.ReadLine()
				if err != nil {
					if err := funcerr(err); err != nil {
						break
					}
					continue
				}
				countError = 0
				select {
				case dev.chRecv <- line:
				case <-time.After(1 * time.Second):
				}
				continue
			}
			b, err := bf.ReadByte()
			if err != nil {
				if err := funcerr(err); err != nil {
					break
				}
				continue
			}
			// fmt.Printf("byte: %X\n", b)
			// fmt.Printf("tempb: [% X]\n", tempb[:indxb])
			countError = 0
			if indxb <= 0 {
				if b == '\x02' {
					tempb[0] = b
					indxb = 1
				}
				continue
			}

			tempb[indxb] = b
			indxb++
			// fmt.Printf("len: %v, %v\n", indxb, int(tempb[2])+5)
			if indxb < 6 {
				continue
			}
			if b == '\x03' && (indxb >= int(tempb[2])+5) {
				// fmt.Printf("tempb final: [% X]\n", tempb[:indxb])
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
	recv := make([]byte, 0)
	if n, err := dev.port.Write(data); err != nil {
		return nil, err
	} else if n <= 0 {
		return nil, fmt.Errorf("dont write in SendRecv command")
	}
	select {
	case v, ok := <-dev.chRecv:
		if !ok {
			return nil, fmt.Errorf("close channel in dev")
		}
		if v != nil && len(v) > 0 {
			recv = append(recv, v...)
		}
	case <-time.After(dev.timeout):
	}

	if recv == nil || len(recv) <= 0 {
		return nil, fmt.Errorf("timeout error in SendRecv command")
	}
	return recv, nil
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
