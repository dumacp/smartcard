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

	"github.com/dumacp/smartcard"
	"github.com/tarm/serial"
)

// Device struct
type Device struct {
	port    *serial.Port
	Ok      bool
	mux     sync.Mutex
	timeout time.Duration
	chRecv  chan []byte
	chQuit  chan int
	mode    int
}

// NewDevice create new serial device
func NewDevice(portName string, baudRate int, timeout time.Duration) (*Device, error) {
	log.Println("port serial config ...")
	config := &serial.Config{
		Name: portName,
		Baud: baudRate,
		//TODO if change, change funcerr
		// ReadTimeout: 1 * time.Second,
	}
	if timeout < 1*time.Second {
		config.ReadTimeout = 1 * time.Second
	} else {
		config.ReadTimeout = timeout + 300*time.Millisecond
	}
	s, err := serial.OpenPort(config)
	if err != nil {
		return nil, err
	}

	dev := &Device{
		port:    s,
		Ok:      true,
		timeout: timeout,
		// chQuit:  make(chan int),
	}
	chQuit := make(chan int)
	dev.chQuit = chQuit
	dev.read()
	log.Println("port serial Open!")
	return dev, nil
}

// Close close serial device
func (dev *Device) Close() bool {
	dev.Ok = false
	close(dev.chQuit)
	if err := dev.port.Close(); err != nil {
		log.Printf("close err: %s", err)
		return false
	}
	return true
}

// Read read serial device with a channel
func (dev *Device) read() {
	if !dev.Ok {
		// log.Printf("Device is closed === %s", dev)
		return
	}
	dev.chRecv = make(chan []byte)
	go func() {
		defer func() {
			select {
			case _, ok := <-dev.chRecv:
				if !ok {
					// log.Println("=== chRecv closed ===")
					return
				}
			default:
			}
			close(dev.chRecv)
			log.Println("finish read port")
		}()
		countError := 0
		//TODO timeoutRead?
		funcerr := func(err error) error {
			if err == nil {
				return nil
			}
			log.Printf("funcread err: %s", err)
			switch {
			case errors.Is(err, os.ErrClosed):
				dev.Ok = false
				return err
			case errors.Is(err, io.ErrClosedPipe):
				dev.Ok = false
				return err
			case errors.Is(err, io.EOF):
				if countError > 3 {
					if !dev.Ok {
						return err
					}
					countError = 0
				}
				countError++
			}

			return nil

			// if countError > 3 {
			// dev.Ok = false
			// return err
			// }
			// time.Sleep(1 * time.Second)
			// countError++
			// return nil
		}
		bf := bufio.NewReader(dev.port)
		tempb := make([]byte, 1024)
		// buff := make([]byte, 1)
		indxb := 0
		for {
			if !dev.Ok {
				// log.Printf("Device is closed === %s  ######", dev)
				return
			}
			// log.Println("0")
			// if dev.mode != 0 {
			// 	line, _, err := bf.ReadLine()
			// 	if err != nil {
			// 		if err := funcerr(err); err != nil {
			// 			return
			// 		}
			// 		continue
			// 	}
			// 	countError = 0
			// 	select {
			// 	case <-dev.chQuit:
			// 		return
			// 	case dev.chRecv <- line:
			// 	case <-time.After(1 * time.Second):
			// 	}
			// 	continue
			// }
			b, err := bf.ReadByte()
			if err != nil {
				if err := funcerr(err); err != nil {
					// log.Printf("0, err: %s", err)
					return
				}
				continue
			}
			// var b byte
			// if n > 0 {
			// 	b = buff[0]
			// } else {
			// 	continue
			// }
			// log.Printf("0, err: %s, [% X]", err, buff[:n])
			// if err != nil {
			if err := funcerr(err); err != nil {
				return
			}
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
			// log.Println("2")
			if b == '\x03' && (indxb >= int(tempb[2])+5) {
				// fmt.Printf("tempb final: [% X]\n", tempb[:indxb])
				select {
				case <-dev.chQuit:
					// log.Println("3")
					return
				case dev.chRecv <- tempb[0:indxb]:
					// fmt.Printf("tempb final: [% X]\n", tempb[:])
				case <-time.After(1 * time.Second):
				}
				indxb = 0
			}
		}
	}()
	log.Println("reading port")
}

// Send write data bytes in serial device
func (dev *Device) Send(data []byte) (int, error) {
	dev.mux.Lock()
	defer dev.mux.Unlock()
	n, err := dev.port.Write(data)

	return n, err
}

// SendRecv write daa bytes in serial device and wait by response
func (dev *Device) SendRecv(data []byte) ([]byte, error) {
	dev.mux.Lock()
	defer dev.mux.Unlock()
	buff := make([]byte, 0)
	buff = append(buff, data[:]...)

	// log.Printf("data send: [% X]", data)
	if n, err := dev.port.Write(buff); err != nil {
		return nil, err
	} else if n <= 0 {
		return nil, fmt.Errorf("dont write in SendRecv command, %w", smartcard.ErrComm)
	}
	select {
	case v, ok := <-dev.chRecv:
		if !ok {
			return nil, fmt.Errorf("close channel in dev")
		}
		recv := make([]byte, 0)
		if len(v) > 0 {
			recv = append(recv, v...)
		}
		return recv, nil
	case <-time.After(dev.timeout):
		return nil, fmt.Errorf("timeout error in SendRecv command, %w", smartcard.ErrComm)
	}
}

// Recv read data bytes in serial device
func (dev *Device) Recv() ([]byte, error) {
	var recv []byte
	select {
	case recv = <-dev.chRecv:
	case <-time.After(dev.timeout):
	}
	if recv == nil || len(recv) <= 0 {
		return nil, fmt.Errorf("timeout error in Recv command, %w", smartcard.ErrComm)
	}
	return recv[:], nil
}
