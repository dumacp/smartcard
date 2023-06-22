package acr128s

import (
	"bytes"
	"context"
	"encoding/binary"
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
	mux     sync.Mutex
	timeout time.Duration
}

// NewDevice create new serial device
func NewDevice(portName string, baudRate int, timeout time.Duration) (*Device, error) {
	log.Println("port serial config ...")
	config := &serial.Config{
		Name: portName,
		Baud: baudRate,
		//TODO if change, change funcerr
		ReadTimeout: timeout,
	}

	s, err := serial.OpenPort(config)
	if err != nil {
		return nil, err
	}

	dev := &Device{
		port:    s,
		timeout: timeout,
	}
	log.Println("port serial Open!")
	return dev, nil
}

// Close close serial device
func (dev *Device) Close() bool {
	if err := dev.port.Close(); err != nil {
		log.Printf("close err: %s", err)
		return false
	}
	return true
}

// Read read serial device with a channel
func (dev *Device) read(contxt context.Context, waitResponse bool) ([]byte, error) {

	countError := 0
	//TODO timeoutRead?
	funcerr := func(err error) error {
		if err == nil {
			return nil
		}
		log.Printf("funcread err: %s", err)
		switch {
		case errors.Is(err, os.ErrClosed):
			return err
		case errors.Is(err, io.ErrClosedPipe):
			return err
		case errors.Is(err, io.EOF):
			if countError > 3 {
				return err
			}
			countError++
		}

		return nil

	}

	//TODO: limit to read
	bb := make([]byte, 0)
	indxb := 0
	for {

		select {
		case <-contxt.Done():
			return nil, fmt.Errorf("timeout error, %w", smartcard.ErrComm)
		default:
		}
		tempb := make([]byte, 2048)
		lendata := uint32(0)

		// fmt.Println("execute read")

		n, err := dev.port.Read(tempb)
		if err != nil && n <= 0 {
			if err := funcerr(err); err != nil {
				// log.Printf("0, err: %s", err)
				return nil, err
			}
			continue
		}
		// fmt.Printf("len: %v, [% X]\n", len(tempb[:n]), tempb[:n])

		// prepareBuffer := make([]byte, len(tempb[:n]))

		// copy(prepareBuffer, tempb[:n])

		bf := bytes.NewBuffer(tempb[:n])
		// fmt.Printf("len: %v, %v, %v, %v\n", len(prepareBuffer), cap(prepareBuffer), bf.Cap(), bf.Len())

		b := func() []byte {
			var result []byte

			for {
				select {
				case <-contxt.Done():
					return nil
				default:
				}

				last, err := bf.ReadByte()
				if err == nil {
					if indxb <= 0 && last != '\x02' {
						continue
					}
					indxb++
					bb = append(bb, last)
				} else {
					break
				}
				// fmt.Printf("len: %v, last: %X, [% X]\n", len(bb), last, bb[:])
				// log.Println("2")
				if len(bb) == 6 {

					lendata = binary.LittleEndian.Uint32(bb[2:6])
					// fmt.Printf("len data: %d\n", lendata)
				}
				if last == '\x03' && len(bb) == 4 && bb[1] == bb[2] {
					result = make([]byte, len(bb))
					copy(result, bb[:])
					bb = make([]byte, 0)
					continue
				}
				if last == '\x03' && len(bb) >= int(lendata)+1+10+1+1 {
					// fmt.Printf("tempb final: [% X]\n", bb[:])

					result = make([]byte, len(bb))
					copy(result, bb[:])
					bb = make([]byte, 0)
					continue
				}
			}
			return result
		}()

		if waitResponse {
			if len(b) <= 0 {
				continue
			}
			if len(b) == 4 && b[1] == b[2] && b[1] == 0x00 {
				continue
			}
			if len(b) == 13 && bytes.Equal(b, FRAME_NACK) {
				continue
			}
			if b[len(b)-1] != 0x03 {
				continue
			}
		}

		// fmt.Printf("resul final: [% X]\n", b[:])

		// if indxb <= 0 {
		// 	if b == '\x02' {
		// 		tempb[0] = b
		// 		indxb = 1
		// 	}
		// 	continue
		// }

		// tempb[indxb] = b
		// indxb++
		// fmt.Printf("len: %v, [% X]\n", indxb, tempb[:indxb])
		// // log.Println("2")
		// if indxb == 6 {
		// 	lendata = binary.LittleEndian.Uint32(tempb[2:6])
		// }
		// if b == '\x03' && indxb == 4 && tempb[1] == tempb[2] {
		// 	dest := make([]byte, indxb)
		// 	copy(dest, tempb[:indxb])
		// 	return dest, nil
		// }
		// if b == '\x03' && indxb >= int(lendata)+1+10+1+1 {
		// 	// fmt.Printf("tempb final: [% X]\n", tempb[:indxb])

		// 	dest := make([]byte, indxb)
		// 	copy(dest, tempb[:indxb])
		// 	return dest, nil
		// }
		dest := make([]byte, len(b))
		copy(dest, b[:])
		return dest, nil

	}
}

// Send write data bytes in serial device
func (dev *Device) Send(data []byte) (int, error) {
	dev.mux.Lock()
	defer dev.mux.Unlock()
	n, err := dev.port.Write(data)
	if err != nil {
		return 0, fmt.Errorf("dont write in Send command, err: %s, %w", err, smartcard.ErrComm)
	}

	return n, err
}

// SendRecv write daa bytes in serial device and wait by response
func (dev *Device) SendRecv(data []byte, timeout time.Duration) ([]byte, error) {
	dev.mux.Lock()
	defer dev.mux.Unlock()
	buff := make([]byte, 0)
	buff = append(buff, data[:]...)

	// fmt.Printf("data send: [% X]\n", data)
	if n, err := dev.port.Write(buff); err != nil {
		return nil, fmt.Errorf("dont write in SendRecv command err: %s, %w", err, smartcard.ErrComm)
	} else if n <= 0 {
		return nil, fmt.Errorf("dont write in SendRecv command, %w", smartcard.ErrComm)
	}
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	return dev.read(ctx, true)
}

// Recv read data bytes in serial device
func (dev *Device) Recv(timeout time.Duration) ([]byte, error) {

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	return dev.read(ctx, false)
}
