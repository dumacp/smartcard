package clrc633

import (
	"encoding/binary"
	"fmt"
	"time"

	"periph.io/x/conn/v3/spi"
)

func selectTag(c spi.Conn, data []byte, timeout time.Duration) (byte, error) {

	if err := write(c, 0x10, []byte{0xFF}); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x11, []byte{0xFF}); err != nil {
		return 0x00, err
	}
	var convertTime int64

	if timeout.Milliseconds()/5 > 0xFFFF {
		convertTime = 0xFFFF
	} else {
		convertTime = timeout.Milliseconds() / 5
		if convertTime <= 0 {
			convertTime = 10
		}
	}
	bufftime := make([]byte, 4)
	binary.LittleEndian.PutUint32(bufftime, uint32(convertTime&0x00FFFF))
	fmt.Printf("bufferTime: [% X]\n", bufftime)

	if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return 0x00, err
	}
	if err := setmask(c, 0x0C, 0x00); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x2C, []byte{0x19}); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x2D, []byte{0x19}); err != nil {
		return 0x00, err
	}

	apdu := []byte{0x93, 0x70}
	apdu = append(apdu, data...)
	fmt.Printf("select apdu: [% X]\n", apdu)
	if _, err := writeFifo(c, apdu); err != nil {
		return 0x00, err
	}
	if err := resetIRQ(c); err != nil {
		return 0x00, err
	}
	// waitIrq
	// if err := setmask(c, 0x08, 0x10); err != nil {
	// 	return 0x00, err
	// }
	// if err := setmask(c, 0x09, 0x42); err != nil {
	// 	return 0x00, err
	// }
	// Command (Transceive)
	if err := write(c, 0x00, []byte{0x07}); err != nil {
		return 0x00, err
	}
	// IRQ1 register
	if err := waitRxIRQ(c, 0x02, timeout+30*time.Millisecond); err != nil {
		return 0x00, err
	}

	// irqstatus, err := statusIRQ(c)
	// if err != nil {
	// 	return 0x00, err
	// }
	// json.Marshal(irqstatus)
	// fmt.Printf("IRQ status: %s\n", func() []byte {
	// 	v, _ := json.MarshalIndent(irqstatus, "", "\t")
	// 	return v
	// }())

	// if irqstatus.ErrIRQ {
	// 	// Error
	// 	if resp, err := read(c, []byte{0x0A}); err != nil {
	// 		return 0x00, err
	// 	} else if err := errorClrc663(resp[0]); err != nil {
	// 		return 0x00, err
	// 	}
	// }

	// if resp, err := read(c, []byte{0x07}); err != nil {
	// 	return 0x00, err
	// } else if resp[0]&0x02 != 0x00 {
	// 	fmt.Printf("read IRQ1 register: 0x%02X\n", resp[0])
	// 	// return nil, errors.New("without response Timer1IRQ")
	// }

	// FIFOLength register
	length := 0x00
	if resp, err := read(c, []byte{0x04}); err != nil {
		return 0x00, err
	} else if resp[0] < 1 {
		return 0x00, fmt.Errorf("length is different than 1 (%d)", resp[0])
	} else {
		fmt.Printf("length select response (%d)\n", resp[0])
		length = int(resp[0])
	}

	buff := make([]byte, length)
	if err := ReadFifo(c, buff); err != nil {
		return 0x00, err
	}

	fmt.Printf("select FIFO response: [% X]\n", buff)

	// // Error
	// if resp, err := read(c, []byte{0x0A}); err != nil {
	// 	return 0x00, err
	// } else if err := errorClrc663(resp[0]); err != nil {
	// 	return 0x00, err
	// }

	return buff[0], nil
}

func select2Tag(c spi.Conn, data []byte, timeout time.Duration) (byte, error) {

	// if err := write(c, 0x10, []byte{0xFF}); err != nil {
	// 	return 0x00, err
	// }
	// if err := write(c, 0x11, []byte{0xFF}); err != nil {
	// 	return 0x00, err
	// }
	var convertTime int64

	if timeout.Milliseconds()/5 > 0xFFFF {
		convertTime = 0xFFFF
	} else {
		convertTime = timeout.Milliseconds() / 5
		if convertTime <= 0 {
			convertTime = 10
		}
	}
	bufftime := make([]byte, 4)
	binary.LittleEndian.PutUint32(bufftime, uint32(convertTime&0x00FFFF))

	if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return 0x00, err
	}

	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return 0x00, err
	}
	if err := setmask(c, 0x0C, 0x00); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x2C, []byte{0x19}); err != nil {
		return 0x00, err
	}
	if err := write(c, 0x2D, []byte{0x19}); err != nil {
		return 0x00, err
	}

	apdu := []byte{0x95, 0x70}
	apdu = append(apdu, data...)
	fmt.Printf("select apdu: [% X]\n", apdu)
	if _, err := writeFifo(c, apdu); err != nil {
		return 0x00, err
	}
	if err := resetIRQ(c); err != nil {
		return 0x00, err
	}
	// waitIrq
	// if err := setmask(c, 0x08, 0x10); err != nil {
	// 	return 0x00, err
	// }
	// if err := setmask(c, 0x09, 0x42); err != nil {
	// 	return 0x00, err
	// }
	// Command (Transceive)
	if err := write(c, 0x00, []byte{0x07}); err != nil {
		return 0x00, err
	}
	// IRQ1 register
	if err := waitRxIRQ(c, 0x02, timeout+30*time.Millisecond); err != nil {
		return 0x00, err
	}

	// irqstatus, err := statusIRQ(c)
	// if err != nil {
	// 	return 0x00, err
	// }
	// json.Marshal(irqstatus)
	// fmt.Printf("IRQ status: %s\n", func() []byte {
	// 	v, _ := json.MarshalIndent(irqstatus, "", "\t")
	// 	return v
	// }())

	// if irqstatus.ErrIRQ {
	// 	// Error
	// 	if resp, err := read(c, []byte{0x0A}); err != nil {
	// 		return 0x00, err
	// 	} else if err := errorClrc663(resp[0]); err != nil {
	// 		return 0x00, err
	// 	}
	// }

	if resp, err := read(c, []byte{0x07}); err != nil {
		return 0x00, err
	} else if resp[0]&0x02 != 0x00 {
		fmt.Printf("read IRQ1 register: 0x%02X\n", resp[0])
		// return nil, errors.New("without response Timer1IRQ")
	}

	// FIFOLength register
	length := 0x00
	if resp, err := read(c, []byte{0x04}); err != nil {
		return 0x00, err
	} else if resp[0] < 1 {
		return 0x00, fmt.Errorf("length is different than 1 (%d)", resp[0])
	} else {
		fmt.Printf("length select response (%d)\n", resp[0])
		length = int(resp[0])
	}

	buff := make([]byte, length)
	if err := ReadFifo(c, buff); err != nil {
		return 0x00, err
	}

	fmt.Printf("select_2 FIFO response: [% X]\n", buff)

	// // Error
	// if resp, err := read(c, []byte{0x0A}); err != nil {
	// 	return 0x00, err
	// } else if err := errorClrc663(resp[0]); err != nil {
	// 	return 0x00, err
	// }

	return buff[0], nil
}
