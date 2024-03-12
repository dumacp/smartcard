package clrc633

import (
	"encoding/binary"
	"fmt"
	"time"

	"periph.io/x/conn/v3/spi"
)

func anticoll(c spi.Conn, timeout time.Duration) ([]byte, error) {

	if err := write(c, 0x2c, []byte{0x18}); err != nil {
		return nil, err
	}
	if err := write(c, 0x2d, []byte{0x18}); err != nil {
		return nil, err
	}
	// // T0ReloadHi
	// if err := write(c, 0x10, []byte{0xFF}); err != nil {
	// 	return nil, err
	// }
	// // T0ReloadLo
	// if err := write(c, 0x11, []byte{0xFF}); err != nil {
	// 	return nil, err
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

	// T1ReloadHi
	if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
		return nil, err
	}
	// T1ReloadLo
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return nil, err
	}

	// TxDataNum
	if err := write(c, 0x2e, []byte{0x08}); err != nil {
		return nil, err
	}
	if err := write(c, 0x0c, []byte{0x00}); err != nil {
		return nil, err
	}
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return nil, err
	}
	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return nil, err
	}

	apdu := []byte{0x93, 0x20}

	if _, err := writeFifo(c, apdu); err != nil {
		return nil, err
	} /** else {
		fmt.Printf("write %d bytes\n", n)
	} /**/

	if err := resetIRQ(c); err != nil {
		return nil, err
	}

	// // TODO: create IRQ set
	// // if err := setmask(c, 0x08, 0x10); err != nil {
	// // 	return nil, err
	// // }
	// if err := setmask(c, 0x08, 0x04); err != nil {
	// 	return nil, err
	// }
	// if err := setmask(c, 0x09, 0x42); err != nil {
	// 	return nil, err
	// }
	// Command (Transceive)
	if err := write(c, 0x00, []byte{0x07}); err != nil {
		return nil, err
	}
	tt := time.Now()
	// IRQ1 register
	if err := waitRxIRQ(c, 0x02, timeout+30*time.Millisecond); err != nil {
		return nil, err
	}
	fmt.Printf("time elapse anticoll: %s\n", time.Since(tt))

	// irqstatus, err := statusIRQ(c)
	// if err != nil {
	// 	return nil, err
	// }
	// json.Marshal(irqstatus)
	// fmt.Printf("IRQ status: %s\n", func() []byte {
	// 	v, _ := json.MarshalIndent(irqstatus, "", "\t")
	// 	return v
	// }())

	// if irqstatus.ErrIRQ {
	// 	// Error
	// 	if resp, err := read(c, []byte{0x0A}); err != nil {
	// 		return nil, err
	// 	} else if err := errorClrc663(resp[0]); err != nil {
	// 		return nil, err
	// 	}
	// }

	if _, err := read(c, []byte{0x07}); err != nil {
		return nil, err
	} /** else if resp[0]&0x02 != 0x00 {
		fmt.Printf("read IRQ1 register: 0x%02X\n", resp[0])
		// return nil, errors.New("without response Timer1IRQ")
	} /**/

	// FIFOLength register
	length := 0
	if resp, err := read(c, []byte{0x04}); err != nil {
		return nil, err
	} else if resp[0] < 5 {
		return nil, fmt.Errorf("length is less than 5 (%d)", resp[0])
	} else {
		length = int(resp[0])
	}

	buff := make([]byte, length)
	if err := ReadFifo(c, buff); err != nil {
		return nil, err
	}

	// // Error
	// if resp, err := read(c, []byte{0x0A}); err != nil {
	// 	return nil, err
	// } else if err := errorClrc663(resp[0]); err != nil {
	// 	return nil, err
	// }

	return buff, nil
}

func anticoll2(c spi.Conn, timeout time.Duration) ([]byte, error) {

	if err := write(c, 0x2c, []byte{0x18}); err != nil {
		return nil, err
	}
	if err := write(c, 0x2d, []byte{0x18}); err != nil {
		return nil, err
	}
	// // T0ReloadHi
	// if err := write(c, 0x10, []byte{0xFF}); err != nil {
	// 	return nil, err
	// }
	// // T0ReloadLo
	// if err := write(c, 0x11, []byte{0xFF}); err != nil {
	// 	return nil, err
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

	// T1ReloadHi
	if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
		return nil, err
	}
	// T1ReloadLo
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return nil, err
	}
	// TxDataNum
	if err := write(c, 0x2e, []byte{0x08}); err != nil {
		return nil, err
	}
	if err := write(c, 0x0c, []byte{0x00}); err != nil {
		return nil, err
	}
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return nil, err
	}

	apdu := []byte{0x95, 0x20}

	if _, err := writeFifo(c, apdu); err != nil {
		return nil, err
	} /** else {
		fmt.Printf("write %d bytes\n", n)
	} /**/

	if err := resetIRQ(c); err != nil {
		return nil, err
	}

	// // TODO: create IRQ set
	// // if err := setmask(c, 0x08, 0x10); err != nil {
	// // 	return nil, err
	// // }
	// if err := setmask(c, 0x08, 0x04); err != nil {
	// 	return nil, err
	// }
	// if err := setmask(c, 0x09, 0x42); err != nil {
	// 	return nil, err
	// }
	// Command (Transceive)
	if err := write(c, 0x00, []byte{0x07}); err != nil {
		return nil, err
	}
	tt := time.Now()
	// IRQ1 register
	if err := waitRxIRQ(c, 0x02, timeout+30*time.Millisecond); err != nil {
		return nil, err
	}
	fmt.Printf("time elapse anticoll2: %s\n", time.Since(tt))

	// irqstatus, err := statusIRQ(c)
	// if err != nil {
	// 	return nil, err
	// }
	// json.Marshal(irqstatus)
	// fmt.Printf("IRQ status: %s\n", func() []byte {
	// 	v, _ := json.MarshalIndent(irqstatus, "", "\t")
	// 	return v
	// }())

	// if irqstatus.ErrIRQ {
	// 	// Error
	// 	if resp, err := read(c, []byte{0x0A}); err != nil {
	// 		return nil, err
	// 	} else if err := errorClrc663(resp[0]); err != nil {
	// 		return nil, err
	// 	}
	// }

	if resp, err := read(c, []byte{0x07}); err != nil {
		return nil, err
	} else if resp[0]&0x02 != 0x00 {
		fmt.Printf("read IRQ1 register: 0x%02X\n", resp[0])
		// return nil, errors.New("without response Timer1IRQ")
	}

	// FIFOLength register
	length := 0
	if resp, err := read(c, []byte{0x04}); err != nil {
		return nil, err
	} else if resp[0] < 5 {
		return nil, fmt.Errorf("length is less than 5 (%d)", resp[0])
	} else {
		length = int(resp[0])
	}

	buff := make([]byte, length)
	if err := ReadFifo(c, buff); err != nil {
		return nil, err
	}

	// // Error
	// if resp, err := read(c, []byte{0x0A}); err != nil {
	// 	return nil, err
	// } else if err := errorClrc663(resp[0]); err != nil {
	// 	return nil, err
	// }

	return buff, nil
}
