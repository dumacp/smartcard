package clrc633

import (
	"encoding/binary"
	"fmt"
	"time"

	"periph.io/x/conn/v3/spi"
)

func loadKey(c spi.Conn, key []byte, timeout time.Duration) error {

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
		return err
	}
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return err
	}

	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return err
	}
	// fmt.Printf("send key: [% X]\n", key)
	if _, err := writeFifo(c, key); err != nil {
		return err
	}
	if err := resetIRQ(c); err != nil {
		return err
	}
	// waitIrq
	// if err := setmask(c, 0x08, 0x10); err != nil {
	// 	return err
	// }
	// if err := setmask(c, 0x09, 0x40); err != nil {
	// 	return err
	// }
	// Command (load key)
	if err := write(c, 0x00, []byte{0x02}); err != nil {
		return err
	}

	// tSelect := time.Now()
	// defer func() { fmt.Printf("time loadKey: %v\n", time.Since(tSelect)) }()
	// time.Sleep(100 * time.Millisecond)
	// IRQ1 register
	if err := waitIdleIRQ(c, TIME1IRQ, timeout+30*time.Millisecond); err != nil {
		return err
	}

	// irqstatus, err := statusIRQ(c)
	// if err != nil {
	// 	return err
	// }
	// json.Marshal(irqstatus)
	// fmt.Printf("IRQ status: %s\n", func() []byte {
	// 	v, _ := json.MarshalIndent(irqstatus, "", "\t")
	// 	return v
	// }())

	// if irqstatus.ErrIRQ {
	// 	// Error
	// 	if resp, err := read(c, []byte{0x0A}); err != nil {
	// 		return err
	// 	} else if err := errorClrc663(resp[0]); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func auth(c spi.Conn, keyType, block byte, uid []byte, timeout time.Duration) error {

	// //Status register
	// if err := clearmask(c, 0x0B, 0x20); err != nil {
	// 	return err
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
	// fmt.Printf("bufferTime: [% X]\n", bufftime)

	if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
		return err
	}
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return err
	}

	// if err := write(c, 0x10, []byte{0xFF}); err != nil {
	// 	return err
	// }
	// if err := write(c, 0x11, []byte{0xFF}); err != nil {
	// 	return err
	// }
	// if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
	// 	return err
	// }
	// if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
	// 	return err
	// }
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return err
	}
	if err := write(c, 0x2C, []byte{0x19}); err != nil {
		return err
	}
	if err := write(c, 0x2D, []byte{0x19}); err != nil {
		return err
	}

	frame := make([]byte, 0)
	if keyType == 0x00 {
		frame = append(frame, 0x60)
	} else {
		frame = append(frame, 0x61)
	}
	frame = append(frame, block)
	frame = append(frame, uid...)

	// fmt.Printf("send auth frame: [% X]\n", frame)
	if _, err := writeFifo(c, frame); err != nil {
		return err
	}
	if err := resetIRQ(c); err != nil {
		return err
	}
	// waitIrq
	// if err := setmask(c, 0x08, 0x10); err != nil {
	// 	return err
	// }
	// if err := setmask(c, 0x09, 0x40); err != nil {
	// 	return err
	// }
	// Command (auth)
	if err := write(c, 0x00, []byte{0x03}); err != nil {
		return err
	}

	// tSelect := time.Now()
	// defer func() { fmt.Printf("time auth: %v\n", time.Since(tSelect)) }()
	// IRQ1 register
	if err := waitIdleIRQ(c, 0x02, timeout+30*time.Millisecond); err != nil {
		return ErrorAuth
	}

	// irqstatus, err := statusIRQ(c)
	// if err != nil {
	// 	return err
	// }
	// json.Marshal(irqstatus)
	// fmt.Printf("IRQ status: %s\n", func() []byte {
	// 	v, _ := json.MarshalIndent(irqstatus, "", "\t")
	// 	return v
	// }())

	// if irqstatus.ErrIRQ {
	// 	// Error
	// 	if resp, err := read(c, []byte{0x0A}); err != nil {
	// 		return err
	// 	} else if err := errorClrc663(resp[0]); err != nil {
	// 		return err
	// 	}
	// }

	//Status register
	if resp, err := read(c, []byte{0x0B}); err != nil {
		return err
	} else {
		if len(resp) > 0 && resp[0]&0x20 == 0x20 {
			return nil
		}
	}

	return fmt.Errorf("auth failed")
}
