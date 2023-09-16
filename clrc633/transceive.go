package clrc633

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"periph.io/x/conn/v3/spi"
)

func sendApdu(c spi.Conn, apdu []byte, timeout time.Duration) ([]byte, error) {

	if err := write(c, 0x10, []byte{0xFF}); err != nil {
		return nil, err
	}
	if err := write(c, 0x11, []byte{0xFF}); err != nil {
		return nil, err
	}

	// calc timeout:
	// step => 0x01 ~= 5 ms

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

	// fmt.Printf("buff time: [ % X ]\n", bufftime)

	// T1ReloadHi
	if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
		return nil, err
	}
	// T1ReloadLo
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return nil, err
	}
	// TXCrcPreset
	if err := write(c, 0x2C, []byte{0x19}); err != nil {
		return nil, err
	}
	// RxCrcCon
	if err := write(c, 0x2D, []byte{0x18}); err != nil {
		return nil, err
	}
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return nil, err
	}
	// fmt.Printf("send apdu: [% X]\n", apdu)
	if _, err := writeFifo(c, apdu); err != nil {
		return nil, err
	}
	if err := resetIRQ(c); err != nil {
		return nil, err
	}
	// waitRxIRQ
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
	defer func() { fmt.Printf("time transceive: %v\n", time.Since(tt)) }()
	// IRQ1 register
	if err := waitRxIRQ(c, 0x02, timeout+10*time.Millisecond); err != nil {
		return nil, err
	}

	irqstatus, err := statusIRQ(c)
	if err != nil {
		return nil, err
	}
	json.Marshal(irqstatus)
	fmt.Printf("IRQ status: %s\n", func() []byte {
		v, _ := json.MarshalIndent(irqstatus, "", "\t")
		return v
	}())

	if irqstatus.ErrIRQ {
		// Error
		if resp, err := read(c, []byte{0x0A}); err != nil {
			return nil, err
		} else if err := errorClrc663(resp[0]); err != nil {
			return nil, err
		}
	}

	if resp, err := read(c, []byte{0x07}); err != nil {
		return nil, err
	} else if resp[0]&0x02 != 0x00 {
		fmt.Printf("read IRQ1 register: 0x%02X\n", resp[0])
		// return nil, errors.New("without response Timer1IRQ")
	}

	// FIFOLength register
	length := 0x00
	if resp, err := read(c, []byte{0x04}); err != nil {
		return nil, err
	} else if resp[0] == 0 {
		// return nil, fmt.Errorf("length response is zero (%d)", resp[0])
		fmt.Printf("length response is zero (%d)\n", resp[0])
		length = 0x10
	} else {
		fmt.Printf("length response is: %d\n", resp[0])
		length = int(resp[0])
	}

	buff := make([]byte, length)
	if err := ReadFifo(c, buff); err != nil {
		return nil, err
	}

	if len(buff) > 2 {
		return buff[:len(buff)-2], nil
	}

	return buff, nil
}
