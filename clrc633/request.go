package clrc633

import (
	"encoding/binary"
	"fmt"
	"time"

	"periph.io/x/conn/v3/spi"
)

func request(c spi.Conn, tagType byte, timeout time.Duration) (byte, error) {

	///////////  NEW    /////////////////
	/////////////////////////////////////

	/**
	DrvMode
	Bit		Symbol		Description
	7		Tx2			InvInverts transmitter 2 at TX2 pin
	6		Tx1			InvInverts transmitter 1 at TX1 pin
	5					RFU
	4		-			RFU
	3		TxEn		If set to 1 both transmitter pins are enabled
	2 to 0	TxClkMode	Transmitter clock settings. Codes 011b and 0b110 are not supported.
						This register defines, if the output is operated in open-drain, push-pull,
						at high impedance or pulled to a fix high or low level.
	/**/
	// DrvMode
	if err := write(c, 0x28, []byte{0x81}); err != nil {
		return 0x00, err
	}
	// DrvMode
	if err := write(c, 0x28, []byte{0x89}); err != nil {
		return 0x00, err
	}
	//Status register
	if err := clearmask(c, 0x0B, 0x20); err != nil {
		return 0x00, err
	}
	/////////////////////////////////////

	//TxWaitCtrl
	if err := write(c, 0x31, []byte{0xC0}); err != nil {
		return 0x00, err
	}
	//TxWaitLo
	if err := write(c, 0x32, []byte{0x0B}); err != nil {
		return 0x00, err
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

	// //T0ReloadHi
	// if err := write(c, 0x10, []byte{bufftime[1]}); err != nil {
	// 	return 0x00, err
	// }
	// //T0ReloadLo
	// if err := write(c, 0x11, []byte{bufftime[0]}); err != nil {
	// 	return 0x00, err
	// }
	//T1ReloadHi
	if err := write(c, 0x15, []byte{bufftime[1]}); err != nil {
		return 0x00, err
	}
	//T1ReloadLo
	if err := write(c, 0x16, []byte{bufftime[0]}); err != nil {
		return 0x00, err
	}
	//RxWait
	if err := write(c, 0x36, []byte{0x90}); err != nil {
		return 0x00, err
	}
	//TxDataNum
	if err := write(c, 0x2E, []byte{0x0F}); err != nil {
		return 0x00, err
	}
	//TxCrcPreset
	if err := write(c, 0x2C, []byte{0x18}); err != nil {
		return 0x00, err
	}
	//RxCrcCon
	if err := write(c, 0x2D, []byte{0x18}); err != nil {
		return 0x00, err
	}

	//Command 0x00
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return 0x00, err
	}
	if _, err := writeFifo(c, []byte{tagType}); err != nil {
		return 0x00, err
	}

	if err := resetIRQ(c); err != nil {
		return 0x00, err
	}

	// // IRQ0En
	// if err := setmask(c, 0x08, 0x10); err != nil {
	// 	return 0x00, err
	// }
	// // IRQ1En
	// if err := setmask(c, 0x09, 0x42); err != nil {
	// 	return 0x00, err
	// }

	// Command (transceive)
	if err := write(c, 0x00, []byte{0x07}); err != nil {
		return 0x00, err
	}

	// tt := time.Now()
	if err := waitRxIRQ(c, TIME1IRQ, (timeout + 30*time.Millisecond)); err != nil {
		return 0x00, err
	}
	// fmt.Printf("time elapse request: %s\n", time.Since(tt))

	// printStatusIRQ(c)

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
	if resp, err := read(c, []byte{0x04}); err != nil {
		return 0x00, err
	} else if resp[0] != 2 {
		return 0x00, fmt.Errorf("length is different than 2 (%d)", resp[0])
	}

	buff := make([]byte, 2)
	if err := ReadFifo(c, buff); err != nil {
		return 0x00, err
	}

	fmt.Printf("request response: [% X]\n", buff)

	// // Error
	// if resp, err := read(c, []byte{0x0A}); err != nil {
	// 	return 0x00, err
	// } else if err := errorClrc663(resp[0]); err != nil {
	// 	return 0x00, err
	// }

	//TxDataNum
	if err := write(c, 0x2E, []byte{0x08}); err != nil {
		return 0x00, err
	}

	return buff[0], nil
}
