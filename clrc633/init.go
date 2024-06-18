package clrc633

import (
	"fmt"
	"time"

	"periph.io/x/conn/v3/spi"
)

func initDev(c spi.Conn) error {

	fifoLenght := 0x00

	// T0control
	//
	// bits: 7 (T0StopRx)
	//		 If set, the timer stops immediately after receiving the first 4 bits.
	// 		 If cleared the timer does not stop automatically.
	// 		 Note: If LFO Trimming is selected by T0Start, this bit has no effect.
	// bits: 6 (RFU)
	// bits: 5 to 4 (T0Start)
	//		 00b: The timer is not started automatically
	//       01 b: The timer starts automatically at the end of the transmission
	//		 10 b: Timer is used for LFO trimming without underflow (Start/Stop on PosEdge)
	//		 11 b: Timer is used for LFO trimming with underflow (Start/Stop on PosEdge)
	// bits: 3 (T0AutoRestart)
	//		 1: the timer automatically restarts its count-down from T0ReloadValue,
	//		    after the counter value has reached the value zero.
	//		 0: the timer decrements to zero and stops.
	//		 Note: The bit Timer1IRQ is set to logic 1 when the timer underflows.
	// bits: 2 (RFU)
	// bits: 1 to 0 (T0Clk)
	//		 00 b: The timer input clock is 13.56 MHz.
	//		 01 b: The timer input clock is 211,875 kHz.
	//		 10 b: The timer input clock is an underflow of Timer2.
	//		 11 b: The timer input clock is an underflow of Timer1.
	if err := write(c, 0x0f, []byte{0x98}); err != nil {
		return err
	}

	// T1Control
	if err := write(c, 0x14, []byte{0x92}); err != nil {
		return err
	}

	// T2Control
	if err := write(c, 0x19, []byte{0x20}); err != nil {
		return err
	}

	// T2ReloadHi
	if err := write(c, 0x1a, []byte{0x03}); err != nil {
		return err
	}

	// T2ReloadLo
	if err := write(c, 0x1b, []byte{0xFF}); err != nil {
		return err
	}

	// T3Control
	if err := write(c, 0x1E, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl
	if err := write(c, 0x02, []byte{0x90}); err != nil {
		return err
	}

	// WaterLevel
	if err := write(c, 0x03, []byte{0xFE}); err != nil {
		return err
	}

	// RxBitCtrl
	if err := write(c, 0x0C, []byte{0x80}); err != nil {
		return err
	}

	// DrvMode ???
	if resp, err := read(c, []byte{0x28}); err != nil {
		return err
	} else if err := write(c, 0x28, resp); err != nil {
		return err
	} else {
		fmt.Printf("write [% 02X] in addr: 0x%02X\n", resp, 0x28)
	}

	// TxAmp
	if err := write(c, 0x29, []byte{0x00}); err != nil {
		return err
	}

	// TxCon
	if err := write(c, 0x2A, []byte{0x01}); err != nil {
		return err
	}

	// Txl
	if err := write(c, 0x2B, []byte{0x05}); err != nil {
		return err
	}

	// RxSofD
	if err := write(c, 0x34, []byte{0x00}); err != nil {
		return err
	}

	// Rcv
	if err := write(c, 0x38, []byte{0x12}); err != nil {
		return err
	}

	// Command (0x00)
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}

	// // IRQ0 register
	// if err := write(c, 0x06, []byte{0x7F}); err != nil {
	// 	return err
	// }

	// // IRQ1 register
	// if err := write(c, 0x07, []byte{0x7F}); err != nil {
	// 	return err
	// }

	// FIFOLength
	if resp, err := read(c, []byte{0x04}); err != nil {
		return err
	} else {
		fifoLenght = int(resp[0])
		fmt.Printf("FIFOLength: %d\n", fifoLenght)
	}

	// FIFOData
	if err := write(c, 0x05, []byte{0x00, 0x00}); err != nil {
		return err
	}

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// IRQ0En register (IdleIRQEn)
	if err := setmask(c, 0x08, 0x10); err != nil {
		return err
	}
	// IRQ1En (Timer2 IRQEn)
	if err := setmask(c, 0x09, 0x40); err != nil {
		return err
	}

	// command (LoadProtocol) Note: FIFOData
	if err := write(c, 0x00, []byte{0x0d}); err != nil {
		return err
	}
	// wait IRQ
	if err := waitIRQ(c, 0x07, 0x40, 300*time.Millisecond); err != nil {
		return err
	}

	printStatusIRQ(c)

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}
	// Error
	if resp, err := read(c, []byte{0x0A}); err != nil {
		return err
	} else if resp[0] != 0x00 {
		fmt.Printf("Error: 0x%02X\n", resp[0])
		return errorClrc663(resp[0])
	}

	if err := write(c, 0x2C, []byte{0x18}); err != nil {
		return err
	}
	if err := write(c, 0x2D, []byte{0x18}); err != nil {
		return err
	}
	// TxDataNum
	if err := write(c, 0x2E, []byte{0x08}); err != nil {
		return err
	}
	// TxDATAModWith
	if err := write(c, 0x2F, []byte{0x20}); err != nil {
		return err
	}
	// TxSym10BurstLen
	if err := write(c, 0x30, []byte{0x0}); err != nil {
		return err
	}
	// FrameCon
	if err := write(c, 0x33, []byte{0xcf}); err != nil {
		return err
	}
	// RxCtrl
	if err := write(c, 0x35, []byte{0x04}); err != nil {
		return err
	}
	// RxThreshold
	if err := write(c, 0x37, []byte{0x32}); err != nil {
		return err
	}
	// RxAna
	if err := write(c, 0x39, []byte{0x00}); err != nil {
		return err
	}
	// RxWait
	if err := write(c, 0x36, []byte{0x90}); err != nil {
		return err
	}
	// TxWaitCtrl
	if err := write(c, 0x31, []byte{0xC0}); err != nil {
		return err
	}
	// TxWaitLo
	if err := write(c, 0x32, []byte{0x0B}); err != nil {
		return err
	}
	// T0ReloadHi
	if err := write(c, 0x10, []byte{0x08}); err != nil {
		return err
	}
	// T0ReloadLo
	if err := write(c, 0x11, []byte{0xD8}); err != nil {
		return err
	}
	// T1ReloadHi
	if err := write(c, 0x15, []byte{0x00}); err != nil {
		return err
	}
	// T1ReloadLo
	if err := write(c, 0x16, []byte{0x00}); err != nil {
		return err
	}
	// DrvMode
	if err := write(c, 0x28, []byte{0x81}); err != nil {
		return err
	}
	// Status
	if err := clearmask(c, 0x0B, 0x20); err != nil {
		return err
	}
	// TxBitMod
	if err := setmask(c, 0x48, 0x20); err != nil {
		return err
	}
	// RxBitMod
	if err := setmask(c, 0x58, 0x02); err != nil {
		return err
	}
	// DrvMode
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
	if err := write(c, 0x28, []byte{0x89}); err != nil {
		return err
	}
	return nil
}

func init_iso14443_Dev(c spi.Conn) error {

	fifoLenght := 0x00

	// T0control
	//
	// bits: 7 (T0StopRx)
	//		 If set, the timer stops immediately after receiving the first 4 bits.
	// 		 If cleared the timer does not stop automatically.
	// 		 Note: If LFO Trimming is selected by T0Start, this bit has no effect.
	// bits: 6 (RFU)
	// bits: 5 to 4 (T0Start)
	//		 00b: The timer is not started automatically
	//       01 b: The timer starts automatically at the end of the transmission
	//		 10 b: Timer is used for LFO trimming without underflow (Start/Stop on PosEdge)
	//		 11 b: Timer is used for LFO trimming with underflow (Start/Stop on PosEdge)
	// bits: 3 (T0AutoRestart)
	//		 1: the timer automatically restarts its count-down from T0ReloadValue,
	//		    after the counter value has reached the value zero.
	//		 0: the timer decrements to zero and stops.
	//		 Note: The bit Timer1IRQ is set to logic 1 when the timer underflows.
	// bits: 2 (RFU)
	// bits: 1 to 0 (T0Clk)
	//		 00 b: The timer input clock is 13.56 MHz.
	//		 01 b: The timer input clock is 211,875 kHz.
	//		 10 b: The timer input clock is an underflow of Timer2.
	//		 11 b: The timer input clock is an underflow of Timer1.
	if err := write(c, 0x0f, []byte{0x98}); err != nil {
		return err
	}

	// T1Control
	if err := write(c, 0x14, []byte{0x92}); err != nil {
		return err
	}

	// T2Control
	if err := write(c, 0x19, []byte{0x20}); err != nil {
		return err
	}

	// T2ReloadHi
	if err := write(c, 0x1a, []byte{0x03}); err != nil {
		return err
	}

	// T2ReloadLo
	if err := write(c, 0x1b, []byte{0xFF}); err != nil {
		return err
	}

	// T3Control
	if err := write(c, 0x1E, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl
	if err := write(c, 0x02, []byte{0x90}); err != nil {
		return err
	}

	// WaterLevel
	if err := write(c, 0x03, []byte{0xFE}); err != nil {
		return err
	}

	// RxBitCtrl
	if err := write(c, 0x0C, []byte{0x80}); err != nil {
		return err
	}

	// // DrvMode ???
	// if resp, err := read(c, []byte{0x28}); err != nil {
	// 	return err
	// } else if err := write(c, 0x28, resp); err != nil {
	// 	return err
	// } else {
	// 	fmt.Printf("write [% 02X] in addr: 0x%02X\n", resp, 0x28)
	// }
	if err := setmask(c, 0x28, 0x80); err != nil {
		return err
	}

	// TxAmp
	if err := write(c, 0x29, []byte{0x00}); err != nil {
		return err
	}

	// TxCon
	if err := write(c, 0x2A, []byte{0x01}); err != nil {
		return err
	}

	// Txl
	if err := write(c, 0x2B, []byte{0x05}); err != nil {
		return err
	}

	// RxSofD
	if err := write(c, 0x34, []byte{0x00}); err != nil {
		return err
	}

	// Rcv
	if err := write(c, 0x38, []byte{0x12}); err != nil {
		return err
	}

	// Command (0x00)
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}

	// // IRQ0 register
	// if err := write(c, 0x06, []byte{0x7F}); err != nil {
	// 	return err
	// }

	// // IRQ1 register
	// if err := write(c, 0x07, []byte{0x7F}); err != nil {
	// 	return err
	// }

	// FIFOLength
	if resp, err := read(c, []byte{0x04}); err != nil {
		return err
	} else {
		fifoLenght = int(resp[0])
		fmt.Printf("FIFOLength: %d\n", fifoLenght)
	}

	// FIFOData
	if err := write(c, 0x05, []byte{0x00, 0x00}); err != nil {
		return err
	}

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// IRQ0En register (IdleIRQEn)
	if err := setmask(c, 0x08, 0x10); err != nil {
		return err
	}
	// IRQ1En (Timer2 IRQEn)
	if err := setmask(c, 0x09, 0x40); err != nil {
		return err
	}

	// command (LoadProtocol) Note: FIFOData
	if err := write(c, 0x00, []byte{0x0d}); err != nil {
		return err
	}
	// wait IRQ
	if err := waitIRQ(c, 0x07, 0x40, 300*time.Millisecond); err != nil {
		return err
	}

	printStatusIRQ(c)

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}
	// Error
	if resp, err := read(c, []byte{0x0A}); err != nil {
		return err
	} else if resp[0] != 0x00 {
		fmt.Printf("Error: 0x%02X\n", resp[0])
		return errorClrc663(resp[0])
	}

	// if err := write(c, 0x2C, []byte{0x18}); err != nil {
	// 	return err
	// }
	// if err := write(c, 0x2D, []byte{0x18}); err != nil {
	// 	return err
	// }
	// TxDataNum
	if err := write(c, 0x2E, []byte{0x08}); err != nil {
		return err
	}
	// TxDATAModWith
	if err := write(c, 0x2F, []byte{0x20}); err != nil {
		return err
	}
	// TxSym10BurstLen
	if err := write(c, 0x30, []byte{0x0}); err != nil {
		return err
	}
	// FrameCon
	if err := write(c, 0x33, []byte{0xcf}); err != nil {
		return err
	}
	// // RxCtrl
	// if err := write(c, 0x35, []byte{0x04}); err != nil {
	// 	return err
	// }
	// RxThreshold
	if err := write(c, 0x37, []byte{0x32}); err != nil {
		return err
	}
	// RxAna
	if err := write(c, 0x39, []byte{0x00}); err != nil {
		return err
	}
	// RxWait
	if err := write(c, 0x36, []byte{0x90}); err != nil {
		return err
	}
	// TxWaitCtrl
	if err := write(c, 0x31, []byte{0xC0}); err != nil {
		return err
	}
	// TxWaitLo
	if err := write(c, 0x32, []byte{0x0B}); err != nil {
		return err
	}
	// DrvMode
	if err := write(c, 0x28, []byte{0x81}); err != nil {
		return err
	}
	// TxBitMod
	if err := setmask(c, 0x48, 0x20); err != nil {
		return err
	}
	// RxBitMod
	if err := setmask(c, 0x58, 0x02); err != nil {
		return err
	}
	// DrvMode
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
	if err := write(c, 0x28, []byte{0x89}); err != nil {
		return err
	}
	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	return nil
}

func init_test_Dev(c spi.Conn) error {

	fifoLenght := 0x00

	// T0control
	//
	// bits: 7 (T0StopRx)
	//		 If set, the timer stops immediately after receiving the first 4 bits.
	// 		 If cleared the timer does not stop automatically.
	// 		 Note: If LFO Trimming is selected by T0Start, this bit has no effect.
	// bits: 6 (RFU)
	// bits: 5 to 4 (T0Start)
	//		 00b: The timer is not started automatically
	//       01 b: The timer starts automatically at the end of the transmission
	//		 10 b: Timer is used for LFO trimming without underflow (Start/Stop on PosEdge)
	//		 11 b: Timer is used for LFO trimming with underflow (Start/Stop on PosEdge)
	// bits: 3 (T0AutoRestart)
	//		 1: the timer automatically restarts its count-down from T0ReloadValue,
	//		    after the counter value has reached the value zero.
	//		 0: the timer decrements to zero and stops.
	//		 Note: The bit Timer1IRQ is set to logic 1 when the timer underflows.
	// bits: 2 (RFU)
	// bits: 1 to 0 (T0Clk)
	//		 00 b: The timer input clock is 13.56 MHz.
	//		 01 b: The timer input clock is 211,875 kHz.
	//		 10 b: The timer input clock is an underflow of Timer2.
	//		 11 b: The timer input clock is an underflow of Timer1.
	if err := write(c, 0x0f, []byte{0x98}); err != nil {
		return err
	}

	// T1Control
	if err := write(c, 0x14, []byte{0x92}); err != nil {
		return err
	}

	// T2Control
	if err := write(c, 0x19, []byte{0x20}); err != nil {
		return err
	}

	// T2ReloadHi
	if err := write(c, 0x1a, []byte{0x03}); err != nil {
		return err
	}

	// T2ReloadLo
	if err := write(c, 0x1b, []byte{0xFF}); err != nil {
		return err
	}

	// T3Control
	if err := write(c, 0x1E, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl
	if err := write(c, 0x02, []byte{0x90}); err != nil {
		return err
	}

	// WaterLevel
	if err := write(c, 0x03, []byte{0xFE}); err != nil {
		return err
	}

	// RxBitCtrl
	if err := write(c, 0x0C, []byte{0x80}); err != nil {
		return err
	}

	// DrvMode ???
	if resp, err := read(c, []byte{0x28}); err != nil {
		return err
	} else if err := write(c, 0x28, resp); err != nil {
		return err
	} else {
		fmt.Printf("write [% 02X] in addr: 0x%02X\n", resp, 0x28)
	}
	if err := setmask(c, 0x28, 0x80); err != nil {
		return err
	}

	// TxAmp
	if err := write(c, 0x29, []byte{0x00}); err != nil {
		return err
	}

	// TxCon
	if err := write(c, 0x2A, []byte{0x01}); err != nil {
		return err
	}

	// Txl
	if err := write(c, 0x2B, []byte{0x05}); err != nil {
		return err
	}

	// RxSofD
	if err := write(c, 0x34, []byte{0x00}); err != nil {
		return err
	}

	// Rcv
	if err := write(c, 0x38, []byte{0x12}); err != nil {
		return err
	}

	// Command (0x00)
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}

	// // IRQ0 register
	// if err := write(c, 0x06, []byte{0x7F}); err != nil {
	// 	return err
	// }

	// // IRQ1 register
	// if err := write(c, 0x07, []byte{0x7F}); err != nil {
	// 	return err
	// }

	// FIFOLength
	if resp, err := read(c, []byte{0x04}); err != nil {
		return err
	} else {
		fifoLenght = int(resp[0])
		fmt.Printf("FIFOLength: %d\n", fifoLenght)
	}

	// FIFOData
	if err := write(c, 0x05, []byte{0x00, 0x00}); err != nil {
		return err
	}

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// IRQ0En register (IdleIRQEn)
	if err := setmask(c, 0x08, 0x10); err != nil {
		return err
	}
	// IRQ1En (Timer2 IRQEn)
	if err := setmask(c, 0x09, 0x40); err != nil {
		return err
	}

	// command (LoadProtocol) Note: FIFOData
	if err := write(c, 0x00, []byte{0x0d}); err != nil {
		return err
	}
	// wait IRQ
	if err := waitIRQ(c, 0x07, 0x40, 300*time.Millisecond); err != nil {
		return err
	}

	printStatusIRQ(c)

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}
	// Error
	if resp, err := read(c, []byte{0x0A}); err != nil {
		return err
	} else if resp[0] != 0x00 {
		fmt.Printf("Error: 0x%02X\n", resp[0])
		return errorClrc663(resp[0])
	}

	// diff 2
	if err := write(c, 0x2C, []byte{0x18}); err != nil {
		return err
	}
	if err := write(c, 0x2D, []byte{0x18}); err != nil {
		return err
	}
	// TxDataNum
	if err := write(c, 0x2E, []byte{0x08}); err != nil {
		return err
	}
	// TxDATAModWith
	if err := write(c, 0x2F, []byte{0x20}); err != nil {
		return err
	}
	// TxSym10BurstLen
	if err := write(c, 0x30, []byte{0x0}); err != nil {
		return err
	}
	// FrameCon
	if err := write(c, 0x33, []byte{0xcf}); err != nil {
		return err
	}
	// diff 2
	// RxCtrl
	if err := write(c, 0x35, []byte{0x04}); err != nil {
		return err
	}
	// RxThreshold
	if err := write(c, 0x37, []byte{0x32}); err != nil {
		return err
	}
	// RxAna
	if err := write(c, 0x39, []byte{0x00}); err != nil {
		return err
	}
	// RxWait
	if err := write(c, 0x36, []byte{0x90}); err != nil {
		return err
	}
	// TxWaitCtrl
	if err := write(c, 0x31, []byte{0xC0}); err != nil {
		return err
	}
	// TxWaitLo
	if err := write(c, 0x32, []byte{0x0B}); err != nil {
		return err
	}

	// diff 4
	// T0ReloadHi
	if err := write(c, 0x10, []byte{0x08}); err != nil {
		return err
	}
	// T0ReloadLo
	if err := write(c, 0x11, []byte{0xD8}); err != nil {
		return err
	}
	// T1ReloadHi
	if err := write(c, 0x15, []byte{0x00}); err != nil {
		return err
	}
	// T1ReloadLo
	if err := write(c, 0x16, []byte{0x00}); err != nil {
		return err
	}
	//////////////////////////////////////

	// DrvMode
	if err := write(c, 0x28, []byte{0x81}); err != nil {
		return err
	}

	// diff 6
	// Status
	if err := clearmask(c, 0x0B, 0x20); err != nil {
		return err
	}
	////////////////////////////////////////////
	// TxBitMod
	if err := setmask(c, 0x48, 0x20); err != nil {
		return err
	}
	// RxBitMod
	if err := setmask(c, 0x58, 0x02); err != nil {
		return err
	}
	// DrvMode
	if err := write(c, 0x28, []byte{0x89}); err != nil {
		return err
	}
	// diff 5
	// // reset IRQ
	// if err := resetIRQ(c); err != nil {
	// 	return err
	// }
	return nil
}

func init_test2_Dev(c spi.Conn) error {

	fifoLenght := 0x00
	fmt.Println(fifoLenght)

	// T0control
	//
	// bits: 7 (T0StopRx)
	//		 If set, the timer stops immediately after receiving the first 4 bits.
	// 		 If cleared the timer does not stop automatically.
	// 		 Note: If LFO Trimming is selected by T0Start, this bit has no effect.
	// bits: 6 (RFU)
	// bits: 5 to 4 (T0Start)
	//		 00b: The timer is not started automatically
	//       01 b: The timer starts automatically at the end of the transmission
	//		 10 b: Timer is used for LFO trimming without underflow (Start/Stop on PosEdge)
	//		 11 b: Timer is used for LFO trimming with underflow (Start/Stop on PosEdge)
	// bits: 3 (T0AutoRestart)
	//		 1: the timer automatically restarts its count-down from T0ReloadValue,
	//		    after the counter value has reached the value zero.
	//		 0: the timer decrements to zero and stops.
	//		 Note: The bit Timer1IRQ is set to logic 1 when the timer underflows.
	// bits: 2 (RFU)
	// bits: 1 to 0 (T0Clk)
	//		 00 b: The timer input clock is 13.56 MHz.
	//		 01 b: The timer input clock is 211,875 kHz.
	//		 10 b: The timer input clock is an underflow of Timer2.
	//		 11 b: The timer input clock is an underflow of Timer1.
	if err := write(c, 0x0f, []byte{0x98}); err != nil {
		return err
	}

	// T1Control
	if err := write(c, 0x14, []byte{0x92}); err != nil {
		return err
	}

	// T2Control
	if err := write(c, 0x19, []byte{0x20}); err != nil {
		return err
	}

	// T2ReloadHi
	if err := write(c, 0x1a, []byte{0x03}); err != nil {
		return err
	}

	// T2ReloadLo
	if err := write(c, 0x1b, []byte{0xFF}); err != nil {
		return err
	}

	// T3Control
	if err := write(c, 0x1E, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl
	if err := write(c, 0x02, []byte{0x90}); err != nil {
		return err
	}
	//*

	// WaterLevel
	if err := write(c, 0x03, []byte{0xFE}); err != nil {
		return err
	}

	// RxBitCtrl
	if err := write(c, 0x0C, []byte{0x80}); err != nil {
		return err
	}

	// DrvMode ???
	if resp, err := read(c, []byte{0x28}); err != nil {
		return err
	} else if err := write(c, 0x28, resp); err != nil {
		return err
	} else {
		fmt.Printf("write [% 02X] in addr: 0x%02X\n", resp, 0x28)
	}
	// if err := setmask(c, 0x28, 0x80); err != nil {
	// 	return err
	// }

	// TxAmp
	if err := write(c, 0x29, []byte{0x00}); err != nil {
		return err
	}

	// TxCon
	if err := write(c, 0x2A, []byte{0x01}); err != nil {
		return err
	}

	// Txl
	if err := write(c, 0x2B, []byte{0x05}); err != nil {
		return err
	}

	// RxSofD
	if err := write(c, 0x34, []byte{0x00}); err != nil {
		return err
	}

	//*

	// Rcv
	if err := write(c, 0x38, []byte{0x12}); err != nil {
		return err
	}

	// Command (0x00)
	if err := write(c, 0x00, []byte{0x00}); err != nil {
		return err
	}

	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}

	// // IRQ0 register
	// if err := write(c, 0x06, []byte{0x7F}); err != nil {
	// 	return err
	// }

	// // IRQ1 register
	// if err := write(c, 0x07, []byte{0x7F}); err != nil {
	// 	return err
	// }

	//*

	// FIFOLength
	if resp, err := read(c, []byte{0x04}); err != nil {
		return err
	} else {
		fifoLenght = int(resp[0])
		fmt.Printf("FIFOLength: %d\n", fifoLenght)
	}

	// FIFOData
	if err := write(c, 0x05, []byte{0x00, 0x00}); err != nil {
		return err
	}

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// IRQ0En register (IdleIRQEn)
	if err := setmask(c, 0x08, 0x10); err != nil {
		return err
	}
	// IRQ1En (Timer2 IRQEn)
	if err := setmask(c, 0x09, 0x40); err != nil {
		return err
	}

	// command (LoadProtocol) Note: FIFOData
	if err := write(c, 0x00, []byte{0x0d}); err != nil {
		return err
	}
	// wait IRQ
	if err := waitIRQ(c, 0x07, 0x40, 300*time.Millisecond); err != nil {
		return err
	}
	//*

	printStatusIRQ(c)

	// reset IRQ
	if err := resetIRQ(c); err != nil {
		return err
	}
	// FIFOControl (flush)
	if err := setmask(c, 0x02, 0x10); err != nil {
		return err
	}
	// Error
	if resp, err := read(c, []byte{0x0A}); err != nil {
		return err
	} else if resp[0] != 0x00 {
		fmt.Printf("Error: 0x%02X\n", resp[0])
		return errorClrc663(resp[0])
	}

	//*

	// diff 2
	if err := write(c, 0x2C, []byte{0x18}); err != nil {
		return err
	}
	if err := write(c, 0x2D, []byte{0x18}); err != nil {
		return err
	}
	// TxDataNum
	if err := write(c, 0x2E, []byte{0x08}); err != nil {
		return err
	}
	// TxDATAModWith
	if err := write(c, 0x2F, []byte{0x20}); err != nil {
		return err
	}
	// TxSym10BurstLen
	if err := write(c, 0x30, []byte{0x0}); err != nil {
		return err
	}

	//*

	// FrameCon
	if err := write(c, 0x33, []byte{0xcf}); err != nil {
		return err
	}
	// diff 2
	// RxCtrl
	if err := write(c, 0x35, []byte{0x04}); err != nil {
		return err
	}
	// RxThreshold
	if err := write(c, 0x37, []byte{0x32}); err != nil {
		return err
	}
	// RxAna
	if err := write(c, 0x39, []byte{0x00}); err != nil {
		return err
	}
	// RxWait
	if err := write(c, 0x36, []byte{0x90}); err != nil {
		return err
	}
	// TxWaitCtrl
	if err := write(c, 0x31, []byte{0xC0}); err != nil {
		return err
	}
	// TxWaitLo
	if err := write(c, 0x32, []byte{0x0B}); err != nil {
		return err
	}

	//*

	// // diff 4
	// // T0ReloadHi
	// if err := write(c, 0x10, []byte{0x08}); err != nil {
	// 	return err
	// }
	// // T0ReloadLo
	// if err := write(c, 0x11, []byte{0xD8}); err != nil {
	// 	return err
	// }
	// // T1ReloadHi
	// if err := write(c, 0x15, []byte{0x00}); err != nil {
	// 	return err
	// }
	// // T1ReloadLo
	// if err := write(c, 0x16, []byte{0x00}); err != nil {
	// 	return err
	// }
	// //////////////////////////////////////

	// DrvMode
	if err := write(c, 0x28, []byte{0x81}); err != nil {
		return err
	}

	//*

	// // diff 6
	// // Status
	// if err := clearmask(c, 0x0B, 0x20); err != nil {
	// 	return err
	// }
	// ////////////////////////////////////////////
	// // TxBitMod
	// if err := setmask(c, 0x48, 0x20); err != nil {
	// 	return err
	// }
	// // RxBitMod
	// if err := setmask(c, 0x58, 0x02); err != nil {
	// 	return err
	// }
	// // DrvMode
	// if err := write(c, 0x28, []byte{0x89}); err != nil {
	// 	return err
	// }
	// // diff 5
	// // // reset IRQ
	// // if err := resetIRQ(c); err != nil {
	// // 	return err
	// // }
	return nil
}
