package clrc633

import (
	"fmt"
	"time"

	"periph.io/x/conn/v3/spi"
)

const (
	HIALERTIRQ = 0x40
	LOALERTIRQ = 0x20
	IDLEIRQ    = 0x01
	TXIRQ      = 0x08
	RXIRQ      = 0x04
	ERRIRQ     = 0x02
	RXSOFIRQ   = 0x01
	GLOBALIRQ  = 0x40
	LPCD_IRQ   = 0x20
	TIME4IRQ   = 0x10
	TIME3IRQ   = 0x08
	TIME2IRQ   = 0x04
	TIME1IRQ   = 0x02
	TIME0IRQ   = 0x01
)

type StatusIRQ struct {
	HiAlertIRQ bool
	LoAlertIRQ bool
	IdleIRQ    bool
	TxIRQ      bool
	RxIRQ      bool
	ErrIRQ     bool
	RxSOFIrq   bool
	GlobalIRQ  bool
	LPCD_IRQ   bool
	Time4IRQ   bool
	Time3IRQ   bool
	Time2IRQ   bool
	Time1IRQ   bool
	Time0IRQ   bool
}

func bit(data, cmp byte) bool { return data&cmp == cmp }

func resetIRQ(c spi.Conn) error {

	// IRQ0En register
	if err := write(c, 0x08, []byte{0x00}); err != nil {
		return err
	}

	// IRQ1En
	if err := write(c, 0x09, []byte{0x00}); err != nil {
		return err
	}

	// IRQ0 register
	if err := write(c, 0x06, []byte{0x7F}); err != nil {
		return err
	}

	// IRQ1 register
	if err := write(c, 0x07, []byte{0x7F}); err != nil {
		return err
	}
	return nil
}

func statusIRQ(c spi.Conn) (*StatusIRQ, error) {

	respIrq, err := read(c, []byte{0x06, 0x07})
	if err != nil {
		return nil, err
	}

	if len(respIrq) < 2 {
		return nil, err
	}

	// fmt.Printf("IRQ status -> IRQ0 (0x%02X), IRQ1 (0x%02X)\n", respIrq[0], respIrq[1])

	irq := &StatusIRQ{
		HiAlertIRQ: respIrq[0]&0x40 == 0x40,
		LoAlertIRQ: respIrq[0]&0x20 == 0x20,
		IdleIRQ:    respIrq[0]&0x10 == 0x10,
		TxIRQ:      respIrq[0]&0x08 == 0x08,
		RxIRQ:      respIrq[0]&0x04 == 0x04,
		ErrIRQ:     respIrq[0]&0x02 == 0x02,
		RxSOFIrq:   respIrq[0]&0x01 == 0x01,
		GlobalIRQ:  respIrq[1]&0x40 == 0x40,
		LPCD_IRQ:   respIrq[1]&0x20 == 0x20,
		Time4IRQ:   respIrq[1]&0x10 == 0x10,
		Time3IRQ:   respIrq[1]&0x08 == 0x08,
		Time2IRQ:   respIrq[1]&0x04 == 0x04,
		Time1IRQ:   respIrq[1]&0x02 == 0x02,
		Time0IRQ:   respIrq[1]&0x01 == 0x01,
	}

	return irq, nil

	// resp0, err := read(c, []byte{0x06})
	// if err != nil {
	// 	return
	// }
	// if len(resp0) < 1 {
	// 	return
	// }
	// resp1, err := read(c, []byte{0x07})
	// if err != nil {
	// 	return
	// }
	// if len(resp1) < 1 {
	// 	return
	// }
	// fmt.Printf("IRQ status -> IRQ0 (0x%02X), IRQ1 (0x%02X)\n", resp0[0], resp1[0])
}

func printStatusIRQ(c spi.Conn) {

	respIrq, err := read(c, []byte{0x06, 0x07})
	if err != nil {
		return
	}

	if len(respIrq) < 2 {
		return
	}

	fmt.Printf("IRQ status -> IRQ0 (0x%02X), IRQ1 (0x%02X)\n", respIrq[0], respIrq[1])

	// resp0, err := read(c, []byte{0x06})
	// if err != nil {
	// 	return
	// }
	// if len(resp0) < 1 {
	// 	return
	// }
	// resp1, err := read(c, []byte{0x07})
	// if err != nil {
	// 	return
	// }
	// if len(resp1) < 1 {
	// 	return
	// }
	// fmt.Printf("IRQ status -> IRQ0 (0x%02X), IRQ1 (0x%02X)\n", resp0[0], resp1[0])
}

func waitIRQ(c spi.Conn, addrIrq, value byte, timeout time.Duration) error {

	t1 := time.NewTimer(timeout)
	defer t1.Stop()
	t2 := time.NewTicker(3 * time.Millisecond)
	defer t2.Stop()
	for {
		resp, err := read(c, []byte{addrIrq})
		if err != nil {
			return err
		}
		select {
		case <-t2.C:
			if value == (resp[0] & value) {
				// fmt.Printf("read byte IRQ (0x%02X): 0x%02X\n", addrIrq, resp[0])
				return nil
			}
		case <-t1.C:
			// fmt.Printf("read byte IRQ (0x%02X): 0x%02X\n", addrIrq, resp[0])
			return ErrorReadTimeout
		}
	}
}

func waitRxIRQ(c spi.Conn, timerId byte, timeout time.Duration) error {

	if err := setmask(c, 0x08, 0x06); err != nil {
		return err
	}
	if err := setmask(c, 0x09, (0x40 | timerId)); err != nil {
		return err
	}

	t1 := time.NewTimer(timeout)
	defer t1.Stop()
	t2 := time.NewTicker(1 * time.Millisecond)
	defer t2.Stop()
	var statusIrq *StatusIRQ
	for {
		select {
		case <-t2.C:
			var err error
			statusIrq, err = statusIRQ(c)
			if err != nil {
				return err
			}
			if statusIrq.GlobalIRQ {
				if statusIrq.ErrIRQ {
					return errorGetClrc663(c)
				} else if statusIrq.RxIRQ {
					// fmt.Printf("status irq: %+v\n", statusIrq)
					return nil
				} else {
					// fmt.Printf("status irq: %+v\n", statusIrq)
					switch timerId {
					case 0x01:
						if statusIrq.Time0IRQ {
							return ErrorReadTimeout
						}
					case 0x02:
						if statusIrq.Time1IRQ {
							return ErrorReadTimeout
						}
					case 0x04:
						if statusIrq.Time2IRQ {
							return ErrorReadTimeout
						}
					case 0x08:
						if statusIrq.Time3IRQ {
							return ErrorReadTimeout
						}
					case 0x10:
						if statusIrq.Time4IRQ {
							return ErrorReadTimeout
						}
					}
				}
			}
		case <-t1.C:
			// fmt.Printf("final status irq: %+v\n", statusIrq)
			// fmt.Printf("read byte IRQ (0x%02X): 0x%02X\n", addrIrq, resp[0])
			return ErrorReadTimeout
		}
	}
}

func waitTxIRQ(c spi.Conn, timerId byte, timeout time.Duration) error {

	if err := setmask(c, 0x08, 0x0A); err != nil {
		return err
	}
	if err := setmask(c, 0x09, (0x40 | timerId)); err != nil {
		return err
	}

	t1 := time.NewTimer(timeout)
	defer t1.Stop()
	t2 := time.NewTicker(3 * time.Millisecond)
	defer t2.Stop()
	var statusIrq *StatusIRQ
	for {
		select {
		case <-t2.C:
			var err error
			statusIrq, err = statusIRQ(c)
			if err != nil {
				return err
			}
			if statusIrq.GlobalIRQ {
				if statusIrq.ErrIRQ {
					return errorGetClrc663(c)
				} else if statusIrq.TxIRQ {
					return nil
				} else {
					// fmt.Printf("status irq: %+v\n", statusIrq)
					switch timerId {
					case 0x01:
						if statusIrq.Time0IRQ {
							return ErrorReadTimeout
						}
					case 0x02:
						if statusIrq.Time1IRQ {
							return ErrorReadTimeout
						}
					case 0x04:
						if statusIrq.Time2IRQ {
							return ErrorReadTimeout
						}
					case 0x08:
						if statusIrq.Time3IRQ {
							return ErrorReadTimeout
						}
					case 0x10:
						if statusIrq.Time4IRQ {
							return ErrorReadTimeout
						}
					}
				}
			}
		case <-t1.C:
			// fmt.Printf("read byte IRQ (0x%02X): 0x%02X\n", addrIrq, resp[0])
			// fmt.Printf("final status irq: %+v\n", statusIrq)
			return ErrorReadTimeout
		}
	}
}

func waitIdleIRQ(c spi.Conn, timerId byte, timeout time.Duration) error {

	if err := setmask(c, 0x08, 0x12); err != nil {
		return err
	}
	if err := setmask(c, 0x09, (0x40 | timerId)); err != nil {
		return err
	}

	t1 := time.NewTimer(timeout)
	defer t1.Stop()
	t2 := time.NewTicker(3 * time.Millisecond)
	defer t2.Stop()
	var statusIrq *StatusIRQ
	for {
		select {
		case <-t2.C:
			var err error
			statusIrq, err = statusIRQ(c)
			if err != nil {
				return err
			}
			if statusIrq.GlobalIRQ {
				if statusIrq.ErrIRQ {
					return errorGetClrc663(c)
				} else if statusIrq.IdleIRQ {
					// fmt.Printf("status irq: %+v\n", statusIrq)
					return nil
				} else {
					// fmt.Printf("status irq: %+v\n", statusIrq)
					switch timerId {
					case 0x01:
						if statusIrq.Time0IRQ {
							return ErrorReadTimeout
						}
					case 0x02:
						if statusIrq.Time1IRQ {
							return ErrorReadTimeout
						}
					case 0x04:
						if statusIrq.Time2IRQ {
							return ErrorReadTimeout
						}
					case 0x08:
						if statusIrq.Time3IRQ {
							return ErrorReadTimeout
						}
					case 0x10:
						if statusIrq.Time4IRQ {
							return ErrorReadTimeout
						}
					}
				}
			}
		case <-t1.C:
			// fmt.Printf("final status irq: %+v\n", statusIrq)
			// fmt.Printf("read byte IRQ (0x%02X): 0x%02X\n", addrIrq, resp[0])
			return ErrorReadTimeout
		}
	}
}
