package clrc633

import "periph.io/x/conn/v3/spi"

func reset(c spi.Conn) error {
	if err := write(c, 0x00, []byte{0x1F}); err != nil {
		return err
	}
	return nil
}
