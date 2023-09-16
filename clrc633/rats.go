package clrc633

import (
	"time"

	"periph.io/x/conn/v3/spi"
)

func rats(c spi.Conn, timeout time.Duration) ([]byte, error) {

	apdu := []byte{0xE8, 0x80}

	return sendApdu(c, apdu, timeout)

}
