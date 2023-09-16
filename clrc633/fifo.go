package clrc633

import "periph.io/x/conn/v3/spi"

func writeFifo(c spi.Conn, data []byte) (int, error) {

	if err := setmask(c, 0x02, 0x10); err != nil {
		return 0, err
	}

	if err := write(c, 0x05, data); err != nil {
		return 0, err
	}

	response, err := read(c, []byte{0x04})
	if err != nil {
		return 0, err
	}

	return int(response[0]), nil
}

func ReadFifo(c spi.Conn, data []byte) error {

	length := len(data)
	var buff []byte
	if length > 512 {
		buff = make([]byte, 256)
	} else {
		buff = make([]byte, length)
	}

	for i := range buff {
		buff[i] = 0x05
	}
	response, err := read(c, buff)
	if err != nil {
		return err
	}
	copy(data, response)
	return nil
}
