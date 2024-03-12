package clrc633

import (
	"fmt"

	"periph.io/x/conn/v3/driver/driverreg"
	"periph.io/x/conn/v3/physic"
	"periph.io/x/conn/v3/spi"
	"periph.io/x/conn/v3/spi/spireg"
	"periph.io/x/host/v3"
)

func connect(devicePath string) (spi.PortCloser, spi.Conn, error) {
	if _, err := host.Init(); err != nil {
		return nil, nil, err
	}
	if _, err := driverreg.Init(); err != nil {
		return nil, nil, err
	}

	// Use spireg SPI port registry to find the first available SPI bus.
	p, err := spireg.Open(devicePath)
	if err != nil {
		return nil, nil, err
	}
	// defer p.Close()

	fmt.Printf("device: %v\n", p)

	// Convert the spi.Port into a spi.Conn so it can be used for communication.
	c, err := p.Connect(physic.GigaHertz, spi.Mode0, 8)
	// c, err := p.Connect(0x40046b04, spi.Mode3, 8)
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("mode: %s\n", spi.Mode0.String())

	// Prints out the gpio pin used.
	if p, ok := c.(spi.Pins); ok {
		fmt.Printf("  CLK : %s\n", p.CLK())
		fmt.Printf("  MOSI: %s\n", p.MOSI())
		fmt.Printf("  MISO: %s\n", p.MISO())
		fmt.Printf("  CS  : %s\n", p.CS())
	}

	return p, c, nil
}

func close(p spi.PortCloser) error {
	return p.Close()
}

func write(c spi.Conn, regAdrr byte, data []byte) error {

	addr := regAdrr << 1
	buff := make([]byte, 0)
	buff = append(buff, addr)
	buff = append(buff, data...)
	if err := c.Tx(buff, nil); err != nil {
		return err
	}

	// for _, v := range data {
	// 	addr := regAdrr << 1
	// 	buff := make([]byte, 0)
	// 	buff = append(buff, addr)
	// 	buff = append(buff, v)
	// 	if err := c.Tx(buff, nil); err != nil {
	// 		return err
	// 	}
	// }
	return nil
}

func read(c spi.Conn, regAdrr []byte) ([]byte, error) {

	buffWrite := make([]byte, 0)

	for _, addr := range regAdrr {
		buffWrite = append(buffWrite, addr<<1|1)
		// if len(regAdrr) > 1 {
		// 	buffWrite = append(buffWrite, regAdrr[1:]...)
		// }
	}
	buffWrite = append(buffWrite, 0x00)
	buffRead := make([]byte, len(buffWrite))
	if err := c.Tx(buffWrite, buffRead); err != nil {
		return nil, err
	}
	return buffRead[1:], nil
}

func setmask(c spi.Conn, regAdrr, mask byte) error {

	current, err := read(c, []byte{regAdrr})
	if err != nil {
		return err
	}

	if err := write(c, regAdrr, []byte{current[0] | mask}); err != nil {
		return err
	}

	return err

}

func clearmask(c spi.Conn, regAdrr, mask byte) error {

	current, err := read(c, []byte{regAdrr})
	if err != nil {
		return err
	}
	if err := write(c, regAdrr, []byte{current[0] & ^mask}); err != nil {
		return err
	}
	return err
}
