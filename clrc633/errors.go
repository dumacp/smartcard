package clrc633

import (
	"errors"
	"fmt"

	"periph.io/x/conn/v3/spi"
)

var ErrorReadTimeout = errors.New("timeout reading")

var ErrorEEPROM = errors.New("error appeared during the last EEPROM command")

var ErrorFIFOWr = errors.New(`data was written into the FIFO, during a transmission of a possible CRC, during "RxWait", "Wait for data" or "Receiving" state, or during an authentication command`)
var ErrorFIFOOvl = errors.New("data is written into the FIFO when it is already full")
var ErrorMinFrame = errors.New("a valid SOF was received, but afterwards less than 4 bits of data were received")
var ErrorNoData = errors.New("data should be sent, but no data is in FIFO")
var ErrorCollDet = errors.New("a collision has occurred. The position of the first collision is shown in the register RxColl")
var ErrorProt = errors.New("a protocol error has occurred")
var ErrorInteg = errors.New("a data integrity error has been detected. Possible cause can be a wrong parity or a wrong CRC")

var ErrorIRQ = errors.New("the one of the following errors is set: FifoWrErr, FiFoOvl, ProtErr, NoDataErr, IntegErr")
var ErrorUnsupported = errors.New("unsupport")

func errorClrc663(err byte) error {
	switch {
	case err&0x80 == 0x80:
		return ErrorEEPROM
	case err&0x40 == 0x40:
		return ErrorFIFOWr
	case err&0x20 == 0x20:
		return ErrorFIFOOvl
	case err&0x10 == 0x10:
		return ErrorMinFrame
	case err&0x08 == 0x08:
		return ErrorNoData
	case err&0x04 == 0x04:
		return ErrorCollDet
	case err&0x02 == 0x02:
		return ErrorProt
	case err&0x01 == 0x01:
		return ErrorInteg
	}
	fmt.Printf("error byte: 0x%02X\n", err)

	return nil
}

func errorGetClrc663(c spi.Conn) error {
	resp, err := read(c, []byte{0x0A})
	if err != nil {
		return err
	}
	erro := resp[0]
	switch {
	case erro&0x80 == 0x80:
		return ErrorEEPROM
	case erro&0x40 == 0x40:
		return ErrorFIFOWr
	case erro&0x20 == 0x20:
		return ErrorFIFOOvl
	case erro&0x10 == 0x10:
		return ErrorMinFrame
	case erro&0x08 == 0x08:
		return ErrorNoData
	case erro&0x04 == 0x04:
		return ErrorCollDet
	case erro&0x02 == 0x02:
		return ErrorProt
	case erro&0x01 == 0x01:
		return ErrorInteg
	}
	// fmt.Printf("error byte: 0x%02X\n", erro)

	return nil
}
