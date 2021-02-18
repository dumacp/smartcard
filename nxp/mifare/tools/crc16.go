package tools

//Crc16 calculate CRC16
func Crc16(data []byte) []byte {
	crc := uint32(0x6363)
	for _, x := range data {
		crc = updateCrc16(crc, uint32(x))
	}
	return []byte{byte(crc & 0xff), byte((crc >> 8) & 0xFF)}
}

func updateCrc16(crc, c uint32) uint32 {

	tcrc := uint32(0)

	v := (crc ^ c) & 0xFF
	for range []int{0, 1, 2, 3, 4, 5, 6, 7} {
		if ((tcrc ^ v) & 1) != 0 {
			tcrc = ((tcrc >> 1) ^ 0x8408) & 0xffff
		} else {
			tcrc = tcrc >> 1
		}
		v = v >> 1
	}

	return ((crc >> 8) ^ tcrc) & 0xffff
}
