package ev2

func crc32b(message []byte) uint32 {

	crc := uint32(0)
	msb := uint32(0)

	// crc = 0xFFFFFFFF
	for i := 0; i < len(message); i++ {
		// xor next byte to upper bits of crc
		crc ^= uint32(message[i]) << 24
		for j := 0; j < 8; j++ { // Do eight times.
			msb = crc >> 31
			crc <<= 1
			crc ^= (0 - msb) & 0x04C11DB7
		}
	}
	return crc // don't complement crc on output
}

type crc32_table [256]uint32

func build_crc32_table(poly uint32) crc32_table {
	table := new(crc32_table)
	for i := uint32(0); i < 256; i++ {
		ch := i
		crc := uint32(0)
		for j := 0; j < 8; j++ {
			b := (ch ^ crc) & 1
			crc >>= 1
			if b != 0x00 {
				// crc = crc ^ 0xEDB88320
				crc = crc ^ poly
			}
			ch >>= 1
		}
		table[i] = crc
	}
	return *table
}

func crc32_fast(s []byte, table crc32_table) uint32 {
	crc := uint32(0xFFFFFFFF)

	for i := 0; i < len(s); i++ {
		ch := s[i]
		t := (ch ^ byte(crc&0xFF))
		crc = (crc >> 8) ^ table[t]
	}

	return crc
}
