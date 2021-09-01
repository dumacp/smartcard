package mifare

type AccessBitsData struct {
	c1    bool
	c2    bool
	c3    bool
	plain bool
}

type AccessBitsSectorTrailer struct {
	c1    bool
	c2    bool
	c3    bool
	plain bool
}

func NewAccessBits() *AccessBitsData {
	acl := &AccessBitsData{}
	return acl
}

func NewAccessBitsSectorTrailer() *AccessBitsSectorTrailer {
	acl := &AccessBitsSectorTrailer{}
	return acl
}

func (acl *AccessBitsData) SetPlain() *AccessBitsData {
	acl.plain = true
	return acl
}

func (acl *AccessBitsSectorTrailer) SetPlain() *AccessBitsSectorTrailer {
	acl.plain = true
	return acl
}

func (acl *AccessBitsData) Whole_AB() *AccessBitsData {
	acl.c1 = false
	acl.c2 = false
	acl.c3 = false

	return acl
}
func (acl *AccessBitsData) OnlyRead_AB() *AccessBitsData {
	acl.c1 = false
	acl.c2 = true
	acl.c3 = false

	return acl
}
func (acl *AccessBitsData) Read_AB_Write_B() *AccessBitsData {
	acl.c1 = true
	acl.c2 = false
	acl.c3 = false

	return acl
}
func (acl *AccessBitsData) Whole_B_Read_A_Value_A() *AccessBitsData {
	acl.c1 = true
	acl.c2 = true
	acl.c3 = false

	return acl
}
func (acl *AccessBitsData) Read_AB_Value_AB() *AccessBitsData {
	acl.c1 = false
	acl.c2 = false
	acl.c3 = true

	return acl
}
func (acl *AccessBitsData) ReadWrite_B() *AccessBitsData {
	acl.c1 = false
	acl.c2 = true
	acl.c3 = true

	return acl
}
func (acl *AccessBitsData) OnlyRead_B() *AccessBitsData {
	acl.c1 = true
	acl.c2 = false
	acl.c3 = true

	return acl
}
func (acl *AccessBitsData) Anything() *AccessBitsData {
	acl.c1 = true
	acl.c2 = true
	acl.c3 = true

	return acl
}

func (acl *AccessBitsSectorTrailer) KeyA__WriteA_ReadACL_ReadWriteB() *AccessBitsSectorTrailer {
	acl.c1 = false
	acl.c2 = false
	acl.c3 = false

	return acl
}
func (acl *AccessBitsSectorTrailer) KeyA__ReadACL_ReadB() *AccessBitsSectorTrailer {
	acl.c1 = false
	acl.c2 = true
	acl.c3 = false

	return acl
}
func (acl *AccessBitsSectorTrailer) KeyB__WriteA_ReadACL_WriteB___keyA__ReadACL() *AccessBitsSectorTrailer {
	acl.c1 = true
	acl.c2 = false
	acl.c3 = false

	return acl
}
func (acl *AccessBitsSectorTrailer) KeyAB__ReadACL() *AccessBitsSectorTrailer {
	acl.c1 = true
	acl.c2 = true
	acl.c3 = false

	return acl
}
func (acl *AccessBitsSectorTrailer) KeyA__ReadA_ReadWriteACL_ReadWriteB() *AccessBitsSectorTrailer {
	acl.c1 = false
	acl.c2 = false
	acl.c3 = true

	return acl
}
func (acl *AccessBitsSectorTrailer) KeyB__WriteA_ReadWriteACL_WriteB___KeyA_readACL() *AccessBitsSectorTrailer {
	acl.c1 = false
	acl.c2 = true
	acl.c3 = true

	return acl
}
func (acl *AccessBitsSectorTrailer) KeyB__ReadWriteACL___KeyA_readACL() *AccessBitsSectorTrailer {
	acl.c1 = true
	acl.c2 = false
	acl.c3 = true

	return acl
}
func (acl *AccessBitsSectorTrailer) KeyAB__ReadACL2() *AccessBitsSectorTrailer {
	acl.c1 = true
	acl.c2 = true
	acl.c3 = true

	return acl
}

func AccessConditions(sectorTrailer *AccessBitsSectorTrailer, block2, block1, block0 *AccessBitsData, sl3 bool) []byte {

	result := make([]byte, 16)

	result[6] = byte(
		BitPosition(7, !sectorTrailer.c2) |
			BitPosition(6, !block2.c2) |
			BitPosition(5, !block1.c2) |
			BitPosition(4, !block0.c2) |
			BitPosition(3, !sectorTrailer.c1) |
			BitPosition(2, !block2.c1) |
			BitPosition(1, !block1.c1) |
			BitPosition(0, !block0.c1))

	result[7] = byte(
		BitPosition(7, sectorTrailer.c1) |
			BitPosition(6, block2.c1) |
			BitPosition(5, block1.c1) |
			BitPosition(4, block0.c1) |
			BitPosition(3, !sectorTrailer.c3) |
			BitPosition(2, !block2.c3) |
			BitPosition(1, !block1.c3) |
			BitPosition(0, !block0.c3))

	result[8] = byte(
		BitPosition(7, sectorTrailer.c3) |
			BitPosition(6, block2.c3) |
			BitPosition(5, block1.c3) |
			BitPosition(4, block0.c3) |
			BitPosition(3, sectorTrailer.c2) |
			BitPosition(2, block2.c2) |
			BitPosition(1, block1.c2) |
			BitPosition(0, block0.c2))

	if sl3 {
		result[5] = byte(
			BitPosition(7, !sectorTrailer.plain) |
				BitPosition(6, !block2.plain) |
				BitPosition(5, !block1.plain) |
				BitPosition(4, !block0.plain) |
				BitPosition(3, sectorTrailer.plain) |
				BitPosition(2, block2.plain) |
				BitPosition(1, block1.plain) |
				BitPosition(0, block0.plain))
	}
	result[9] = 0xFF

	return result
}

func BitPosition(position int, bit bool) int {

	if !bit {
		return 0
	}
	if position > 31 || position < 0 {
		return 0
	}
	result := 0x01 << position
	return result
}
