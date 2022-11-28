package mifare

import (
	"reflect"
	"testing"
)

func TestAccessConditions(t *testing.T) {

	sectorTrailer := NewAccessBitsSectorTrailer().KeyB__WriteA_ReadWriteACL_WriteB___KeyA_readACL().SetPlain()
	block2 := NewAccessBits().Whole_AB().SetPlain()
	block1 := NewAccessBits().Whole_AB().SetPlain()
	block0 := NewAccessBits().Whole_AB().SetPlain()

	type args struct {
		sectorTrailer *AccessBitsSectorTrailer
		block2        *AccessBitsData
		block1        *AccessBitsData
		block0        *AccessBitsData
		sl3           bool
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "test1",
			args: args{
				sectorTrailer: sectorTrailer,
				block2:        block2,
				block1:        block1,
				block0:        block0,
				sl3:           true,
			},
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x7F, 0x07, 0x88, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AccessConditions(tt.args.sectorTrailer, tt.args.block2, tt.args.block1, tt.args.block0, tt.args.sl3); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AccessConditions() = [% X], want [% X]", got, tt.want)
			}
		})
	}
}
