package ev2

import (
	"encoding/hex"
	"hash/crc32"
	"testing"
)

func Test_crc32b(t *testing.T) {

	keystring := "3D00000000120000010203040506070809101112131415161718"
	key, err := hex.DecodeString(keystring)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("key: [% X]", key)

	type args struct {
		message []byte
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{
			name: "test1",
			args: args{
				message: key,
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crc32b(tt.args.message); got != tt.want {
				t.Errorf("crc32b() = %X, want %X", got, tt.want)
			}
		})
	}
}

func Test_crc32_fast(t *testing.T) {

	keystring := "3D00000000120000010203040506070809101112131415161718"
	key, err := hex.DecodeString(keystring)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("key: [% X]", key)

	// table := build_crc32_table(0x04C11DB7)
	table := build_crc32_table(crc32.IEEE)

	type args struct {
		s     []byte
		table crc32_table
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{
			name: "test1",
			args: args{
				s:     key,
				table: table,
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crc32_fast(tt.args.s, tt.args.table); got != tt.want {
				t.Errorf("crc32_fast() = %X, want %X", got, tt.want)
			}
		})
	}
}
