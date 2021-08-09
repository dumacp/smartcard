/**
Implementation to mifare smartcard family (Mifare Plus, Desfire, SamAV2, ...)
/**/
package mifare

import (
	"reflect"
	"testing"
)

func Test_calcSessionKeyEV0(t *testing.T) {
	type args struct {
		rndA []byte
		rndB []byte
		key  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		want1   []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{
				rndA: []byte{0xCF, 0xC1, 0x0C, 0x4F, 0x63, 0x05, 0x3E, 0x15, 0x08, 0x25, 0xC8, 0xC7, 0xE8, 0x05, 0xF3, 0x02},
				rndB: []byte{0xB0, 0xE4, 0x0C, 0x79, 0x7C, 0x50, 0xE1, 0xE4, 0x8E, 0x88, 0xBE, 0xD0, 0x4C, 0x9F, 0x95, 0x79},
				key:  []byte{0x8D, 0xDF, 0xF1, 0x51, 0xA6, 0xEF, 0x6A, 0x7F, 0xE6, 0xD0, 0x33, 0x3A, 0x42, 0xBE, 0x21, 0xEE},
			},
			want1: []byte{0x72, 0xA8, 0x2A, 0xEF, 0x1A, 0x1E, 0xA4, 0xB8, 0x69, 0x5C, 0x26, 0x08, 0x22, 0xA2, 0xA8, 0xE5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := calcSessionKeyEV0(tt.args.rndA, tt.args.rndB, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("calcSessionKeyEV0() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("calcSessionKeyEV0() got = %X, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("calcSessionKeyEV0() got1 = %X, want %X", got1, tt.want1)
			}
		})
	}
}
