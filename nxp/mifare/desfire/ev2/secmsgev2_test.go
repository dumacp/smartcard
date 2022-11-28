package ev2

import (
	"crypto/aes"
	"reflect"
	"testing"
)

func Test_calcCommandIVOnFullModeEV2(t *testing.T) {
	type args struct {
		ksesAuthEnc []byte
		ti          []byte
		cmdCtr      uint16
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "test1",
			args: args{
				ksesAuthEnc: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				ti:          []byte{0x0A, 0x0B, 0x0C, 0x0D},
				cmdCtr:      3,
			},
			want:    []byte{0x52, 0x82, 0x83, 0xB1, 0xF5, 0x72, 0xA7, 0x7B, 0x44, 0xBF, 0xFC, 0xA4, 0xD1, 0xF8, 0x9A, 0x49},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := calcCommandIVOnFullModeEV2(tt.args.ksesAuthEnc, tt.args.ti, tt.args.cmdCtr)
			if (err != nil) != tt.wantErr {
				t.Errorf("calcCommandIVOnFullModeEV2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("calcCommandIVOnFullModeEV2() = [%X], want [%X]", got, tt.want)
			}
		})
	}
}

func Test_calcMacOnCommandEV2(t *testing.T) {
	type args struct {
		ksesAuthEnc []byte
		ti          []byte
		cmd         byte
		cmdCtr      uint16
		cmdHeader   []byte
		data        []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "test1",
			args: args{
				ksesAuthEnc: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				ti:          []byte{0x0A, 0x0B, 0x0C, 0x0D},
				cmd:         0xCA,
				cmdCtr:      3,
				cmdHeader:   []byte{0x00, 0x01},
			},
			want:    []byte{0x9D, 0xA1, 0x9B, 0xEF, 0x7A, 0xBB, 0x8A, 0x6C},
			wantErr: false,
		},
	}
	for _, tt := range tests {

		block, err := aes.NewCipher(tt.args.ksesAuthEnc)
		if err != nil {
			t.Error(err)
		}
		t.Run(tt.name, func(t *testing.T) {
			got, err := calcMacOnCommandEV2(block, tt.args.ti, tt.args.cmd, tt.args.cmdCtr, tt.args.cmdHeader, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("calcMacOnCommandEV2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("calcMacOnCommandEV2() = [%X], want [%X]", got, tt.want)
			}
		})
	}
}

func Test_calcCryptogramEV2(t *testing.T) {
	type args struct {
		ksesAuthEnc []byte
		plaindata   []byte
		iv          []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "test1",
			args: args{
				ksesAuthEnc: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				plaindata:   []byte("prueba de cifrado"),
				iv:          []byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25},
			},
			want: []byte{0x01, 0x2F, 0xAA, 0x54, 0x34, 0x8E, 0xEB, 0xBC, 0xB0, 0xF1, 0xFD,
				0x76, 0x5F, 0x42, 0x82, 0xB5, 0xA4, 0x58, 0x6C, 0xBA, 0x66, 0xD4, 0x86, 0xAC,
				0xAC, 0xE5, 0x91, 0x1B, 0x2C, 0x6A, 0x2F, 0x27},
		},
	}
	for _, tt := range tests {
		block, err := aes.NewCipher(tt.args.ksesAuthEnc)
		if err != nil {
			t.Error(err)
		}
		t.Run(tt.name, func(t *testing.T) {
			if got := calcCryptogramEV2(block, tt.args.plaindata, tt.args.iv); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("calcCryptogramEV2() = [%X], want [%X]", got, tt.want)
			}
		})
	}
}
