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
		data []byte
		ti   []byte
	}
	tests := []struct {
		name    string
		args    args
		want0   []byte
		want1   []byte
		want2   []byte
		wantErr bool
	}{
		{
			name: "test cipher functions",
			args: args{
				rndA: []byte{0xCF, 0xC1, 0x0C, 0x4F, 0x63, 0x05, 0x3E, 0x15, 0x08, 0x25, 0xC8, 0xC7, 0xE8, 0x05, 0xF3, 0x02},
				rndB: []byte{0xB0, 0xE4, 0x0C, 0x79, 0x7C, 0x50, 0xE1, 0xE4, 0x8E, 0x88, 0xBE, 0xD0, 0x4C, 0x9F, 0x95, 0x79},
				key:  []byte{0x8D, 0xDF, 0xF1, 0x51, 0xA6, 0xEF, 0x6A, 0x7F, 0xE6, 0xD0, 0x33, 0x3A, 0x42, 0xBE, 0x21, 0xEE}, //KEY in sector CARD
				data: []byte{0x32, 0x14, 0xA5, 0xF4, 0xDE, 0x18, 0xAE, 0xC8, 0xDA, 0x6F, 0x50, 0x33, 0x32, 0xB7, 0x10, 0xD7}, //DATA to write
				ti:   []byte{0xAA, 0xBB, 0xCC, 0x24},                                                                         //Transaction ID from CARD
			},
			want0: []byte{0xD1, 0x3C, 0xDB, 0x09, 0xCC, 0xD2, 0xE4, 0x2C, 0xE0, 0x5E, 0xD7, 0xB8, 0xB6, 0xEB, 0xC6, 0x87}, //KEY session to Enc
			want1: []byte{0x72, 0xA8, 0x2A, 0xEF, 0x1A, 0x1E, 0xA4, 0xB8, 0x69, 0x5C, 0x26, 0x08, 0x22, 0xA2, 0xA8, 0xE5}, //KEY session to Mac
			want2: []byte{0xBC, 0x43, 0x05, 0xFE, 0x72, 0x9F, 0xBD, 0x03},                                                 //MAC in command
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//Calculo de llaves de sesión

			keyEnc, keyMac, err := calcSessionKeyEV0(tt.args.rndA, tt.args.rndB, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("calcSessionKeyEV0() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(keyEnc, tt.want0) {
				t.Errorf("calcSessionKeyEV0() keyEnc = %X, want %v", keyEnc, tt.want0)
			}
			if !reflect.DeepEqual(keyMac, tt.want1) {
				t.Errorf("calcSessionKeyEV0() keyMac = %X, want %X", keyMac, tt.want1)
			}

			//Calcular CMAC para un comando de escritura con cifrado y mac (cmd: 0xA1)
			//bloque de destion 09 (bNr: 09)
			//los contadores se reinician a CERO

			readCount := 0
			writeCount := 0
			dataE, err := encCalc(readCount, writeCount, keyEnc, tt.args.ti, tt.args.data)
			if err != nil {
				t.Error(err)
			}

			//payload para el calculo de mac
			payload := []byte{0xA1}
			payload = append(payload, 0x00)
			payload = append(payload, 0x00)
			payload = append(payload, tt.args.ti...)
			payload = append(payload, 0x09)
			payload = append(payload, 0x00)
			payload = append(payload, dataE...)

			cmacReq, err := macCalc(keyMac, payload)
			if err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(cmacReq, tt.want2) {
				t.Logf("dataE = %X", dataE)
				t.Logf("payload = %X, len: %d", payload, len(payload))
				t.Errorf("calc cmac = %X, want %X", cmacReq, tt.want2)
			}
		})
	}
}
