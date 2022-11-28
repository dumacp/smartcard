package samav2

import (
	"reflect"
	"testing"
)

func Test_samAv2_SETConfigurationSettings(t *testing.T) {

	type args struct {
		allowDumpSessionKey   bool
		keepIV                bool
		keyType               KeyType
		authKey               bool
		disableKeyEntry       bool
		lockKey               bool
		disableWritingKeyPICC bool
		disableDecryption     bool
		disableEncryption     bool
		disableVerifyMAC      bool
		disableGenMAC         bool
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{
				keyType:             AES_128,
				allowDumpSessionKey: true,
			},
			want: []byte{0x21, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SETConfigurationSettings(tt.args.allowDumpSessionKey, tt.args.keepIV, tt.args.keyType, tt.args.authKey, tt.args.disableKeyEntry, tt.args.lockKey, tt.args.disableWritingKeyPICC, tt.args.disableDecryption, tt.args.disableEncryption, tt.args.disableVerifyMAC, tt.args.disableGenMAC); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("samAv2.SETConfigurationSettings() = [ % X ], want [ % X ]", got, tt.want)
			}
		})
	}
}
