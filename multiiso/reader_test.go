/**
package to handle the communication of smartcard devices under the PCSC implementation

projects on which it is based:

	https://github.com/LudovicRousseau/PCSC
	github.com/ebfe/scard

/**/
package multiiso

import "testing"

func Test_checksum(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want byte
	}{
		{
			name: "test1",
			args: args{
				data: []byte{0x02, 0x01, 0x01, 0x021, 0x20, 0x03},
			},
			want: 0x00,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checksum(tt.args.data); got != tt.want {
				t.Errorf("checksum() = %v, want %v", got, tt.want)
			}
		})
	}
}
