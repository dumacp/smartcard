package ev2

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/pcsc"
)

func Test_desfire_AuthenticateEV2First(t *testing.T) {

	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal(err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatal(err)
	}

	var reader pcsc.Reader
	for i, r := range readers {
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "PICC") {
			reader = pcsc.NewReader(ctx, r)
		}
	}

	direct, err := reader.ConnectDirect()
	if err != nil {
		log.Fatal(err)
	}
	resp1, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp1: [% X]", resp1)
	}
	resp2, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x01, 0x8F})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp2: [% X]", resp2)
	}

	direct.DisconnectCard()

	cardi, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	type fields struct {
		ICard smartcard.ICard
	}
	type args struct {
		targetKey int
		keyNumber int
		pcdCap2   []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:   "test1",
			fields: fields{ICard: cardi},
			args: args{
				targetKey: 0,
				keyNumber: 0,
				pcdCap2:   nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &desfire{
				ICard: tt.fields.ICard,
			}

			_, err := d.GetApplicationsID()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetApplicationsID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_, err = d.SelectApplication([]byte{1, 0, 0}, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.SelectApplication() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_, err = d.GetApplicationsID()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetApplicationsID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := d.AuthenticateEV2First(tt.args.targetKey, tt.args.keyNumber, tt.args.pcdCap2)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.AuthenticateEV2First() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("desfire.AuthenticateEV2First() = [% X], want [% X]", got, tt.want)
			}
		})
	}
}

func Test_desfire_GetApplicationsID(t *testing.T) {

	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal(err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatal(err)
	}

	var reader pcsc.Reader
	for i, r := range readers {
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "PICC") {
			reader = pcsc.NewReader(ctx, r)
		}
	}

	direct, err := reader.ConnectDirect()
	if err != nil {
		log.Fatal(err)
	}
	resp1, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp1: [% X]", resp1)
	}
	resp2, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x01, 0x8F})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp2: [% X]", resp2)
	}

	direct.DisconnectCard()

	cardi, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	type fields struct {
		ICard smartcard.ICard
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:   "test1",
			fields: fields{ICard: cardi},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &desfire{
				ICard: tt.fields.ICard,
			}
			got, err := d.GetApplicationsID()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetApplicationsID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("desfire.GetApplicationsID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_desfire_CRC32(t *testing.T) {

	keystring := "D300000000120000010203040506070809101112131415161718"

	key, err := hex.DecodeString(keystring)
	if err != nil {
		t.Fatal(err)
	}

	crc32.NewIEEE().Sum(key)

	type args struct {
		data string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{
				// data: "3D00000000120000010203040506070809101112131415161718",
				data: "C40000102031405060708090A0B0B0A09080",
			},
			want: "3D00000000120000010203040506070809101112131415161718",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			key, err := hex.DecodeString(tt.args.data)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("key: [% X]", key)

			crc := ^crc32.ChecksumIEEE(key)
			// crc := crc32.ChecksumIEEE(key)
			// crc.Write(key)

			crcslice := make([]byte, 4)
			binary.LittleEndian.PutUint32(crcslice, crc)
			// datacrc := hex.EncodeToString(crc)

			if !reflect.DeepEqual(crc, tt.want) {
				t.Errorf("desfire.CRC32() = %X, %X, want %v", crc, crcslice, tt.want)
			}
		})
	}

}

func Test_desfire_AuthenticateISO(t *testing.T) {
	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal(err)
	}

	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatal(err)
	}

	var reader pcsc.Reader
	for i, r := range readers {
		log.Printf("reader %q: %s", i, r)
		if strings.Contains(r, "PICC") {
			reader = pcsc.NewReader(ctx, r)
		}
	}

	direct, err := reader.ConnectDirect()
	if err != nil {
		log.Fatal(err)
	}
	resp1, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x00})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp1: [% X]", resp1)
	}
	resp2, err := direct.ControlApdu(0x42000000+2079, []byte{0x23, 0x01, 0x8F})
	if err != nil {
		log.Fatal(err)
	} else {
		log.Printf("resp2: [% X]", resp2)
	}

	direct.DisconnectCard()

	cardi, err := reader.ConnectCardPCSC()
	if err != nil {
		log.Fatalln(err)
	}

	type fields struct {
		ICard smartcard.ICard
	}
	type args struct {
		targetKey int
		keyNumber int
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:   "test1",
			fields: fields{ICard: cardi},
			args: args{
				targetKey: 0,
				keyNumber: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &desfire{
				ICard: tt.fields.ICard,
			}

			_, err := d.GetApplicationsID()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetApplicationsID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_, err = d.SelectApplication([]byte{0, 0, 0}, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.SelectApplication() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_, err = d.GetApplicationsID()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetApplicationsID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			auth1, err := d.AuthenticateISO(tt.args.targetKey, tt.args.keyNumber)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.AuthenticateISO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			err = VerifyResponse(auth1)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.VerifyResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			auth2, err := d.AuthenticateISOPart2(make([]byte, 16), auth1[:])
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.AuthenticateISO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			err = VerifyResponse(auth2)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.VerifyResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(auth2, tt.want) {
				t.Errorf("desfire.AuthenticateISO() = %v, want %v", auth2, tt.want)
			}
		})
	}
}
