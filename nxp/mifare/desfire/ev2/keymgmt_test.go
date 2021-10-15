package ev2

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/pcsc"
)

func Test_desfire_Crypto(t *testing.T) {
	key := "520E3D90BCD82896F6A200C446322CAE520E3C90BCD82896"
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	data := "10182029303840485058606870788088C9720E6300000000"
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}

	block, err := des.NewTripleDESCipher(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	mode := cipher.NewCBCEncrypter(block, make([]byte, 8))

	dest := make([]byte, len(dataBytes))
	mode.CryptBlocks(dest, dataBytes)

	t.Logf("result: [% X]", dest)
}

func Test_desfire_GetKeySettings(t *testing.T) {
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
			got, err := d.GetKeySettings()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetKeySettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("desfire.GetKeySettings() = %v, want %v", got, tt.want)
			}
		})
	}
}
