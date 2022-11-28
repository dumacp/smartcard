package ev2

import (
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/dumacp/smartcard"
	"github.com/dumacp/smartcard/pcsc"
)

func Test_desfire_GetVersion(t *testing.T) {

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
		want    [][]byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			fields: fields{
				ICard: cardi,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Desfire{
				ICard: tt.fields.ICard,
			}
			got, err := d.GetVersion()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("desfire.GetVersion() = [%X], want [% X]", got, tt.want)
			}
		})
	}
}

func Test_desfire_GetCardUID(t *testing.T) {
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
		want    [][]byte
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			fields: fields{
				ICard: cardi,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Desfire{
				ICard: tt.fields.ICard,
			}
			auth1, err := d.AuthenticateEV2First(0, 0, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.AuthenticateISO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			err = VerifyResponse(auth1)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.VerifyResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			auth2, err := d.AuthenticateEV2FirstPart2(make([]byte, 16), auth1[:])
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.AuthenticateISO() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			err = VerifyResponse(auth2)
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.VerifyResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// _, err = d.GetCardUID()
			// if (err != nil) != tt.wantErr {
			// 	t.Errorf("desfire.GetCardUID() error = %v, wantErr %v", err, tt.wantErr)
			// 	return
			// }
			got, err := d.GetCardUID()
			if (err != nil) != tt.wantErr {
				t.Errorf("desfire.GetCardUID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("desfire.GetCardUID() = [% X], want %v", got, tt.want)
			}
		})
	}
}
