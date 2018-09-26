package mifare


import (
        _ "fmt"
	"flag"
	"encoding/hex"
	"strings"
        "testing"
	"github.com/dumacp/smartcard"
)

var keyS string

func init() {
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
}


/**
func TestGetVersion(t *testing.T) {
	t.Log("Start Logs")
	ctx, err := smartcard.NewContext()
	if err != nil {
                t.Fatal("Not connection")
        }
	defer ctx.Release()

	readers, err := smartcard.ListReaders(ctx)
	for i, el := range readers {
		t.Logf("reader %v: %s\n", i, el)
	}

	samReaders := make([]smartcard.Reader,0)
	for _, el := range readers {
		if strings.Contains(el, "SAM") {
			samReaders = append(samReaders, smartcard.NewReader(ctx, el))
		}
	}

	for _, samReader := range samReaders {
		//sam, err := samReader.ConnectSamAv2()
		sam, err := ConnectSamAv2(samReader)
		if err != nil {
			t.Logf("%s\n",err)
			continue
		}
		version, err := sam.GetVersion()
		if err != nil {
			t.Error("Not GetVersion: ", err)
		}
		t.Logf("GetVersion sam: % X\n", version)
		t.Logf("GetVersion sam: %s\n", string(version))
		atr, err := sam.ATR()
		if err != nil {
			t.Error("Not ATR: ", err)
		}
		t.Logf("ATR sam: % X\n", atr)
		sam.DisconnectCard()
	}
}
/**/
/**/
func TestGetData(t *testing.T) {
	t.Log("Start Logs")
	flag.Parse()
	ctx, err := smartcard.NewContext()
	if err != nil {
                t.Fatal("Not connection")
        }
	defer ctx.Release()

	readers, err := smartcard.ListReaders(ctx)
	for i, el := range readers {
		t.Logf("reader %v: %s\n", i, el)
	}

	piccReaders := make([]smartcard.Reader,0)
	for _, el := range readers {
		if strings.Contains(el, "PICC") {
			piccReaders = append(piccReaders, smartcard.NewReader(ctx, el))
		}
	}

	for _, piccReader := range piccReaders {
		t.Logf("picc reader: %s\n", piccReader)
		picc, err := piccReader.ConnectCard()
		if err != nil {
			t.Errorf("%s\n",err)
		}

		resp1, err := picc.UID()
		t.Logf("picc UID: % X\n", resp1)
		if err != nil {
			t.Error("%s\n",err)
		}

		resp2, err := picc.ATR()
		t.Logf("picc ATR: % X\n", resp2)
		if err != nil {
			t.Error("%s\n",err)
		}

		resp3, err := picc.ATS()
		t.Logf("picc ATS: % X\n", resp3)
		if err != nil {
			t.Error("%s\n",err)
		}
		picc.DisconnectCard()
	}
}
/**/

/**
func TestAuthHostAV2(t *testing.T) {
	t.Log("Start Logs")
	ctx, err := smartcard.NewContext()
	if err != nil {
                t.Fatal("Not connection")
        }
	defer ctx.Release()

	readers, err := smartcard.ListReaders(ctx)
	for i, el := range readers {
		t.Logf("reader %v: %s\n", i, el)
	}

	samReaders := make([]smartcard.Reader,0)
	for _, el := range readers {
		if strings.Contains(el, "SAM") {
			samReaders = append(samReaders, smartcard.NewReader(ctx, el))
		}
	}

	for _, samReader := range samReaders {
		t.Logf("sam reader: %s\n", samReader)
		//sam, err := samReader.ConnectSamAv2()
		sam, err := ConnectSamAv2(samReader)
		if err != nil {
			t.Error("%s\n",err)
		}
		version, err := sam.GetVersion()
		if err != nil {
			t.Error("Not GetVersion: ", err)
		}
		t.Logf("GetVersion sam: % X\n", version)
		keyI, err := hex.DecodeString(keyS)
		if err != nil {
			t.Fatal(err)
		}
		key := make([]byte, 16)

		for i, v := range keyI {
			key[i] = byte(v)
		}

		resp, err := sam.AuthHostAV2(key, 100)
		if err != nil {
			t.Error("Not Auth: ", err)
		}
		t.Logf("auth sam: % X\n", resp)
		sam.DisconnectCard()
	}
}
/**/
/**/
func TestNonAuthMFP(t *testing.T) {
	t.Log("Start Logs")
	flag.Parse()
	ctx, err := smartcard.NewContext()
	if err != nil {
                t.Fatal("Not connection")
        }
	defer ctx.Release()

	readers, err := smartcard.ListReaders(ctx)
	for i, el := range readers {
		t.Logf("reader %v: %s\n", i, el)
	}

	var sam SamAv2
	var mplus MifarePlus
	samReaders := make([]smartcard.Reader,0)
	for _, el := range readers {
		if strings.Contains(el, "SAM") {
			samReaders = append(samReaders, smartcard.NewReader(ctx, el))
		}
	}

	for _, samReader := range samReaders {
		t.Logf("sam reader: %s\n", samReader)
		//sam, err := samReader.ConnectSamAv2()
		sam, err = ConnectSamAv2(samReader)
		if err != nil {
			t.Error("%s\n",err)
		}
		version, err := sam.GetVersion()
		if err != nil {
			t.Error("Not GetVersion: ", err)
		}
		t.Logf("GetVersion sam: % X\n", version)

		key, err := hex.DecodeString(keyS)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := sam.AuthHostAV2(key, 100)
		if err != nil {
			t.Error("Not Auth: ", err)
		}
		t.Logf("auth sam: [% X]\n", resp)

		//sam.DisconnectCard()
	}

	mplusReaders := make([]smartcard.Reader,0)
	for _, el := range readers {
		if strings.Contains(el, "PICC") {
			mplusReaders = append(mplusReaders, smartcard.NewReader(ctx, el))
		}
	}

	for _, mplusReader := range mplusReaders {
		rCounter := 0
		wCounter := 0
		t.Logf("mplus reader: %s\n", mplusReader)
		mplus, err = ConnectMplus(mplusReader)
		if err != nil {
			t.Errorf("%s\n",err)
		}
		resp, err := mplus.UID()
		t.Logf("mplus uuid: % X\n", resp)
		if err != nil {
			t.Error("%s\n",err)
		}
		dataDiv := make([]byte,4)
		dataDiv = append(dataDiv,resp[0:4]...)

		//resp, err = mplus.FirstAuthf1(0x4002)
		resp, err = mplus.FirstAuthf1(0x4005)
		if err != nil {
			t.Fatalf("%s\n",err)
		}
		//resp, err = sam.NonXauthMFPf1(true,3,0x07,0x00,resp,nil)
		resp, err = sam.NonXauthMFPf1(true,3,0x01,0x00,resp,dataDiv)
		if err != nil {
			t.Fatalf("%s\n",err)
		}
		t.Logf("aid f2: [% X]\n", resp)
		resp, err = mplus.FirstAuthf2(resp[0:len(resp)-2])
		if err != nil {
			t.Errorf("%s\n",err)
		}
		resp, err = sam.NonXauthMFPf2(resp)
		if err != nil {
			t.Errorf("%s\n",err)
		}
		t.Logf("auth mplus: [% X]\n", resp)

		resp, err = sam.DumpSessionKey()
		if err != nil {
			t.Fatalf("%s\n",err)
		}
		t.Logf("sessionKey mplus: [% X]\n", resp)

		keyEnc := resp[0:16]
		keyMac := resp[16:32]
		t.Logf("key Mac: [% X]\n", keyMac)
		Ti := resp[32:36]
		t.Logf("Ti: [% X]\n", Ti)
		readCounter := resp[36:38]
		t.Logf("Read Counter: [% X]\n", readCounter)
		writeCounter := resp[38:40]
		t.Logf("wrtie Counter: [% X]\n", writeCounter)

		//resp, err = mplus.ReadEncMacMac(4,1,rCounter,wCounter,Ti,keyMac,keyEnc)
		resp, err = mplus.ReadEncMacMac(8,1,rCounter,wCounter,Ti,keyMac,keyEnc)
		if err != nil {
			t.Fatalf("%s\n",err)
		}
		t.Logf("read 4 resp: [% X]\n", resp)

		//rCounter++
		//err = mplus.WriteEncMacMac(8,resp,rCounter,wCounter,Ti,keyMac,keyEnc)
		//if err != nil {
		//	t.Fatalf("%s\n",err)
		//}

		//mplus.DisconnectCard()
	}
	sam.DisconnectCard()
	mplus.DisconnectCard()
}
/**/

