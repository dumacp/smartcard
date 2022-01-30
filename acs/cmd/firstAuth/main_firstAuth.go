package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/nmelo/smartcard/nxp/mifare"
	"github.com/nmelo/smartcard/nxp/mifare/samav2"
	"github.com/nmelo/smartcard/pcsc"
	MQTT "github.com/eclipse/paho.mqtt.golang"
)

var keyS string
var keyNbr int
var urlBroker string
var respChan chan Response

func init() {
	flag.StringVar(&urlBroker, "urlBroker", "tcp://127.0.0.1:1883", "MQTT url broker")
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
	flag.IntVar(&keyNbr, "keyNbr", 0x4002, "key Number")
	respChan = make(chan Response)
}

type Response struct {
	channel uint64
	data    []byte
}

var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {
	log.Printf("TOPIC: %s\n", msg.Topic())
	log.Printf("MSG: % X\n", msg.Payload())
	spl1 := strings.Split(msg.Topic(), "/")
	uuid := spl1[len(spl1)-1]
	u, _ := strconv.ParseUint(uuid, 16, 64)
	select {
	case respChan <- Response{u, msg.Payload()}:
	case <-time.After(time.Second * 10):
		log.Printf("TIMEOUT!!!\n")
	}
}

func main() {
	flag.Parse()

	clientId := fmt.Sprintf("go-samfarm-client-%v", time.Now().UnixNano())
	opts := MQTT.NewClientOptions().AddBroker(urlBroker)
	opts.SetClientID(clientId)
	opts.SetDefaultPublishHandler(f)

	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}
	defer c.Disconnect(100)

	if token := c.Subscribe("SAMFARM/RESP/#", 0, nil); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	key, err := hex.DecodeString(keyS)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("key: [% X]\n", key)

	ctx, err := pcsc.NewContext()
	if err != nil {
		log.Fatal("Not connection")
	}
	defer ctx.Release()
	readers, err := pcsc.ListReaders(ctx)
	for i, el := range readers {
		log.Printf("reader %v: %s\n", i, el)
	}
	mplusReaders := make([]pcsc.Reader, 0)
	for _, el := range readers {
		if strings.Contains(el, "PICC") {
			mplusReaders = append(mplusReaders, pcsc.NewReader(ctx, el))
		}
	}
	for _, mplusReader := range mplusReaders {
		mplus, err := mifare.ConnectMplus(mplusReader)
		if err != nil {
			log.Printf("%s\n", err)
			continue
		}
		uid, err := mplus.UID()
		if err != nil {
			log.Fatalln("ERROR: ", err)
		}
		log.Printf("card UID: % X\n", uid)

		ats, err := mplus.ATS()
		if err != nil {
			log.Println("ERROR: ", err)
		}
		log.Printf("card ATS: % X\n", ats)

		/**
		resp, err := mplus.FirstAuth(0x4005,key)
		if err != nil {
			log.Fatalf("Error: %s\n",err)
		}
		log.Printf("Auth: % X\n", resp)
		/**/
		resp, err := mplus.FirstAuthf1(0x4004)
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("Auth f1: %X\n", resp)
		// dataDiv := make([]byte, 4)
		// dataDiv = append(dataDiv, uid[0:4]...)
		var dataDiv []byte
		apdu1 := samav2.ApduNonXauthMFPf1(true, 3, 11, 0x00, resp, dataDiv)
		log.Printf("SEND TOPIC: %s\n", fmt.Sprintf("SAMFARM/ASYN/123/%X", uid[0:4]))
		token := c.Publish(fmt.Sprintf("SAMFARM/ASYN/123/%X", uid[0:4]), 0, false, apdu1)
		token.Wait()

		log.Printf("WAIT SAM\n")
		respSam12 := <-respChan
		respSam1 := respSam12.data
		log.Printf("SAM resp: % X\n", respSam1)
		resp2, err := mplus.FirstAuthf2(respSam1[0 : len(respSam1)-2])
		if err != nil {
			log.Fatalf("Error: %s\n", err)
		}
		log.Printf("FirstAuth Resp: %X\n", resp2)
		apdu2 := samav2.ApduNonXauthMFPf2(resp2)
		log.Printf("SEND TOPIC: %s\n", fmt.Sprintf("SAMFARM/SYN/%X/123", respSam12.channel))
		token = c.Publish(fmt.Sprintf("SAMFARM/SYN/%X/123", respSam12.channel), 0, false, apdu2)
		token.Wait()

		var respSam21 Response
		for v := range respChan {
			if v.channel == respSam12.channel {
				respSam21 = v
				break
			}
		}
		respSam2 := respSam21.data
		log.Printf("SAM resp: % X\n", respSam2)
		// keyEnc := respSam2[0:16]
		keyMac := respSam2[16:32]
		log.Printf("key Mac: [% X]\n", keyMac)
		Ti := respSam2[32:36]
		log.Printf("Ti: [% X]\n", Ti)
		readCounter := respSam2[36:38]
		log.Printf("Read Counter: [% X]\n", readCounter)
		// rCounter := 0
		// wCounter := 0
		//resp, err = mplus.ReadEncMacMac(4,1,rCounter,wCounter,Ti,keyMac,keyEnc)
		resp3, err := mplus.ReadEncMacMac(8, 4)
		if err != nil {
			log.Fatalf("%s\n", err)
		}
		log.Printf("read 8 resp: [% X]\n", resp3)
	}
}
