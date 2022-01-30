package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"

	"github.com/nmelo/smartcard/samfarm"
	MQTT "github.com/eclipse/paho.mqtt.golang"
)

func verifyCreateSamChannels(ctx *samfarm.Context) {
	log.Printf("///// verifyCreateSamChannels /////")
	sams, err := samfarm.GetSamDevices(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	key, err := hex.DecodeString(keyS)
	if err != nil {
		log.Fatal(err)
	}
	for k, sam := range sams {
		/**
		isn't necesary
		if chOld, ok := samInputChannels[k]; ok {
			close(chOld)
		}
		/**/
		log.Printf("New device %v: %+v\n", k, sam)

		resp, err := sam.AuthHostAV2(key, 0, 0, 0)
		if err != nil {
			log.Print("Not Auth: ", err)
			continue
		}
		log.Printf("auth sam: [% X]\n", resp)

		samDevices[k] = sam
		inCh := make(chan []byte)
		outCh := make(chan []byte)

		var strTopicName bytes.Buffer
		strTopicName.WriteString(topicNameSyncInputs)
		strTopicName.WriteString(fmt.Sprintf("%X", k))
		strTopicName.WriteString("/#")
		f2 := uniqListen(outCh)
		clientID := fmt.Sprintf("go-samfarm-client-%X", k)
		//fmt.Printf("clientId: %s\n", clientId)
		//fmt.Printf("topic sam: %s\n",  strTopicName.String())

		uri, err := url.Parse(urlBroker)
		if err != nil {
			log.Fatal(err)
		}
		opts := MQTT.NewClientOptions().AddBroker(fmt.Sprintf("%s://%s%s", uri.Scheme, uri.Host, uri.Path))
		if uri.User != nil {
			opts.SetUsername(uri.User.Username())
			password, _ := uri.User.Password()
			opts.SetPassword(password)
		}

		opts.SetClientID(clientID)
		opts.SetDefaultPublishHandler(f2)
		var fDisconnect MQTT.ConnectionLostHandler = func(client MQTT.Client, err error) {
			defer func() {
				if x := recover(); x != nil {
					log.Printf("lost, run time panic: %v", x)
				}
			}()
			log.Printf("Disconnect error: %s", err)
			close(inCh)
		}
		opts.SetConnectionLostHandler(fDisconnect)
		c, err := createClientMQTT(opts, strTopicName.String())
		if err != nil {
			log.Printf("Create client error: %s", err)
			continue
		}
		go func() {
			defer func() {
				if x := recover(); x != nil {
					log.Printf("ReaderChannel, run time panic: %v", x)
				}
			}()
			samfarm.ReaderChannel(sam, inCh, outCh)
			//			log.Printf("End samfarm.ReaderChannel\n")
			//close(inCh)
			c.Disconnect(100)
		}()
		samInputChannels[k] = inCh
		samOutputChannels[k] = outCh
		log.Printf("devices: %+v\n", samDevices)
	}
}
