package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dumacp/smartcard/samfarm"
	MQTT "github.com/eclipse/paho.mqtt.golang"
)

/**
Receiver of Messages sent to specific SAM devices (topic: "topicNameSyncInputs/samid/appid")

This function send response Messages in topic "topicNameOutputs/appid/samid"
/**/
func uniqListen(samInput chan []byte) func(MQTT.Client, MQTT.Message) {
	return func(client MQTT.Client, msg MQTT.Message) {
		log.Printf("INFO: SYN TOPIC: %s\n", msg.Topic())
		log.Printf("INFO: SYN MSG: [% X]\n", msg.Payload())

		spl1 := strings.Split(msg.Topic(), "/")
		samid := spl1[len(spl1)-3]
		txid := spl1[len(spl1)-2]
		appid := spl1[len(spl1)-1]

		select {
		case samInput <- msg.Payload():
		default:
			return
		}
		var data []byte
		select {
		case v, ok := <-samInput:
			if !ok {
				return
			}
			data = v
		case <-time.After(time.Second * 10):
			return
		}
		var strRespName bytes.Buffer
		strRespName.WriteString(topicNameOutputs)
		strRespName.WriteString(appid)
		strRespName.WriteString("/")
		strRespName.WriteString(txid)
		strRespName.WriteString("/")
		strRespName.WriteString(samid)
		log.Printf("apdu1 topic: %s", strRespName.String())
		log.Printf("apdu1 data: %X", data)
		token := client.Publish(strRespName.String(), 0, false, data)
		token.Wait()
	}
}

/**
Receiver of Messages sent to generic SAM devices (topic: "topicNameAsyncInputs/uuid/appid")

This function send response Messages in topic "topicNameOutputs/appid/uuid"
/**/
var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {
	log.Printf("INFO: TOPIC async: %s\n", msg.Topic())
	log.Printf("INFO: MSG async: [% X]\n", msg.Payload())

	samInputs := make([]chan []byte, 0)
	samInKeys := make([]uint64, 0)
	samOutputs := make([]chan []byte, 0)
	samOutKeys := make([]uint64, 0)

	for k, input := range samInputChannels {
		samInputs = append(samInputs, input)
		samInKeys = append(samInKeys, k)
	}
	for k, output := range samOutputChannels {
		samOutputs = append(samOutputs, output)
		samOutKeys = append(samOutKeys, k)
	}

	if len(samInputs) > 0 && len(samOutputs) > 0 {
		go func() {
			data, chosen2, err2 := samfarm.RecvResp(samOutputs)
			if err2 != nil {
				log.Printf("%s; channel: %v\n", err2, chosen2)
				if chosen2 >= 0 && chosen2 < len(samOutKeys) {
					k := samOutKeys[chosen2]
					log.Printf("delete sam: %v, %v\n", k, chosen2)
					delete(samInputChannels, k)
					delete(samOutputChannels, k)
					delete(samDevices, k)
				}
				return
			}
			spl1 := strings.Split(msg.Topic(), "/")
			appid := spl1[len(spl1)-1]
			uuid := spl1[len(spl1)-2]
			var strRespName bytes.Buffer
			strRespName.WriteString(topicNameOutputs)
			strRespName.WriteString(appid)
			strRespName.WriteString("/")
			strRespName.WriteString(uuid)
			strRespName.WriteString("/")
			strRespName.WriteString(fmt.Sprintf("%X", samOutKeys[chosen2]))
			log.Printf("apdu2 topic: %s", strRespName.String())
			log.Printf("apdu2 data: %X", data)
			token := client.Publish(strRespName.String(), 0, false, data)
			token.Wait()
		}()
		go func() {
			defer func() {
				if x := recover(); x != nil {
					log.Printf("run time panic: %v", x)
				}
			}()
			_, err1 := samfarm.SendCmd(msg.Payload(), samInputs)
			if err1 != nil {
				log.Printf("%s\n", err1)
			}
		}()
	}
}

func createClientMQTT(opts *MQTT.ClientOptions, topicName string) (MQTT.Client, error) {
	c := MQTT.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}

	if token := c.Subscribe(topicName, 0, nil); token.Wait() && token.Error() != nil {
		return nil, token.Error()
	}

	return c, nil
}
