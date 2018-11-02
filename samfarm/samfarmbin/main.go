/**
this app implements a SAMav2 cluster through MQTT topics


The messages are APDU Commands ([]byte) sent to "<topicName*Inputs>",
and APDU Responses ([]byte) that are left in "<topicNameOutput>"


* <topicNameAsyncInputs> is the prefix of topic to generic command (sent to any SAM device).
* <topicNameSyncInputs> is the prefix of topic to especific command (sent to especific SAM device).
* <topicNameOutput> is the prefix of topic to responses.

The "<topicNameAsyncInputs/*>" should end with suffix "/id1/id2". Where "id1" (hexstring) is a 
identifier for transaction, and "id2" (hexstring) is the identifier for app client who sent the 
command and will be receiver of the response.

The "<topicNameSyncInputs/*> should end with suffix "/id3/id2". Where "id3" (hexstring) is the 
identifier for the SAM device that should reciver the APDU command, and "id2" (hexstring) is the 
identifier for app client who sent the command and will be receiver of the response.

The "<topicNameOutput/*>" end with suffix "/id2/id1/id3". Where "id3" (hexstring) is the identifier 
for the SAM device that left the response, "id2" (hexstring) is the identifier for app client who 
will be receiver of the response and "id1" (hexstring) is the identifier of the transaction. 



Usage of ./samfarmbin:
  -clientName string
    	Client Name conecction mqtt (default "go-samfarm-client-1541166125194006904")
  -isShared
    	is shared subcription? 
  -key string
    	key aes128 (default "00000000000000000000000000000000")
  -password string
    	MQTT Password broker
  -topicNameAsyncInputs string
    	MQTT topic name to cmd requests Async (default "SAMFARM/ASYN/")
  -topicNameOutputs string
    	MQTT topic name to cmd responses (default "SAMFARM/RESP/")
  -topicNameSyncInputs string
    	MQTT topic name to cmd request Sync (default "SAMFARM/SYN/")
  -urlBroker string
    	MQTT url broker (default "tcp://127.0.0.1:1883")
  -username string
    	MQTT Username broker

/**/
package main

import (
	"fmt"
	"log"
	"flag"
	"time"
	"strings"
	"bytes"
	"net/url"
	"encoding/hex"
	"github.com/dumacp/smartcard/samfarm"
	_ "github.com/dumacp/smartcard/nxp/mifare"
	MQTT "github.com/eclipse/paho.mqtt.golang"
)


var ctx *samfarm.Context
var samDevices map[uint64]samfarm.SamDevice
var samInputChannels map[uint64]chan []byte
var samOutputChannels map[uint64]chan []byte

var urlBroker string
var username string
var password string
var topicNameAsyncInputs string
var topicNameSyncInputs string
var topicNameOutputs string
var keyS string
var clientName string
var isShared bool

func init() {
	flag.StringVar(&urlBroker, "urlBroker", "tcp://127.0.0.1:1883", "MQTT url broker")
	flag.StringVar(&urlBroker, "username", "", "MQTT Username broker")
	flag.StringVar(&urlBroker, "password", "", "MQTT Password broker")
	flag.StringVar(&topicNameAsyncInputs, "topicNameAsyncInputs", "SAMFARM/ASYN/", "MQTT topic name to cmd requests Async")
	flag.StringVar(&topicNameSyncInputs, "topicNameSyncInputs", "SAMFARM/SYN/", "MQTT topic name to cmd request Sync")
	flag.StringVar(&topicNameOutputs, "topicNameOutputs", "SAMFARM/RESP/", "MQTT topic name to cmd responses")
	flag.StringVar(&keyS, "key", "00000000000000000000000000000000", "key aes128")
	flag.StringVar(&clientName, "clientName", fmt.Sprintf("go-samfarm-client-%v", time.Now().UnixNano()), "Client Name conecction mqtt")
	flag.BoolVar(&isShared, "isShared", false, "is shared subcription? ")

	samDevices = make(map[uint64]samfarm.SamDevice)
	samInputChannels = make(map[uint64]chan []byte)
	samOutputChannels = make(map[uint64]chan []byte)
}

/**
Receiver of Messages sent to specific SAM devices (topic: "topicNameSyncInputs/samid/appid")

This function send response Messages in topic "topicNameOutputs/appid/samid"
/**/
func uniqListen(samInput chan []byte) func(MQTT.Client, MQTT.Message) {
	return func(client MQTT.Client, msg MQTT.Message) {
		log.Printf("SYN TOPIC: %s\n", msg.Topic())
		log.Printf("SYN MSG: [% X]\n", msg.Payload())

		spl1 := strings.Split(msg.Topic(), "/")
		samid := spl1[len(spl1) -2]
		appid := spl1[len(spl1) -1]

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
		strRespName.WriteString(samid)
		log.Printf("apdu2 topic: %s", strRespName.String())
		token := client.Publish(strRespName.String(), 0, false, data)
                token.Wait()
	}
}

/**
Receiver of Messages sent to generic SAM devices (topic: "topicNameAsyncInputs/uuid/appid")

This function send response Messages in topic "topicNameOutputs/appid/uuid"
/**/
var f MQTT.MessageHandler = func(client MQTT.Client, msg MQTT.Message) {
	log.Printf("TOPIC: %s\n", msg.Topic())
	log.Printf("MSG: [% X]\n", msg.Payload())

	samInputs := make([]chan []byte,0)
	samInKeys := make([]uint64,0)
	samOutputs := make([]chan []byte,0)
	samOutKeys := make([]uint64,0)

	for k, input := range samInputChannels {
		samInputs = append(samInputs, input)
		samInKeys = append(samInKeys,k)
	}
	for k, output := range samOutputChannels {
		samOutputs = append(samOutputs,output)
		samOutKeys = append(samOutKeys,k)
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
				}
				return
			}
			spl1 := strings.Split(msg.Topic(), "/")
			appid := spl1[len(spl1) -1]
			uuid := spl1[len(spl1) -2]
			var strRespName bytes.Buffer
			strRespName.WriteString(topicNameOutputs)
			strRespName.WriteString(appid)
			strRespName.WriteString("/")
			strRespName.WriteString(uuid)
			strRespName.WriteString("/")
			strRespName.WriteString(fmt.Sprintf("%X",samOutKeys[chosen2]))
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

func verifyCreateSamChannels(ctx *samfarm.Context) {
	sams, err := samfarm.GetSamDevices(ctx)
	if err != nil {
		//log.Println(err)
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
		log.Printf("device %v: %+v\n",k, sam)

                resp, err := sam.AuthHostAV2(key, 100)
                if err != nil {
                        log.Println("Not Auth: ", err)
			continue
                }
                log.Printf("auth sam: [% X]\n", resp)

		samDevices[k] = sam
		inCh := make(chan []byte)
                outCh := make(chan []byte)

		var strTopicName bytes.Buffer
		strTopicName.WriteString(topicNameSyncInputs)
		strTopicName.WriteString(fmt.Sprintf("%X",k))
		strTopicName.WriteString("/#")
		f2 := uniqListen(outCh)
		clientId := fmt.Sprintf("go-samfarm-client-%X", k)
		fmt.Printf("clientId: %s\n", clientId)
		fmt.Printf("topic sam: %s\n",  strTopicName.String())

		uri, err := url.Parse(urlBroker)
		if err != nil {
			log.Fatal(err)
		}
		opts := MQTT.NewClientOptions().AddBroker(fmt.Sprintf("tcp://%s", uri.Host))
		if uri.User != nil {
			opts.SetUsername(uri.User.Username())
			password, _ := uri.User.Password()
			opts.SetPassword(password)
		}

	        opts.SetClientID(clientId)
		opts.SetDefaultPublishHandler(f2)
		var fDisconnect MQTT.ConnectionLostHandler = func(client MQTT.Client, err error) {
			defer func() {
				if x := recover(); x != nil {
					log.Printf("lost, run time panic: %v", x)
				}
			}()
			log.Printf("%s", err)
			close(inCh)
		}
		opts.SetConnectionLostHandler(fDisconnect)
		c, err := createClientMQTT(opts, strTopicName.String())
		if err != nil {
			log.Printf("error client: %s",err)
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


func main() {

	flag.Parse()

	var strTopicName bytes.Buffer
	if isShared {
		strTopicName.WriteString("$share/SAMS01/")
	}
	strTopicName.WriteString(topicNameAsyncInputs)
	strTopicName.WriteString("#")

	errDisconnect := make(chan error)
	var fDisconnect MQTT.ConnectionLostHandler = func(client MQTT.Client, err error) {
		log.Println(err)
		client.Disconnect(100)
		errDisconnect <- err
	}

	fmt.Printf("go-samfarm-client: %s\n", clientName)
	fmt.Printf("go-samfarm-client topic: %s\n", strTopicName.String())

	uri, err := url.Parse(urlBroker)
	if err != nil {
		log.Fatal(err)
	}
	opts := MQTT.NewClientOptions().AddBroker(fmt.Sprintf("tcp://%s", uri.Host))
	if uri.User != nil {
		opts.SetUsername(uri.User.Username())
		password, _ := uri.User.Password()
		opts.SetPassword(password)
	}

	opts.SetClientID(clientName)
	opts.SetDefaultPublishHandler(f)
	opts.SetConnectionLostHandler(fDisconnect)


	for {
		client, err := createClientMQTT(opts, strTopicName.String())
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}
		defer client.Disconnect(100)

		ctx, err := samfarm.NewContext()
		if err != nil {
			log.Fatal(err)
		}

		verifyCreateSamChannels(ctx)

		timeout := time.Tick(time.Second * 10)


OuterLoop:
		for {
			select {
			case <-errDisconnect:
				break OuterLoop
			case <-timeout:
				verifyCreateSamChannels(ctx)
			}
		}
		time.Sleep(time.Second * 5)
	}
}
