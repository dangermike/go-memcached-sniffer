package main

import (
	"fmt"
	"os"
	"runtime"

	log "github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/google/gopacket/pcap"
	"github.com/minio/cli"
)

func main() {
	defaultInterface := "eth0"
	if runtime.GOOS == "darwin" {
		defaultInterface = "en0"
	}

	app := cli.NewApp()
	app.Name = "go-memcached-sniffer"
	app.Usage = "Like a dog with its nose up memcached's butt"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "interface, i",
			Value: defaultInterface,
			Usage: "the interface to sniff",
		},
		cli.StringFlag{
			Name:  "filter, f",
			Value: "tcp and port 11211",
			Usage: "pcap-stype filter on the incoming packets",
		},
		cli.IntFlag{
			Name:  "snaplength, s",
			Value: 1600,
			Usage: "maximum size to read for each packet",
		},
		cli.BoolFlag{
			Name:  "promiscuous, p",
			Usage: "put the interface into promiscuous mode",
		},
		cli.DurationFlag{
			Name:  "timeout, t",
			Value: pcap.BlockForever,
			Usage: `timeout on a connection. defaults to 'BlockForever'

 A timeout of 0 is not recommended. Some platforms, like Macs (http://www.manpages.info/macosx/pcap.3.html) say:

  The read timeout is used to arrange that the read not necessarily return
  immediately when a packet is seen, but that it wait for some amount of time
  to allow more packets to arrive and to read multiple packets from the OS
  kernel in one operation.

 This means that if you only capture one packet, the kernel might decide to wait 'timeout' for more packets to batch with it before returning. A timeout of 0, then, means 'wait forever for more packets', which is... not good.

 To get around this, we've introduced the following behavior: if a negative timeout is passed in, we set the positive timeout in the handle, then loop internally in ReadPacketData/ZeroCopyReadPacketData when we see timeout errors.`,
		},
		cli.BoolFlag{
			Name:  "verbose, v",
			Usage: "enable verbose logging",
		},
		cli.BoolFlag{
			Name:  "quiet, q",
			Usage: "disable logging on non-fatal events",
		},
	}
	app.Action = appAction
	app.Run(os.Args)
}

// FlowBuffer holds a buffer and the flow it came from
type FlowBuffer struct {
	Flow   gopacket.Flow
	Buffer []byte
}

func appAction(c *cli.Context) {
	if c.Bool("quiet") {
		log.SetLevel(log.FatalLevel)
	} else if c.Bool("verbose") {
		log.SetLevel(log.DebugLevel)
	}

	log.WithFields(log.Fields{
		"interface":   c.String("interface"),
		"snaplength":  c.Int("snaplength"),
		"promiscuous": c.Bool("promiscuous"),
		"timeout":     c.Duration("timeout"),
	}).Debug("Opening interface")

	handle, err := pcap.OpenLive(c.String("interface"), int32(c.Int("snaplength")), c.Bool("promiscuous"), c.Duration("timeout"))
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if c.String("filter") != "" {
		log.WithField("filter", c.String("filter")).Debug("Applying filter")
		err = handle.SetBPFFilter(c.String("filter"))
		if err != nil {
			log.WithError(err).Fatal("Failed to set filter")
		}
	}

	flowRemnants := map[gopacket.Flow]([]byte){}
	toBeParsed := make(chan FlowBuffer)

	go func() {
		for fbuff := range toBeParsed {
			pr := parseSession(fbuff.Buffer)
			if pr.ParserOffset != pr.BufferLength || pr.ParserState != memcached_first_final {
				log.WithFields(pr.ToLogFields()).WithField("flow_id", fbuff.Flow.FastHash()).Info("Parse failed on flow")

				fname := fmt.Sprintf("flow_%d.bin", fbuff.Flow.FastHash())
				f, err := os.Create(fname)
				if err != nil {
					log.WithField("fname", fname).WithError(err).Error("Failed to open file")
				} else {
					defer f.Close()
					_, err = f.Write(fbuff.Buffer)
					if err != nil {
						log.WithField("fname", fname).WithError(err).Error("Failed to write file")
					}
				}
			}
		}
	}()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			// ip, _ := ipLayer.(*layers.IPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				flow := tcp.TransportFlow()
				remnant, ok := flowRemnants[flow]
				if tcp.FIN {
					log.WithField("hash", flow.FastHash()).Debug("Received FIN")
					// close the flow
					if ok {
						log.WithField("hash", flow.FastHash()).Debug("Closing flow")
						if len(remnant) > 0 {
							toBeParsed <- FlowBuffer{flow, remnant}
						}
						delete(flowRemnants, flow)
						log.WithField("hash", flow.FastHash()).Debug("Closed flow")
					}
				} else {
					al := packet.ApplicationLayer()
					if al != nil {
						if !ok {
							log.WithField("hash", flow.FastHash()).Debug("Opened")
							remnant = []byte{}
							flowRemnants[flow] = remnant // shouldn't be necessary
						}
						// fmt.Printf(
						// 	"Application Packet #%d sent from %v:%d to %v:%d. flowhash=%d\n",
						// 	tcp.Seq,
						// 	flow.Src(),
						// 	tcp.SrcPort,
						// 	flow.Dst(),
						// 	tcp.DstPort,
						// 	flow.FastHash(),
						// )
						log.WithFields(log.Fields{
							"hash":   flow.FastHash(),
							"length": len(al.Payload()),
						}).Debug("Appending packet")

						remnant = append(remnant, al.Payload()...)
						flowRemnants[flow] = remnant

						log.WithFields(log.Fields{
							"hash":   flow.FastHash(),
							"length": len(al.Payload()),
						}).Debug("Appended packet")
						// body := string(al.Payload())
						// fmt.Println(body)
					}
				}
			}
			close(toBeParsed)
		}
	}
}
