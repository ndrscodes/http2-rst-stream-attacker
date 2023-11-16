# CVE-2023-44487 and http2-rst-stream-attacker

## CVE-2023-44487

CVE-2023-44487 is an exploit against the HTTP2 protocol itself. In HTTP2, requests for data are initiated by sending a HEADERS frame. After receiving this frame, a server will start processing your request,
subsequently sending DATA frames until all data is transmitted. HTTP2 also specified a RST_STREAM frame, which can be used to close a stream at any point. To prevent attacks,
servers usually limit the maximum amount of concurrently opened streams (to 100 by default). If clients actually wait for all resources to be consumed, this limit is rarely hit.
The attack works for a simple reason: A client can send a RST_STREAM frame at *any* point. A RST_STREAM frame closes a stream, and closed streams are not counted as a concurrent stream. This means that
a client can send requests rapidly, without ever hitting this limit, simply by closing a connection directly after sending a request. The server being attacked will, in some cases, still start loading the data, creating excessive load.

This tool aims to check a server's vulnerability to this attack. It establishes one or more concurrent HTTP2 connections and subsequently sends the specified numbers of HEADER frames, followed by RST_STREAM frames.

It also provides numerous other configuration options, like delay between HEADERS and RST_STREAM frames, the number of streams to open, the amount of frames to send per stream and so on.
After the attack is completed, it prints out a summary containing information about the number of frames received, as well as the number of errors and GOAWAY frames received.
This can assist you in identifying if your services are vulnerable to CVE-2023-44487.

## Running

As of now, this tool is distributed as source code only, meaning a go install is required. The tool can be executed by running `go run main.go <options>`

## CLI Flags

Currently, the following CLI options are implemented:
| Flag           | Default                | Meaning                                                                                                                                                     |
|----------------|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| attempts       | 1                      | the number of HEADERS and RST_STREAM frames to send on any stream                                                                                           |
| connections    | 1                      | the number of TLS connections to run the attack on (concurrently)                                                                                           |
| delay          | 0                      | the time (in ms) to wait between sending HEADERS and RST_STREAM frames                                                                                      |
| ignoreGoAway   | false                  | if true, GOAWAY streams will not cause the receiving routine to terminate. Instead, it will wait until no frame has been received for more than 10 seconds. |
| routines       | 1                      | the number of streams to attack                                                                                                                             |
| skipValidation | true                   | if true, the server certificate will not be validated (this is the default - we don't care about security since we are the attacker anyways)                |
| url            | https://localhost:433/ | the url to run the attack against                                                                                                                           |

## Example output

The tool will print out a lot of debug information, as well as a summary.
The debug information contains information about the way the connection was established and about the current progress and the type of frames currently being sent.

The summary will look something like this (depending on your configuration)
```
####################SUMMARY####################
Packet types received:
	PING: 2
	HEADERS: 12
	SETTINGS: 0
	DATA: 11
	GOAWAY: 3
	RSTSTREAM: 0
	WINDOWUPDATE: 0
	UNKNOWN: 0
Attack ending reasons (per receiving thread):
	GoAway events: 3
	Timeout events: 0
	Error events: 0
Summary for connection 2
	PING: 1
	HEADERS: 9
	SETTINGS: 0
	DATA: 6
	GOAWAY: 1
	RSTSTREAM: 0
	WINDOWUPDATE: 0
	UNKNOWN: 0
	Reason for stopping to listen for more packets: GoAway - the server responded as expected.
Summary for connection 1
	PING: 1
	HEADERS: 3
	SETTINGS: 0
	DATA: 5
	GOAWAY: 1
	RSTSTREAM: 0
	WINDOWUPDATE: 0
	UNKNOWN: 0
	Reason for stopping to listen for more packets: GoAway - the server responded as expected.
Summary for connection 0
	PING: 0
	HEADERS: 0
	SETTINGS: 0
	DATA: 0
	GOAWAY: 1
	RSTSTREAM: 0
	WINDOWUPDATE: 0
	UNKNOWN: 0
	Reason for stopping to listen for more packets: GoAway - the server responded as expected.
```

If you think there are other statistics that need to be gathered - do not hesitate to contact me or create an issue!

## TODO

- calculate the average delay between sending HEADERS and receiving the first frame for this request
- calculate the average delay between sending HEADERS and receiving GOAWAY frames, if any
- calculate the percentage of connections the server responded correctly to
- calculate the percentage of streams the server responded correctly to (per connection and in total)
- include amount of packets sent in the summary

## DISCLAIMER

This tool is meant for research purposes ONLY. It is not meant to run attacks against servers not owned or managed by yourself.
I take no responsibility for the accuracy of the statistics provided, nor for attacks and their consequences for servers and services.
