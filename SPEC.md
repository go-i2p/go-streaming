
geti2p.net
Streaming Protocol - I2P
21–26 minutes

This page was last updated in 2025-07 and is accurate for router version 0.9.67.
Overview

The streaming library is technically part of the "application" layer, as it is not a core router function. In practice, however, it provides a vital function for almost all existing I2P applications, by providing a TCP-like streams over I2P, and allowing existing apps to be easily ported to I2P. The other end-to-end transport library for client communication is the datagram library.

The streaming library is a layer on top of the core I2CP API that allows reliable, in-order, and authenticated streams of messages to operate across an unreliable, unordered, and unauthenticated message layer. Just like the TCP to IP relationship, this streaming functionality has a whole series of tradeoffs and optimizations available, but rather than embed that functionality into the base I2P code, it has been factored off into its own library both to keep the TCP-esque complexities separate and to allow alternative optimized implementations.

In consideration of the relatively high cost of messages, the streaming library's protocol for scheduling and delivering those messages has been optimized to allow individual messages passed to contain as much information as is available. For instance, a small HTTP transaction proxied through the streaming library can be completed in a single round trip - the first messages bundle a SYN, FIN, and the small HTTP request payload, and the reply bundles the SYN, FIN, ACK, and the HTTP response payload. While an additional ACK must be transmitted to tell the HTTP server that the SYN/FIN/ACK has been received, the local HTTP proxy can often deliver the full response to the browser immediately.

The streaming library bears much resemblance to an abstraction of TCP, with its sliding windows, congestion control algorithms (both slow start and congestion avoidance), and general packet behavior (ACK, SYN, FIN, RST, rto calculation, etc).

The streaming library is a robust library which is optimized for operation over I2P. It has a one-phase setup, and it contains a full windowing implementation.
API

The streaming library API provides a standard socket paradigm to Java applications. The lower-level I2CP API is completely hidden, except that applications may pass I2CP parameters through the streaming library, to be interpreted by I2CP.

The standard interface to the streaming lib is for the application to use the I2PSocketManagerFactory to create an I2PSocketManager. The application then asks the socket manager for an I2PSession, which will cause a connection to the router via I2CP. The application can then setup connections with an I2PSocket or receive connections with an I2PServerSocket.

Here are the full streaming library Javadocs.

For a good example of usage, see the i2psnark code.
Options and Defaults

The options and current default values are listed below. Options are case-sensitive and may be set for the whole router, for a particular client, or for an individual socket on a per-connection basis. Many values are tuned for HTTP performance over typical I2P conditions. Other applications such as peer-to-peer services are strongly encouraged to modify as necessary, by setting the options and passing them via the call to I2PSocketManagerFactory.createManager(_i2cpHost, _i2cpPort, opts). Time values are in ms.

Note that higher-layer APIs, such as SAM, BOB, and I2PTunnel, may override these defaults with their own defaults. Also note that many options only apply to servers listening for incoming connections.

As of release 0.9.1, most, but not all, options may be changed on an active socket manager or session. See the javadocs for details.
Option	Default	Notes
i2cp.accessList	null	Comma- or space-separated list of Base64 peer Hashes used for either access list or blacklist. As of release 0.7.13.
i2cp.destination.sigType	DSA_SHA1	Use the access list as a whitelist for incoming connections. The name or number of the signature type for a transient destination. As of release 0.9.12.
i2cp.enableAccessList	false	Use the access list as a whitelist for incoming connections. As of release 0.7.13.
i2cp.enableBlackList	false	Use the access list as a blacklist for incoming connections. As of release 0.7.13.
i2p.streaming.answerPings	true	Whether to respond to incoming pings
i2p.streaming.blacklist	null	Comma- or space-separated list of Base64 peer Hashes to be blacklisted for incoming connections to ALL destinations in the context. This option must be set in the context properties, NOT in the createManager() options argument. Note that setting this in the router context will not affect clients outside the router in a separate JVM and context. As of release 0.9.3.
i2p.streaming.bufferSize	64K	How much transmit data (in bytes) will be accepted that hasn't been written out yet.
i2p.streaming.congestionAvoidanceGrowthRateFactor	1	When we're in congestion avoidance, we grow the window size at the rate of 1/(windowSize*factor). In standard TCP, window sizes are in bytes, while in I2P, window sizes are in messages. A higher number means slower growth.
i2p.streaming.connectDelay	-1	How long to wait after instantiating a new con before actually attempting to connect. If this is <= 0, connect immediately with no initial data. If greater than 0, wait until the output stream is flushed, the buffer fills, or that many milliseconds pass, and include any initial data with the SYN.
i2p.streaming.connectTimeout	5*60*1000	How long to block on connect, in milliseconds. Negative means indefinitely. Default is 5 minutes.
i2p.streaming.disableRejectLogging	false	Whether to disable warnings in the logs when an incoming connection is rejected due to connection limits. As of release 0.9.4.
i2p.streaming.dsalist	null	Comma- or space-separated list of Base64 peer Hashes or host names to be contacted using an alternate DSA destination. Only applies if multisession is enabled and the primary session is non-DSA (generally for shared clients only). This option must be set in the context properties, NOT in the createManager() options argument. Note that setting this in the router context will not affect clients outside the router in a separate JVM and context. As of release 0.9.21.
i2p.streaming.enforceProtocol	true	Whether to listen only for the streaming protocol. Setting to true will prohibit communication with Destinations earlier than release 0.7.1 (released March 2009). Set to true if running multiple protocols on this Destination. As of release 0.9.1. Default true as of release 0.9.36.
i2p.streaming.inactivityAction	2 (send) 	(0=noop, 1=disconnect) What to do on an inactivity timeout - do nothing, disconnect, or send a duplicate ack.
i2p.streaming.inactivityTimeout	90*1000 	Idle time before sending a keepalive
i2p.streaming.initialAckDelay	750 	Delay before sending an ack
i2p.streaming.initialResendDelay	1000	The initial value of the resend delay field in the packet header, times 1000. Not fully implemented; see below.
i2p.streaming.initialRTO	9000	Initial timeout (if no sharing data available). As of release 0.9.8.
i2p.streaming.initialRTT	8000 	Initial round trip time estimate (if no sharing data available). Disabled as of release 0.9.8; uses actual RTT.
i2p.streaming.initialWindowSize	6	(if no sharing data available) In standard TCP, window sizes are in bytes, while in I2P, window sizes are in messages.
i2p.streaming.limitAction	reset	What action to take when an incoming connection exceeds limits. Valid values are: reset (reset the connection); drop (drop the connection); or http (send a hardcoded HTTP 429 response). Any other value is a custom response to be sent. backslash-r and backslash-n will be replaced with CR and LF. As of release 0.9.34.
i2p.streaming.maxConcurrentStreams	-1 	(0 or negative value means unlimited) This is a total limit for incoming and outgoing combined.
i2p.streaming.maxConnsPerMinute	0 	Incoming connection limit (per peer; 0 means disabled) As of release 0.7.14.
i2p.streaming.maxConnsPerHour	0 	(per peer; 0 means disabled) As of release 0.7.14.
i2p.streaming.maxConnsPerDay	0 	(per peer; 0 means disabled) As of release 0.7.14.
i2p.streaming.maxMessageSize	1730	The maximum size of the payload, i.e. the MTU in bytes.
i2p.streaming.maxResends	8	Maximum number of retransmissions before failure.
i2p.streaming.maxTotalConnsPerMinute	0 	Incoming connection limit (all peers; 0 means disabled) As of release 0.7.14.
i2p.streaming.maxTotalConnsPerHour	0 	(all peers; 0 means disabled) Use with caution as exceeding this will disable a server for a long time. As of release 0.7.14.
i2p.streaming.maxTotalConnsPerDay	0 	(all peers; 0 means disabled) Use with caution as exceeding this will disable a server for a long time. As of release 0.7.14.
i2p.streaming.maxWindowSize	128
i2p.streaming.profile	1 (bulk)	1=bulk; 2=interactive; see important notes below.
i2p.streaming.readTimeout	-1	How long to block on read, in milliseconds. Negative means indefinitely.
i2p.streaming.slowStartGrowthRateFactor	1	When we're in slow start, we grow the window size at the rate of 1/(factor). In standard TCP, window sizes are in bytes, while in I2P, window sizes are in messages. A higher number means slower growth.
i2p.streaming.tcbcache.rttDampening	0.75	Ref: RFC 2140. Floating point value. May be set only via context properties, not connection options. As of release 0.9.8.
i2p.streaming.tcbcache.rttdevDampening	0.75	Ref: RFC 2140. Floating point value. May be set only via context properties, not connection options. As of release 0.9.8.
i2p.streaming.tcbcache.wdwDampening	0.75	Ref: RFC 2140. Floating point value. May be set only via context properties, not connection options. As of release 0.9.8.
i2p.streaming.writeTimeout	-1	How long to block on write/flush, in milliseconds. Negative means indefinitely.
Protocol Specification

See the Streaming Library Specification page.
Implementation Details
Setup

The initiator sends a packet with the SYNCHRONIZE flag set. This packet may contain the initial data as well. The peer replies with a packet with the SYNCHRONIZE flag set. This packet may contain the initial response data as well.

The initiator may send additional data packets, up to the initial window size, before receiving the SYNCHRONIZE response. These packets will also have the send Stream ID field set to 0. Recipients must buffer packets received on unknown streams for a short period of time, as they may arrive out of order, in advance of the SYNCHRONIZE packet.
MTU Selection and Negotiation

The maximum message size (also called the MTU / MRU) is negotiated to the lower value supported by the two peers. As tunnel messages are padded to 1KB, a poor MTU selection will lead to a large amount of overhead. The MTU is specified by the option i2p.streaming.maxMessageSize. The current default MTU of 1730 was chosen to fit precisely into two 1K I2NP tunnel messages, including overhead for the typical case. Note: This is the maximum size of the payload only, not including the header.

Note: For ECIES connections, which have reduced overhead, the recommended MTU is 1812. The default MTU remains 1730 for all connections, no matter what key type is used. Clients must use the minimum of the sent and received MTU, as usual. See proposal 155.

The first message in a connection includes a 387 byte (typical) Destination added by the streaming layer, and usually a 898 byte (typical) LeaseSet, and Session keys, bundled in the Garlic message by the router. (The LeaseSet and Session Keys will not be bundled if an ElGamal Session was previously established). Therefore, the goal of fitting a complete HTTP request in a single 1KB I2NP message is not always attainable. However, the selection of the MTU, together with careful implementation of fragmentation and batching strategies in the tunnel gateway processor, are important factors in network bandwidth, latency, reliability, and efficiency, especially for long-lived connections.
Data Integrity

Data integrity is assured by the gzip CRC-32 checksum implemented in the I2CP layer. There is no checksum field in the streaming protocol.
Packet Encapsulation

Each packet is sent through I2P as a single message (or as an individual clove in a Garlic Message). Message encapsulation is implemented in the underlying I2CP, I2NP, and tunnel message layers. There is no packet delimiter mechanism or payload length field in the streaming protocol.
Optional Delay

Data packets may include an optional delay field specifying the requested delay, in ms, before the receiver should ack the packet. Valid values are 0 to 60000 inclusive. A value of 0 requests an immediate ack. This is advisory only, and receivers should delay slightly so that additional packets may be acknowledged with a single ack. Some implementations may include an advisory value of (measured RTT / 2) in this field. For nonzero optional delay values, receivers should limit the maximum delay before sending an ack to a few seconds at most. Optional delay values greater than 60000 indicate choking, see below.
Transmit/Receive Windows and Choking

TCP headers include the receive window in bytes; however, the streaming protocol does not provide a way to exchange max receive window size either in bytes or packets. There is only a simple choke/unchoke indication indicating that the receive buffer is full. Each endpoint must maintain its own estimate of the far-end receive window, in either bytes or packets. Note that a receive buffer may overflow at any window size if the client application is slow to empty the buffer.

The default maximum transmit and receive window size in the Java implementation is 128 packets. Implementations setting a maximum transmit window size higher than 128 must consider the following issues:

    CHOKE responses from Java routers due to receive buffer overflow are much more likely.
    Far-end receiver buffer size estimation must be implemented to mitigate repeated overflows (see above)
    CHOKE must be handled correctly (see below)
    Max window sizes over 256 are even more error-prone, because the nack count option field length is one byte, limiting the maximum NACKs to 255. This specification does not address what to do if there are more than 255 NACKs. Max window sizes over 256 are not recommended. 

The recommended minimum buffer size for receiver implementations is 128 packets or 232 KB (approximately 128 * 1812). Because of I2P netowrk latency, packet drops, and the resulting congestion control, a buffer of this size is rarely filled. Overflow is, however, much more likely to occur on high-bandwidth "local loopback" (same-router) connections or in local testing.

To quickly indicate and smoothly recover from overflow conditions, there is a simple mechanism for pushback in the streaming protocol. If a packet is received with an optional delay field of value of 60001 or higher, that indicates "choking" or a receive window of zero. A packet with an optional delay field of value of 60000 or less indicates "unchoking". Packets without an optional delay field do not affect the choke/unchoke state.

After being choked, no more packets with data should be sent until the transmitter is unchoked, except for occasional "probe" data packets to compensate for possible lost unchoke packets. The choked endpoint should start a "persist timer" to control the probing, as in TCP. The unchoking endpoint should send several packets with this field set, or continue sending them periodically until data packets are received again. Maximum time to wait for unchoking is implementation-dependent. Transmitter window size and congestion control strategy after being unchoked is implementation-dependent.
Congestion Control

The streaming lib uses standard slow-start (exponential window growth) and congestion avoidance (linear window growth) phases, with exponential backoff. Windowing and acknowledgments use packet count, not byte count.
Close

Any packet, including one with the SYNCHRONIZE flag set, may have the CLOSE flag sent as well. The connection is not closed until the peer responds with the CLOSE flag. CLOSE packets may contain data as well.
Ping / Pong

There is no ping function at the I2CP layer (equivalent to ICMP echo) or in datagrams. This function is provided in streaming. Pings and pongs may not be combined with a standard streaming packet; if the ECHO option is set, then most other flags, options, ackThrough, sequenceNum, NACKs, etc. are ignored.

A ping packet must have the ECHO, SIGNATURE_INCLUDED, and FROM_INCLUDED flags set. The sendStreamId must be greater than zero, and the receiveStreamId is ignored. The sendStreamId may or may not correspond to an existing connection.

A pong packet must have the ECHO flag set. The sendStreamId must be zero, and the receiveStreamId is the sendStreamId from the ping. Prior to release 0.9.18, the pong packet does not include any payload that was contained in the ping.

As of release 0.9.18, pings and pongs may contain a payload. The payload in the ping, up to a maximum of 32 bytes, is returned in the pong.

Streaming may be configured to disable sending pongs with the configuration i2p.streaming.answerPings=false.
i2p.streaming.profile Notes

This option supports two values; 1=bulk and 2=interactive. The option provides a hint to the streaming library and/or router as to the traffic pattern that is expected.

"Bulk" means to optimize for high bandwidth, possibly at the expense of latency. This is the default. "Interactive" means to optimize for low latency, possibly at the expense of bandwidth or efficiency. Optimization strategies, if any, are implementation-dependent, and may include changes outside of the streaming protocol.

Through API version 0.9.63, Java I2P would return an error for any value other than 1 (bulk) and the tunnel would fail to start. As of API 0.9.64, Java I2P ignores the value. Through API version 0.9.63, i2pd ignored this option; it is implemented in i2pd as of API 0.9.64.

While the streaming protocol includes a flag field to pass the profile setting to the other end, this is not implemented in any known router.
Control Block Sharing

The streaming lib supports "TCP" Control Block sharing. This shares three important streaming lib parameters (window size, round trip time, round trip time variance) across connections to the same remote peer. This is used for "temporal" sharing at connection open/close time, not "ensemble" sharing during a connection (See RFC 2140). There is a separate share per ConnectionManager (i.e. per local Destination) so that there is no information leakage to other Destinations on the same router. The share data for a given peer expires after a few minutes. The following Control Block Sharing parameters can be set per router:

    RTT_DAMPENING = 0.75
    RTTDEV_DAMPENING = 0.75
    WINDOW_DAMPENING = 0.75

Other Parameters

The following parameters are recommended defaults. Defaults may vary, implementation dependent:

    MIN_RESEND_DELAY = 100 ms (minimum RTO)
    MAX_RESEND_DELAY = 45 sec (maximum RTO)
    MIN_WINDOW_SIZE = 1
    MAX_WINDOW_SIZE = 128
    TREND_COUNT = 3
    MIN_MESSAGE_SIZE = 512 (minimum MTU)
    INBOUND_BUFFER_SIZE = maxMessageSize * (maxWindowSize + 2)
    INITIAL_TIMEOUT (valid only before RTT is sampled) = 9 sec
    "alpha" ( RTT dampening factor as per RFC 6298 ) = 0.125
    "beta" ( RTTDEV dampening factor as per RFC 6298 ) = 0.25
    "K" ( RTDEV multiplier as per RFC 6298 ) = 4
    PASSIVE_FLUSH_DELAY = 175 ms
    Maximum RTT estimate: 60 sec 

History

The streaming library has grown organically for I2P - first mihi implemented the "mini streaming library" as part of I2PTunnel, which was limited to a window size of 1 message (requiring an ACK before sending the next one), and then it was refactored out into a generic streaming interface (mirroring TCP sockets) and the full streaming implementation was deployed with a sliding window protocol and optimizations to take into account the high bandwidth x delay product. Individual streams may adjust the maximum packet size and other options. The default message size is selected to fit precisely in two 1K I2NP tunnel messages, and is a reasonable tradeoff between the bandwidth costs of retransmitting lost messages, and the latency and overhead of multiple messages.
Future Work

The behavior of the streaming library has a profound impact on application-level performance, and as such, is an important area for further analysis.

    Additional tuning of the streaming lib parameters may be necessary.
    Another area for research is the interaction of the streaming lib with the NTCP and SSU transport layers. See the NTCP discussion page for details.
    The interaction of the routing algorithms with the streaming lib strongly affects performance. In particular, random distribution of messages to multiple tunnels in a pool leads to a high degree of out-of-order delivery which results in smaller window sizes than would otherwise be the case. The router currently routes messages for a single from/to destination pair through a consistent set of tunnels, until tunnel expiration or delivery failure. The router's failure and tunnel selection algorithms should be reviewed for possible improvements.
    The data in the first SYN packet may exceed the receiver's MTU.
    The DELAY_REQUESTED field could be used more.
    Duplicate initial SYNCHRONIZE packets on short-lived streams may not be recognized and removed.
    Don't send the MTU in a retransmission.
    Data is sent along unless the outbound window is full. (i.e. no-Nagle or TCP_NODELAY) Probably should have a configuration option for this.
    zzz has added debug code to the streaming library to log packets in a wireshark-compatible (pcap) format; Use this to further analyze performance. The format may require enhancement to map more streaming lib parameters to TCP fields.
    There are proposals to replace the streaming lib with standard TCP (or perhaps a null layer together with raw sockets). This would unfortunately be incompatible with the streaming lib but it would be good to compare the performance of the two.

