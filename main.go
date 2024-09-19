package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	metricsNamespace = "netpeek"
)

type metrics struct {
	registry *prometheus.Registry

	rxCounter *prometheus.CounterVec
	txCounter *prometheus.CounterVec
}

func initMetrics() *metrics {
	var m metrics
	m.registry = prometheus.NewRegistry()

	m.rxCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "rx_bytes_total",
		Help:      "The total number of received bytes.",
	}, []string{"protocol", "src_addr"})
	m.registry.MustRegister(m.rxCounter)

	m.txCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "tx_bytes_total",
		Help:      "The total number of transmitted bytes.",
	}, []string{"protocol", "dst_addr"})
	m.registry.MustRegister(m.txCounter)

	return &m
}

func handlePacket(m *metrics, targetPort int, pkt gopacket.Packet) {
	var srcAddr, dstAddr string
	var srcPort, dstPort int
	var protocol string

	// Get source and destination addressed from the network layer.
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcAddr, dstAddr = ip.SrcIP.String(), ip.DstIP.String()
	} else if ipLayer := pkt.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcAddr, dstAddr = ip.SrcIP.String(), ip.DstIP.String()
	}

	// Check whether the packet is TCP or UDP.
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		protocol = "tcp"
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort, dstPort = int(tcp.SrcPort), int(tcp.DstPort)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		protocol = "udp"
		udp, _ := udpLayer.(*layers.UDP)
		srcPort, dstPort = int(udp.SrcPort), int(udp.DstPort)
	}

	// We want to track size of the whole payload, including the below layers.
	pktLen := len(pkt.Data())

	if srcPort == targetPort {
		// incoming packet
		m.rxCounter.With(prometheus.Labels{
			"protocol": protocol,
			"src_addr": srcAddr,
		}).Add(float64(pktLen))
	} else if dstPort == targetPort {
		// outgoing packet
		m.txCounter.With(prometheus.Labels{
			"protocol": protocol,
			"dst_addr": dstAddr,
		}).Add(float64(pktLen))
	}
}

func main() {
	var port int
	var iface string
	var httpAddress string

	flag.IntVar(&port, "port", 8065, "port number to capture packets on")
	flag.StringVar(&iface, "iface", "eth0", "network interface to capture packets on")
	flag.StringVar(&httpAddress, "address", ":9045", "listening address for the HTTP server exposing metrics")
	flag.Parse()

	// Open PCAP handle to capture packets on the network device.
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to start capture: %s", err.Error())
	}

	// Generate and set the BPF filter.
	// We only care about TCP/UDP through a given port for now.
	filter := fmt.Sprintf("(tcp or udp) and port %d", port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("failed to set filter: %s", err.Error())
	}

	metrics := initMetrics()

	// Start HTTP server to expose Prometheus metrics
	http.Handle("/metrics", promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{Registry: metrics.registry}))
	go func() {
		if err := http.ListenAndServe(httpAddress, nil); err != nil {
			log.Fatalf("failed to start HTTP listener: %s", err.Error())
		}
	}()

	// Setup packet decoder and process all the packets that pass the filter.
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range source.Packets() {
		handlePacket(metrics, port, pkt)
	}
}
