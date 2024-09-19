package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"

	pcap "github.com/packetcap/go-pcap"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
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

	m.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
		Namespace: metricsNamespace,
	}))

	m.rxCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "rx_bytes_total",
		Help:      "The total number of received bytes.",
	}, []string{"protocol", "src_addr", "src_port"})
	m.registry.MustRegister(m.rxCounter)

	m.txCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "tx_bytes_total",
		Help:      "The total number of transmitted bytes.",
	}, []string{"protocol", "dst_addr", "dst_port"})
	m.registry.MustRegister(m.txCounter)

	return &m
}

func handlePacket(m *metrics, srcAddrs []string, targetPort int, pkt gopacket.Packet) {
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

	if srcPort == targetPort && slices.Contains(srcAddrs, dstAddr) {
		// incoming packet
		m.rxCounter.With(prometheus.Labels{
			"protocol": protocol,
			"src_addr": srcAddr,
			"src_port": fmt.Sprintf("%d", srcPort),
		}).Add(float64(pktLen))
	} else if dstPort == targetPort && slices.Contains(srcAddrs, srcAddr) {
		// outgoing packet
		m.txCounter.With(prometheus.Labels{
			"protocol": protocol,
			"dst_addr": dstAddr,
			"dst_port": fmt.Sprintf("%d", dstPort),
		}).Add(float64(pktLen))
	}
}

func main() {
	var port int
	var iface string
	var httpAddress string

	flag.IntVar(&port, "port", 8065, "port number to capture packets on")
	flag.StringVar(&iface, "iface", "lo", "network interface to capture packets on")
	flag.StringVar(&httpAddress, "address", ":9045", "listening address for the HTTP server exposing metrics")
	flag.Parse()

	// Find addresses for the given interface.
	nif, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("failed to get interface: %s", err.Error())
	}
	addrs, err := nif.Addrs()
	if err != nil {
		log.Fatalf("failed to get interface addresses: %s", err.Error())
	}

	var ips []string
	for i := range addrs {
		prefix, err := netip.ParsePrefix(addrs[i].String())
		if err != nil {
			log.Fatalf("failed to parse prefix: %s", err.Error())
		}
		ips = append(ips, prefix.Addr().String())
	}

	log.Printf("addrs: %v", ips)

	// Open PCAP handle to capture packets on the network device.
	handle, err := pcap.OpenLive(iface, 1600, true, 0, false)
	if err != nil {
		log.Fatalf("failed to start capture: %s", err.Error())
	}

	// Generate and set the BPF filter.
	// We only care about packets over a single port for now.
	filter := fmt.Sprintf("port %d", port)
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
	source := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	source.NoCopy = true
	for pkt := range source.Packets() {
		handlePacket(metrics, ips, port, pkt)
	}
}
