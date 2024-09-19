<h1 align="center">
  <br>
  netpeek
  <br>
</h1>
<h4 align="center">A small utility to expose protocol level network metrics</h4>
<p align="center">
  <a href="https://pkg.go.dev/github.com/streamer45/netpeek"><img src="https://pkg.go.dev/badge/github.com/streamer45/netpeek.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<br>

### Requirements

- [Golang](https://go.dev/doc/install) >= v1.22
- A C compiler (e.g. GCC)
- [libpcap](https://www.tcpdump.org/)

### Usage

```sh
make
sudo ./dist/netpeek -i eth0 -p 80
curl http://localhost:9045/metrics
```

### License

MIT License - see [LICENSE](LICENSE) for full text
