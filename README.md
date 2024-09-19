<h1 align="center">
  <br>
  netpeek
  <br>
</h1>
<h4 align="center">A small utility to expose protocol level network metrics</h4>
<p align="center">
  <a href="https://pkg.go.dev/github.com/streamer45/netpeek"><img src="https://pkg.go.dev/badge/github.com/streamer45/netpeek.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square" alt="License: Apache License 2.0"></a>
</p>
<br>

### Requirements

- [Golang](https://go.dev/doc/install) >= v1.22

### Usage

```sh
make
sudo ./dist/netpeek -i lo -p 80
curl http://localhost:9045/metrics
```

### License

MIT License - see [LICENSE](LICENSE) for full text
