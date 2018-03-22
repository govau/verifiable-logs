//go:generate protoc -Ipb pb/metadata.proto --go_out=pb
//go:generate go-bindata -debug -pkg assets -o assets/assets.go assets/static/

package verifiablelogs
