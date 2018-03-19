//go:generate protoc -Ipb pb/metadata.proto --go_out=pb

package verifiablelogs

// MetadataResponse is a subset of a log as defined at: https://www.gstatic.com/ct/log_list/log_list_schema.json
type MetadataResponse struct {
	// Key is the ASN.1 DER encoded ECDSA public key for the log
	Key []byte `json:"key"`
}
