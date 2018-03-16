//go:generate protoc -Iproto proto/metadata.proto --go_out=pb

package verifiablelog

// MetadataResponse is a subset of a log as defined at: https://www.gstatic.com/ct/log_list/log_list_schema.json
type MetadataResponse struct {
	Key []byte `json:"key"`
}
