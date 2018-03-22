# Variations to RFC6962

The verifiable log server that we have exposed is based on RFC6962 with minor changes as decribed below.

## TLS Structures

The following 3 TLS structures are modified to accepted a 3rd type of entry, `objecthash_entry` (changes in **bold**):

### [Section 3.1 - Log Entries](https://tools.ietf.org/html/rfc6962#section-3.1)

<pre>
enum { x509_entry(0), precert_entry(1)<b>, objecthash_entry(32769)</b> (65535) } LogEntryType;

<b>opaque ObjectHash[32];</b>

struct {
   LogEntryType entry_type;
   select (entry_type) {
       case x509_entry: X509ChainEntry;
       case precert_entry: PrecertChainEntry;
       <b>case objecthash_entry: ObjectHash;</b>
   } entry;
} LogEntry;
</pre>

### [Section 3.2 - Structure of the Signed Certificate Timestamp](https://tools.ietf.org/html/rfc6962#section-3.2)

<pre>
struct {
   Version sct_version;
   LogID id;
   uint64 timestamp;
   CtExtensions extensions;
   digitally-signed struct {
       Version sct_version;
       SignatureType signature_type = certificate_timestamp;
       uint64 timestamp;
       LogEntryType entry_type;
       select(entry_type) {
           case x509_entry: ASN.1Cert;
           case precert_entry: PreCert;
           <b>case object_hash: ObjectHash;</b>
       } signed_entry;
      CtExtensions extensions;
   };
} SignedCertificateTimestamp;
</pre>

### [Section 3.4 - Merkle Tree](https://tools.ietf.org/html/rfc6962#section-3.4)

<pre>
struct {
   uint64 timestamp;
   LogEntryType entry_type;
   select(entry_type) {
       case x509_entry: ASN.1Cert;
       case precert_entry: PreCert;
       <b>case object_hash: ObjectHash;</b>
   } signed_entry;
   CtExtensions extensions;
} TimestampedEntry;
</pre>

## Log Client Messages

This describes the Log Client messages that may be sent to the Log. Note that the base URL for a log is:

`https://<server>/dataset/<log>`

where a single server may host many verifiable logs, each under a different path are differentiated by the `<log>` above.


### Identical messages

The following messages are implemented as per RFC with no changes:

- [4.4.  Retrieve Merkle Consistency Proof between Two Signed Tree Heads](https://tools.ietf.org/html/rfc6962#section-4.4)
- [4.5.  Retrieve Merkle Audit Proof from Log by Leaf Hash](https://tools.ietf.org/html/rfc6962#section-4.5)
- [4.6.  Retrieve Entries from Log](https://tools.ietf.org/html/rfc6962#section-4.6)
- [4.8.  Retrieve Entry+Merkle Audit Proof from Log](https://tools.ietf.org/html/rfc6962#section-4.8)

### Augmented messages

The following messages are implemented as per RFC with minor additions:

#### [4.3.  Retrieve Latest Signed Tree Head](https://tools.ietf.org/html/rfc6962#section-4.3)

An optional parameter `tree_size` is added. Outputs are unchanged:

<pre>
GET https://&lt;server&gt;/dataset/&lt;log&gt;/ct/v1/get-sth

<del>No inputs.</del>

<b>Inputs:

      tree_size (optional):  The tree_size of the tree on which to base the signed tree head,
         in decimal. If set to 0, then the latest available is returned (same as not setting it).</b>

Outputs:

    tree_size:  The size of the tree, in entries, in decimal.

    timestamp:  The timestamp, in decimal.

    sha256_root_hash:  The Merkle Tree Hash of the tree, in base64.

    tree_head_signature:  A TreeHeadSignature for the above data.
</pre>

### New messages

The following meessages are not defined by the RFC and are specific to our implementation:

#### Add ObjectHash

This is not defined in RFC6962, and is designed to allow adding arbitrary data to a verifiable log. It replaces "Add Chain to Log" and "Add PreCertChain to Log".

```rfc
POST https://<server>/dataset/<log>/ct/v1/add-objecthash

Inputs (JSON):

  hash:  32 base64-encoded bytes. This is incorporated into the log
     as part of the TimestampedEntry, and is used as input to the
     SignedCertificateTimestamp. Normally this is the Object Hash of the
     extra_data object.

  extra_data:  Arbitrary JSON structure as relevant to the client.
     This data is not processed, other than being serialized and made
     availabe via "/get-entries". Expected usage is that this is the
     object from which the "hash" was generated.

Outputs:

   (same as defined by for "Add Chain to Log")
```

The [Object Hash](https://github.com/benlaurie/objecthash) is that described [here](https://github.com/benlaurie/objecthash).

Note that this API requires authentication (since it adds data to a log), and we do not define the mechanism in this document, as it is currently intended as an implementation detail between different components in this repository.

#### Get ObjectHash

This is not defined in RFC6962, and is designed to allow fetching a signed certificate timestamp for an already added hash.

```rfc
GET https://<server>/dataset/<log>/ct/v1/get-objecthash

Inputs:

  hash:  32 base64-encoded bytes representing the objecthash to look up.

Outputs:

   (same as defined by for "Add Chain to Log")
```

The [Object Hash](https://github.com/benlaurie/objecthash) is that described [here](https://github.com/benlaurie/objecthash).

#### Get Metadata

Returns the public key for a log.

```rfc
POST https://<server>/dataset/<log>/ct/v1/metadata

Inputs:  none

Outputs (JSON):

   key:  base-64 encoded ASN.1 DER-encoded ECDSA public key
```

### Unimplemented messages

The following messages are specific to an X.509 Certificate Transparency log, and as such are not implemented in our logs:

- [4.1.  Add Chain to Log](https://tools.ietf.org/html/rfc6962#section-4.1)
- [4.2.  Add PreCertChain to Log](https://tools.ietf.org/html/rfc6962#section-4.2)
- [4.7.  Retrieve Accepted Root Certificates](https://tools.ietf.org/html/rfc6962#section-4.7)
