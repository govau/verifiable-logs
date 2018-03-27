# Verifiable Data Structures

[[Jump to Getting Started]](./doc/install.md)

#### *Status: Experimental (March 2018)*


This repository contains a number of tools that are designed to make it easy to experiment with the use of Verifiable Data Structures to apply to datasets made available by government agencies.

While the first wave of open data facilitated by initiatives such as [data.gov.au](https://data.gov.au) has been eagerly adopted by many interested parties, it is important to take advantage of a new wave of cryptographic application to be be able to publish datasets that are not only open, but are also able to prove properties about their own correctness (such as append-only, no tampering).

## Technical background and approaches

In the late 1970s Ralph Merkle coined the term [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree), an mechanism by which the integrity of large amounts of data could be verified and reasonabed about in an efficient manner, and the principles behind Merkle Trees have found their way into modern systems, being used in source control systems such as [Git](https://blog.sourced.tech/post/difftree/) and [Subversion](https://paulhammant.com/2017/09/17/old-school-merkle-trees-rock/), but perhaps are most well popularized in recent times for underpinning [Blockchain](https://www.blockchain-council.org/blockchain/what-is-merkel-tree-merkel-root-in-blockchain/), the ledger behind the decentralized crypto-currency, Bitcoin.

Merkle Trees are also used to by [RFC6962](https://tools.ietf.org/html/rfc6962#section-2.1) which is a specification for publicly verifiable append-only  log of X.509 Certificates, intended to allow any interested party to verify the correct operation of the set of Certificate Authorities trusted by browsers to [underpin the security of the internet](https://www.certificate-transparency.org/).

While Blockchain and RFC6962 are both based on the same cryptographic primitive (Merkle Trees), the Bitcoin-style Blockchain ledger are typically decentralized, whereby no central authority vouches for the integrity of the data within, rather each node in the network votes based on the amount of compute power they have (and can prove they have by a [tremendously energy-expensive proof-of-work algorithm](https://www.theguardian.com/commentisfree/2017/nov/26/trouble-with-bitcoin-big-data-huge-energy-bill)).

## Applicability to agencies

A typical agency who is responsible for publishing an open dataset is already the authority for its correctness, and as such by default there seems little need to allow other unrelated parties to "vote" on which dataset is the current state of truth, and as such there is questionable upside, and significant downside that a Bitcoin-style Blockchain would bring to a typical dataset published by an agency.

For example, a imagine land registry data that records who owns which piece of lang - should a party with deep pockets be able to affect the accepted state of a who owns which land simply by buying more compute power?

It is interesting however to consider how an agency can make full use of the benefits that a Blockchain ledger can provide, namely the transparency afforded by public append-only verifiable log structures that Merkle Trees can provide, so we look to other approaches in this area.

## Introducing Certificate Transparency

[RFC6962](https://tools.ietf.org/html/rfc6962) describes an efficient, and widely used, log format for capturing X.509 Certificates as issued by Certificate Authorities. The specification was released in June 2013, and at this point has been used for its original purpose by over 70 logs holding over 1 billion certificate entries. Chrome, Firefox and Apple have all adopted usage of Certificate Transparency to various degrees and it has already been used to detect and fix a number of issues with Certificate Authorities.

In late 2015 the Google Certificate Transparency team [published a paper](https://github.com/google/trillian/blob/master/docs/VerifiableDataStructures.pdf) discussing how the same concepts used for Certificate Transparency could apply to [General Transparency](https://github.com/google/trillian/blob/master/docs/VerifiableDataStructures.pdf).

At around the same time, [Tom Loosemore](https://tom.loosemore.com/about/), (formerly Deputy Director of the UK GDS), delivered an address to the Code for America Summit exploring the use of Merkle Trees, Blockchain and Certificate Transparency as applicable to Government Registers, 

[![Tom Loosemore video discussing Merkle Trees](https://img.youtube.com/vi/VjE_zj-7A7A/0.jpg)](https://youtu.be/VjE_zj-7A7A?t=47m40s)

([Link to YouTube, skips to 47m40s in](https://youtu.be/VjE_zj-7A7A?t=47m40s))

## Application of an RFC6962-style log to an open dataset

To experiment with verifiable datasets, we're working on the following:

1. Deploying an RFC6962-based Verifiable Log server to [cloud.gov.au](https://cloud.gov.au) (details [here](./doc/rfc6962-objecthash.md)).
2. Creating a trigger that a dataset hosted on [data.gov.au](https://data.gov.au) can choose to use, which will submit all entries added to a dataset, to a corresponding Verifiable Log.

### What will this enable?

This enable the owner of any public dataset on data.gov.au to be able to easily enable verifiable properties for their dataset.

After a row is added to the verifiable log, the row will be updated with a `signed_certificate_timestamp` field.

Any interested party can then:

1. Statically verify the `signed_certificate_timestamp` matches the row (and they should do so, before accepting the row for processing).
2. Efficient verify the inclusion of a row in a verifiable log, by requesting an inclusion proof.
3. Efficiently verify the consistency of a log between two fetched states, proving the append-only properties of the log.
4. Audit, by fetching all entries, the correct operation of the log.

## Next

[[Jump to Getting Started]](./doc/install.md)
