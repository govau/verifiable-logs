# Verifiable Data Structures

This repository contains a number of tools that are designed to make it easy to experiment with the use of Verifiable Data Structures to apply to datasets made available by government agencies.

While the first wave of open data facilitated by initiatives such as [data.gov.au](https://data.gov.au) has been eagerly adopted by many interested parties, we believe that it is important to take advantage of a new wave of cryptographic application to be be able to publish datasets that are not only open, but are also able to prove properties about their own correctness (such as append-only, no tampering).

## Technical background and approaches

In the late 1970s Ralph Merkle coined the term [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree), an mechanism by which the integrity of large amounts of data could be verified and reasonabed about in an efficient manner, and the principles behind Merkle Trees have found their way into modern systems, being used in source control systems such as [Git](https://blog.sourced.tech/post/difftree/) and [Subversion](https://paulhammant.com/2017/09/17/old-school-merkle-trees-rock/), but perhaps are most well popularzied in recent times for underpinning [Blockchain](https://www.blockchain-council.org/blockchain/what-is-merkel-tree-merkel-root-in-blockchain/), the ledger behind the decentralized crypto-currency, Bitcoin.

Merkle Trees are also used to by [RFC6962](https://tools.ietf.org/html/rfc6962#section-2.1) which is a specification for publicly verifiable append-only  log of X.509 Certificates, intended to allow any interested party to verify the correct operation of the set of Certificate Authorities trusted by browsers to [underpin the security of the internet](https://www.certificate-transparency.org/).

While Blockchain and RFC6962 are both based on the same cryptographic primitive (Merkle Trees), the Bitcoin-style Blockchain ledger are typically decentralized, whereby no central authority vouches for the integrity of the data within, rather each node in the network votes based on the amount of compute power they have (and can prove they have by a [tremendously energy-expensive proof-of-work algorithm](https://www.theguardian.com/commentisfree/2017/nov/26/trouble-with-bitcoin-big-data-huge-energy-bill)).

## Applicability to agencies

We believe that a typical agency who is responsible for publishing an open dataset is already the authority for its correctness, and as such has no need to allow other unrelated parties to "vote" on which dataset is the current state of truth, and as such we don't believe that a Bitcoin-style Blockchain is appropriate for a typical dataset published by an agency.

For example, imagine land registry data that records who owns which piece of lang - should a party with deep pockets be able to affect the accepted state of a who owns which land simply by buying more compute power?

We do however believe that we should experiment with making full-use of the benefits that a Blockchain ledger can provide, namely the transparency afforded by public append-only verifiable log structures that Merkle Trees can provide.


## data.gov.au meets RFC6962

RFC6962 describes an efficient, and widely used, log format for capturing X.509 Certificates as issued by Certificate Authorities. The specification was released in June 2013, and at this point has been used for its original purpose by over 70 logs holding over 1 billion certificate entries. Chrome, Firefox and Apple have all 