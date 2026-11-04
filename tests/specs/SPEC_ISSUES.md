# Proposed IPFIX Specification Errata

This document lists errors and inconsistencies found in the IPFIX specifications that are **not** part of the [published errata](https://www.rfc-editor.org/errata_search.php?rfc=7011). These issues were discovered during implementation and validation of the ipfix-parser library and are candidates for submission as errata.

Each issue includes the current specification text and a proposed correction.

## 1. Message Header: "Version Number" vs "Version"

**Affected Specification:** [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011) (2013), Section 3.1

**Affected Structure:** IPFIX Message Header (Figure F)

### Issue

Figure F labels the first field of the Message Header **Version Number**, but the field definitions that follow the figure name it **Version**. Every other field of the figure (Length, Export Time, Sequence Number, Observation Domain ID) uses the same name in the figure and in the definitions.

The IANA registry for this field is itself named "IPFIX Version Numbers", so either name is defensible, but the two should match.

**Current:**
```text
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |       Version Number          |            Length             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Version

      Version of IPFIX to which this Message conforms.  The value of
      this field is 0x000a for the current version, incrementing by one
      the version used in the NetFlow services export version 9
      [RFC3954].
```

**Proposed Correction:**
```text
   Version Number

      Version of IPFIX to which this Message conforms.  The value of
      this field is 0x000a for the current version, incrementing by one
      the version used in the NetFlow services export version 9
      [RFC3954].
```

### Implementation

The Rust field follows the definition list (`MessageHeader::version`), which is what the [RFC structures validation](README.md) compares against.
