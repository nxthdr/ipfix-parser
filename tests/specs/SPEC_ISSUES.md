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

## 2. Type Information Example: Field Length 65536

**Affected Specification:** [RFC 5610](https://www.rfc-editor.org/rfc/rfc5610) (2009), Appendix A

**Affected Structure:** Example Information Element Type Options Template (Figure 2)

### Issue

The last Field Specifier of the example Options Template, `informationElementName`, has a Field Length of **65536**. This value cannot be encoded: the Field Length is a 16-bit field, and variable-length Information Elements use the reserved value **65535** ([RFC 7011 Section 7](https://www.rfc-editor.org/rfc/rfc7011#section-7)).

[Erratum 4731](https://www.rfc-editor.org/errata/eid4731) corrects the Length (26 → 30) and the Field Count (4 → 5) of this figure, but keeps the Field Length of 65536.

**Current (with Erratum 4731):**
```text
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Field Length = 1        |0| inf.El.Name             341 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Field Length = 65536      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Proposed Correction:**
```text
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Field Length = 1        |0| inf.El.Name             341 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Field Length = 65535      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Implementation

`test_rfc5610_appendix_a_example` (`tests/unit/enterprise_elements.rs`) reproduces the example with Erratum 4731 and a Field Length of 65535.
