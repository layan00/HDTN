/***************************************************************************
 * NASA Glenn Research Center, Cleveland, OH
 * Released under the NASA Open Source Agreement (NOSA)
 * May  2021
 *
 ****************************************************************************
 */


#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "codec/bpv6.h"
#include <inttypes.h>
#include "Sdnv.h"
#include <utility>
#include <iostream>

Bpv6CbhePrimaryBlock::Bpv6CbhePrimaryBlock() { } //a default constructor: X() //don't initialize anything for efficiency, use SetZero if required
Bpv6CbhePrimaryBlock::~Bpv6CbhePrimaryBlock() { } //a destructor: ~X()
Bpv6CbhePrimaryBlock::Bpv6CbhePrimaryBlock(const Bpv6CbhePrimaryBlock& o) :
    m_bundleProcessingControlFlags(o.m_bundleProcessingControlFlags),
    m_blockLength(o.m_blockLength),
    m_destinationEid(o.m_destinationEid),
    m_sourceNodeId(o.m_sourceNodeId),
    m_reportToEid(o.m_reportToEid),
    m_custodianEid(o.m_custodianEid),
    m_creationTimestamp(o.m_creationTimestamp),
    m_lifetimeSeconds(o.m_lifetimeSeconds),
    m_fragmentOffset(o.m_fragmentOffset),
    m_totalApplicationDataUnitLength(o.m_totalApplicationDataUnitLength) { } //a copy constructor: X(const X&)
Bpv6CbhePrimaryBlock::Bpv6CbhePrimaryBlock(Bpv6CbhePrimaryBlock&& o) :
    m_bundleProcessingControlFlags(o.m_bundleProcessingControlFlags),
    m_blockLength(o.m_blockLength),
    m_destinationEid(std::move(o.m_destinationEid)),
    m_sourceNodeId(std::move(o.m_sourceNodeId)),
    m_reportToEid(std::move(o.m_reportToEid)),
    m_custodianEid(std::move(o.m_custodianEid)),
    m_creationTimestamp(std::move(o.m_creationTimestamp)),
    m_lifetimeSeconds(o.m_lifetimeSeconds),
    m_fragmentOffset(o.m_fragmentOffset),
    m_totalApplicationDataUnitLength(o.m_totalApplicationDataUnitLength) { } //a move constructor: X(X&&)
Bpv6CbhePrimaryBlock& Bpv6CbhePrimaryBlock::operator=(const Bpv6CbhePrimaryBlock& o) { //a copy assignment: operator=(const X&)
    m_bundleProcessingControlFlags = o.m_bundleProcessingControlFlags;
    m_blockLength = o.m_blockLength;
    m_destinationEid = o.m_destinationEid;
    m_sourceNodeId = o.m_sourceNodeId;
    m_reportToEid = o.m_reportToEid;
    m_custodianEid = o.m_custodianEid;
    m_creationTimestamp = o.m_creationTimestamp;
    m_lifetimeSeconds = o.m_lifetimeSeconds;
    m_fragmentOffset = o.m_fragmentOffset;
    m_totalApplicationDataUnitLength = o.m_totalApplicationDataUnitLength;
    return *this;
}
Bpv6CbhePrimaryBlock& Bpv6CbhePrimaryBlock::operator=(Bpv6CbhePrimaryBlock && o) { //a move assignment: operator=(X&&)
    m_bundleProcessingControlFlags = o.m_bundleProcessingControlFlags;
    m_blockLength = o.m_blockLength;
    m_destinationEid = std::move(o.m_destinationEid);
    m_sourceNodeId = std::move(o.m_sourceNodeId);
    m_reportToEid = std::move(o.m_reportToEid);
    m_custodianEid = std::move(o.m_custodianEid);
    m_creationTimestamp = std::move(o.m_creationTimestamp);
    m_lifetimeSeconds = o.m_lifetimeSeconds;
    m_fragmentOffset = o.m_fragmentOffset;
    m_totalApplicationDataUnitLength = o.m_totalApplicationDataUnitLength;
    return *this;
}
bool Bpv6CbhePrimaryBlock::operator==(const Bpv6CbhePrimaryBlock & o) const {
    return (m_bundleProcessingControlFlags == o.m_bundleProcessingControlFlags)
        && (m_blockLength == o.m_blockLength)
        && (m_destinationEid == o.m_destinationEid)
        && (m_sourceNodeId == o.m_sourceNodeId)
        && (m_reportToEid == o.m_reportToEid)
        && (m_custodianEid == o.m_custodianEid)
        && (m_creationTimestamp == o.m_creationTimestamp)
        && (m_lifetimeSeconds == o.m_lifetimeSeconds)
        && (m_fragmentOffset == o.m_fragmentOffset)
        && (m_totalApplicationDataUnitLength == o.m_totalApplicationDataUnitLength);
}
bool Bpv6CbhePrimaryBlock::operator!=(const Bpv6CbhePrimaryBlock & o) const {
    return !(*this == o);
}
void Bpv6CbhePrimaryBlock::SetZero() {
    m_bundleProcessingControlFlags = BPV6_BUNDLEFLAG::NO_FLAGS_SET;
    m_blockLength = 0;
    m_destinationEid.SetZero();
    m_sourceNodeId.SetZero();
    m_reportToEid.SetZero();
    m_custodianEid.SetZero();
    m_creationTimestamp.SetZero();
    m_lifetimeSeconds = 0;
    m_fragmentOffset = 0;
    m_totalApplicationDataUnitLength = 0;
}

bool Bpv6CbhePrimaryBlock::DeserializeBpv6(const uint8_t * serialization, uint64_t & numBytesTakenToDecode, uint64_t bufferSize) {
    uint8_t sdnvSize;
    const uint8_t * const serializationBase = serialization;

    if (bufferSize < (SDNV_DECODE_MINIMUM_SAFE_BUFFER_SIZE + 1)) { //version plus flags
        return false;
    }
    const uint8_t version = *serialization++;
    --bufferSize;
    if(version != BPV6_CCSDS_VERSION) {
        return false;
    }
    m_bundleProcessingControlFlags = static_cast<BPV6_BUNDLEFLAG>(SdnvDecodeU64(serialization, &sdnvSize));
    if (sdnvSize == 0) {
        return false;
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;
    const bool isFragment = ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::ISFRAGMENT) != BPV6_BUNDLEFLAG::NO_FLAGS_SET);

    if (bufferSize < SDNV_DECODE_MINIMUM_SAFE_BUFFER_SIZE) {
        return false;
    }
    m_blockLength = SdnvDecodeU64(serialization, &sdnvSize);
    if (sdnvSize == 0) {
        return false;
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;

    if (!m_destinationEid.DeserializeBpv6(serialization, &sdnvSize, bufferSize)) { // sdnvSize will never be 0 if function returns true
        return false; //failure
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;

    if (!m_sourceNodeId.DeserializeBpv6(serialization, &sdnvSize, bufferSize)) { // sdnvSize will never be 0 if function returns true
        return false; //failure
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;

    if (!m_reportToEid.DeserializeBpv6(serialization, &sdnvSize, bufferSize)) { // sdnvSize will never be 0 if function returns true
        return false; //failure
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;

    
    if (!m_custodianEid.DeserializeBpv6(serialization, &sdnvSize, bufferSize)) { // sdnvSize will never be 0 if function returns true
        return false; //failure
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;

    if (!m_creationTimestamp.DeserializeBpv6(serialization, &sdnvSize, bufferSize)) { // sdnvSize will never be 0 if function returns true
        return false; //failure
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;
    
    if (bufferSize < SDNV_DECODE_MINIMUM_SAFE_BUFFER_SIZE) {
        return false;
    }
    m_lifetimeSeconds = SdnvDecodeU64(serialization, &sdnvSize);
    if (sdnvSize == 0) {
        return false;
    }
    serialization += sdnvSize;
    bufferSize -= sdnvSize;

    if (bufferSize == 0) { //dictionary length
        return false;
    }
    const uint8_t dictionaryLength = *serialization++;
    --bufferSize;
    if (dictionaryLength != 0) { //dictionary length (must be 1 byte zero value (1-byte sdnv's are the value itself) 
        //RFC6260
        //3.2.  Reception
        //
        //Upon receiving a bundle whose dictionary length is zero(and only in
        //this circumstance), a CBHE - conformant convergence - layer adapter :
        //
        //1.  MAY infer that the CLA from which the bundle was received is CBHE
        //    conformant.
        //
        //2.  MUST decode the primary block of the bundle in accordance with
        //    the CBHE compression convention described in Section 2.2 before
        //    delivering it to the bundle protocol agent.
        //
        //    Note that when a CLA that is not CBHE conformant receives a bundle
        //    whose dictionary length is zero, it has no choice but to pass it to
        //    the bundle agent without modification.In this case, the bundle
        //    protocol agent will be unable to dispatch the received bundle,
        //    because it will be unable to determine the destination endpoint; the
        //    bundle will be judged to be malformed.The behavior of the bundle
        //    protocol agent in this circumstance is an implementation matter.
        printf("error: cbhe bpv6 primary decode: dictionary size not 0\n");
        return false;
    }

    // Skip the entirety of the dictionary - we assume an IPN scheme

    if(isFragment) {
        if (bufferSize < SDNV_DECODE_MINIMUM_SAFE_BUFFER_SIZE) {
            return false;
        }
        m_fragmentOffset = SdnvDecodeU64(serialization, &sdnvSize);
        if (sdnvSize == 0) {
            return false;
        }
        serialization += sdnvSize;
        bufferSize -= sdnvSize;

        if (bufferSize < SDNV_DECODE_MINIMUM_SAFE_BUFFER_SIZE) {
            return false;
        }
        m_totalApplicationDataUnitLength = SdnvDecodeU64(serialization, &sdnvSize);
        if (sdnvSize == 0) {
            return false;
        }
        serialization += sdnvSize;
        bufferSize -= sdnvSize;
    }
    else {
        m_fragmentOffset = 0;
        m_totalApplicationDataUnitLength = 0;
    }

    numBytesTakenToDecode = serialization - serializationBase;
    return true;
}

uint64_t Bpv6CbhePrimaryBlock::SerializeBpv6(uint8_t * serialization) const {
    uint8_t * const serializationBase = serialization;

    *serialization++ = BPV6_CCSDS_VERSION;
    serialization += SdnvEncodeU64(serialization, static_cast<uint64_t>(m_bundleProcessingControlFlags));
    const bool isFragment = ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::ISFRAGMENT) != BPV6_BUNDLEFLAG::NO_FLAGS_SET);

    uint8_t * const blockLengthPtrForLater = serialization++; // we skip one byte so we can come back and write it later
    
    serialization += m_destinationEid.SerializeBpv6(serialization);
    serialization += m_sourceNodeId.SerializeBpv6(serialization);
    serialization += m_reportToEid.SerializeBpv6(serialization);
    serialization += m_custodianEid.SerializeBpv6(serialization);
    
    serialization += m_creationTimestamp.SerializeBpv6(serialization);

    serialization += SdnvEncodeU64(serialization, m_lifetimeSeconds);
    
    // encode a zero-length dictionary
    *serialization++ = 0; // 1-byte sdnv's are the value itself

    if (isFragment) {
        serialization += SdnvEncodeU64(serialization, m_fragmentOffset);
        serialization += SdnvEncodeU64(serialization, m_totalApplicationDataUnitLength);
    }

    const uint64_t blockLength = serialization - (blockLengthPtrForLater + 1);
    if (blockLength > 127) { // our encoding failed because our block length was too long ...
        printf("error in Bpv6CbhePrimaryBlock::SerializeBpv6 blockLength > 127\n");
        return 0;
    }
    *blockLengthPtrForLater = static_cast<uint8_t>(blockLength); // 1-byte sdnv's are the value itself
    
    return serialization - serializationBase;
}

void bpv6_canonical_block::SetZero() {
    flags = 0;
    length = 0;
    type = 0;
}

uint32_t bpv6_canonical_block::bpv6_canonical_block_decode(const char* buffer, const size_t offset, const size_t bufsz) {
    uint64_t index = offset;
    uint8_t sdnvSize;
    type = buffer[index++];

    const uint8_t flag8bit = buffer[index];
    if (flag8bit <= 127) {
        flags = flag8bit;
        ++index;
    }
    else {
        flags = SdnvDecodeU64((const uint8_t *)&buffer[index], &sdnvSize);
        if (sdnvSize == 0) {
            return 0; //return 0 on failure
        }
        index += sdnvSize;
    }

    length = SdnvDecodeU64((const uint8_t *)&buffer[index], &sdnvSize);
    if (sdnvSize == 0) {
        return 0; //return 0 on failure
    }
    index += sdnvSize;

    return static_cast<uint32_t>(index - offset);
}

uint32_t bpv6_canonical_block::bpv6_canonical_block_encode(char* buffer, const size_t offset, const size_t bufsz) const {
    uint64_t index = offset;
    uint64_t sdnvSize;
    buffer[index++] = type;

    if (flags <= 127) {
        buffer[index++] = static_cast<uint8_t>(flags);
    }
    else {
        sdnvSize = SdnvEncodeU64((uint8_t *)&buffer[index], flags);
        index += sdnvSize;
    }

    sdnvSize = SdnvEncodeU64((uint8_t *)&buffer[index], length);
    index += sdnvSize;

    return static_cast<uint32_t>(index - offset);
}

void Bpv6CbhePrimaryBlock::bpv6_primary_block_print() const {
    printf("BPv6 / Primary block (%" PRIu64 " bytes)\n", m_blockLength);
    printf("Flags: 0x%" PRIx64 "\n", static_cast<uint64_t>(m_bundleProcessingControlFlags));
    if((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::NOFRAGMENT) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* No fragmentation allowed\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::ISFRAGMENT) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Bundle is a fragment\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::ADMINRECORD) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Bundle is administrative (control) traffic\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::CUSTODY_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Custody transfer requested\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::USER_APP_ACK_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Application acknowledgment requested.\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::CUSTODY_STATUS_REPORTS_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Custody reporting requested.\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::DELIVERY_STATUS_REPORTS_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Delivery reporting requested.\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::DELETION_STATUS_REPORTS_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Deletion reporting requested.\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::FORWARDING_STATUS_REPORTS_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Forward reporting requested.\n");
    }
    if ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::RECEPTION_STATUS_REPORTS_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET) {
        printf("* Reception reporting requested.\n");
    }
    const BPV6_PRIORITY priority = GetPriorityFromFlags(m_bundleProcessingControlFlags);
    std::cout << "Priority: " << priority << "\n";

    std::cout << "Destination: " << m_destinationEid << "\n";
    std::cout << "Source: " << m_sourceNodeId << "\n";
    std::cout << "Custodian: " << m_custodianEid << "\n";
    std::cout << "Report-to: " << m_reportToEid << "\n";

    std::cout << "Creation: " << m_creationTimestamp << "\n";
    printf("Lifetime: %" PRIu64 "\n", m_lifetimeSeconds);
}

void bpv6_canonical_block::bpv6_canonical_block_print() const {
    printf("Canonical block [type %u]\n", type);
    switch(type) {
        case BPV6_BLOCKTYPE_AUTHENTICATION:
            printf("> Authentication block\n");
            break;
        case BPV6_BLOCKTYPE_EXTENSION_SECURITY:
            printf("> Extension security block\n");
            break;
        case BPV6_BLOCKTYPE_INTEGRITY:
            printf("> Integrity block\n");
            break;
        case BPV6_BLOCKTYPE_METADATA_EXTENSION:
            printf("> Metadata block\n");
            break;
        case BPV6_BLOCKTYPE_PAYLOAD:
            printf("> Payload block\n");
            break;
        case BPV6_BLOCKTYPE_PAYLOAD_CONF:
            printf("> Payload confidentiality block\n");
            break;
        case BPV6_BLOCKTYPE_PREV_HOP_INSERTION:
            printf("> Previous hop insertion block\n");
            break;
        case BPV6_BLOCKTYPE_CUST_TRANSFER_EXT:
       	    printf("> ACS custody transfer extension block (CTEB)\n");
            break;
        case BPV6_BLOCKTYPE_BPLIB_BIB:
   	    printf("> Bplib bundle integrity block (BIB)\n");
            break;
        case BPV6_BLOCKTYPE_BUNDLE_AGE:
            printf("> Bundle age extension (BAE)\n");
            break;
        default:
            printf("> Unknown block type\n");
            break;
    }
    bpv6_block_flags_print();
    printf("Block length: %" PRIu64 " bytes\n", length);
}

void bpv6_canonical_block::bpv6_block_flags_print() const {
    printf("Flags: 0x%" PRIx64 "\n", flags);
    if (flags & BPV6_BLOCKFLAG_LAST_BLOCK) {
        printf("* Last block in this bundle.\n");
    }
    if (flags & BPV6_BLOCKFLAG_DISCARD_BLOCK_FAILURE) {
        printf("* Block should be discarded upon failure to process.\n");
    }
    if (flags & BPV6_BLOCKFLAG_DISCARD_BUNDLE_FAILURE) {
        printf("* Bundle should be discarded upon failure to process.\n");
    }
    if (flags & BPV6_BLOCKFLAG_EID_REFERENCE) {
        printf("* This block references elements from the dictionary.\n");
    }
    if (flags & BPV6_BLOCKFLAG_FORWARD_NOPROCESS) {
        printf("* This block was forwarded without being processed.\n");
    }

}

bool Bpv6CbhePrimaryBlock::HasCustodyFlagSet() const {
    return ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::CUSTODY_REQUESTED) != BPV6_BUNDLEFLAG::NO_FLAGS_SET);
}
bool Bpv6CbhePrimaryBlock::HasFragmentationFlagSet() const {
    return ((m_bundleProcessingControlFlags & BPV6_BUNDLEFLAG::ISFRAGMENT) != BPV6_BUNDLEFLAG::NO_FLAGS_SET);
}

cbhe_bundle_uuid_t Bpv6CbhePrimaryBlock::GetCbheBundleUuidFromPrimary() const {
    cbhe_bundle_uuid_t uuid;
    uuid.creationSeconds = m_creationTimestamp.secondsSinceStartOfYear2000;
    uuid.sequence = m_creationTimestamp.sequenceNumber;
    uuid.srcEid = m_sourceNodeId;
    uuid.fragmentOffset = m_fragmentOffset;
    uuid.dataLength = m_totalApplicationDataUnitLength;
    return uuid;
}
cbhe_bundle_uuid_nofragment_t Bpv6CbhePrimaryBlock::GetCbheBundleUuidNoFragmentFromPrimary() const {
    cbhe_bundle_uuid_nofragment_t uuid;
    uuid.creationSeconds = m_creationTimestamp.secondsSinceStartOfYear2000;
    uuid.sequence = m_creationTimestamp.sequenceNumber;
    uuid.srcEid = m_sourceNodeId;
    return uuid;
}

cbhe_eid_t Bpv6CbhePrimaryBlock::GetFinalDestinationEid() const {
    return m_destinationEid;
}
uint8_t Bpv6CbhePrimaryBlock::GetPriority() const {
    return static_cast<uint8_t>(GetPriorityFromFlags(m_bundleProcessingControlFlags));
}
uint64_t Bpv6CbhePrimaryBlock::GetExpirationSeconds() const {
    return m_creationTimestamp.secondsSinceStartOfYear2000 + m_lifetimeSeconds;
}
uint64_t Bpv6CbhePrimaryBlock::GetSequenceForSecondsScale() const {
    return m_creationTimestamp.sequenceNumber;
}
uint64_t Bpv6CbhePrimaryBlock::GetExpirationMilliseconds() const {
    return (m_creationTimestamp.secondsSinceStartOfYear2000 + m_lifetimeSeconds) * 1000;
}
uint64_t Bpv6CbhePrimaryBlock::GetSequenceForMillisecondsScale() const {
    return m_creationTimestamp.sequenceNumber;
}
