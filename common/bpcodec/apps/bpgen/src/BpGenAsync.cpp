/**
 * @file BpGenAsync.cpp
 * @author  Brian Tomko <brian.j.tomko@nasa.gov>
 * @author  Gilbert Clark
 *
 * @copyright Copyright © 2021 United States Government as represented by
 * the National Aeronautics and Space Administration.
 * No copyright is claimed in the United States under Title 17, U.S.Code.
 * All Other Rights Reserved.
 *
 * @section LICENSE
 * Released under the NASA Open Source Agreement (NOSA)
 * See LICENSE.md in the source root directory for more information.
 */

#include <string.h>
#include <iostream>
#include <openssl/sha.h>  // OpenSSL library for SHA-256
#include "BpGenAsync.h"


struct bpgen_hdr {
	bpgen_hdr();

	uint64_t seq;
	uint64_t tsc;
	timespec abstime;
};

bpgen_hdr::bpgen_hdr() : seq(0), tsc(0)
{
	abstime.tv_nsec = 0;
	abstime.tv_sec = 0;
}

BpGenAsync::BpGenAsync(uint64_t bundleSizeBytes) :
	BpSourcePattern(),
	m_bundleSizeBytes(bundleSizeBytes),
	m_bpGenSequenceNumber(0)
{

}

BpGenAsync::~BpGenAsync() {}

void CalculateSHA256(const uint8_t* data, size_t size, uint8_t* hash) {
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, data, size);
	SHA256_Final(hash, &sha256);
}

uint64_t BpGenAsync::GetNextPayloadLength_Step1() {
	return m_bundleSizeBytes;
}

bool BpGenAsync::CopyPayload_Step2(uint8_t* destinationBuffer) {
	bpgen_hdr bpGenHeader;
	bpGenHeader.seq = m_bpGenSequenceNumber++;
	memcpy(destinationBuffer, &bpGenHeader, sizeof(bpgen_hdr));

	// Calculate SHA-256 hash of the payload
	uint8_t hash[SHA256_DIGEST_LENGTH];
	CalculateSHA256(destinationBuffer, sizeof(bpgen_hdr), hash);
	std::cout << "signature added, hash: " << hash << std::endln;
    

	return true;
}
