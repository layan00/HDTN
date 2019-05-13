#ifndef _MEMORY_MANAGER_TREE_ARRAY_H
#define _MEMORY_MANAGER_TREE_ARRAY_H

#include <boost/integer.hpp>
#include <stdint.h>
#include "BundleStorageConfig.h"


class MemoryManagerTreeArray {
public:
	MemoryManagerTreeArray();
	~MemoryManagerTreeArray();
	boost::uint32_t GetAndSetFirstFreeSegmentId();
	bool FreeSegmentId(boost::uint32_t segmentId);
	static bool UnitTest();

private:
	bool GetAndSetFirstFreeSegmentId(const boost::uint32_t depthIndex, const boost::uint32_t rowIndex, boost::uint32_t * segmentId);
	void FreeSegmentId(const boost::uint32_t depthIndex, const boost::uint32_t rowIndex, boost::uint32_t segmentId, bool *success);
	void SetupTree();
	void FreeTree();
private:

	boost::uint64_t * m_bitMasks[MAX_TREE_ARRAY_DEPTH];
};


#endif //_MEMORY_MANAGER_TREE_ARRAY_H
