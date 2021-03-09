#include <math.h>

#include <iostream>

#include "message.hpp"
#include "store.hpp"
#include "BundleStorageManagerMT.h"
#include <set>
#include <boost/lexical_cast.hpp>

hdtn::ZmqStorageInterface::ZmqStorageInterface() : m_running(false) {}

hdtn::ZmqStorageInterface::~ZmqStorageInterface() {
    Stop();
}

void hdtn::ZmqStorageInterface::Stop() {
    m_running = false; //thread stopping criteria
    if (m_threadPtr) {
            m_threadPtr->join();
    }
    m_threadPtr = boost::shared_ptr<boost::thread>();
    
}

void hdtn::ZmqStorageInterface::init(zmq::context_t *ctx, const storageConfig & config) {
    m_zmqContextPtr = ctx;
    m_storageConfigFilePath = config.storePath;
    m_queue = config.worker;
}

static void Write(hdtn::BlockHdr *hdr, zmq::message_t *message, BundleStorageManagerMT & bsm) {
    //res = blosc_compress_ctx(9, 0, 4, message->size(), message->data(), outBuf, HDTN_BLOSC_MAXBLOCKSZ, "lz4", 0, 1);
        //storeFlow.write(hdr->flow_id, outBuf, res);

    const boost::uint64_t size = message->size();
    boost::uint8_t * data = (boost::uint8_t *) message->data();


    const unsigned int linkId = hdr->flowId; //std::cout << "linkIdWrite: " << linkId << " sz " << size << std::endl;
    const unsigned int priorityIndex = hdr->ttl; //use ttl for now.. could be 0, 1, or 2, but keep constant for fifo mode
    //static abs_expiration_t bundleI = 0;
    //const abs_expiration_t absExpiration = bundleI++; //increment this every time for fifo mode
    const uint64_t absExpirationUsec = hdr->ts; //use ts for now

    BundleStorageManagerSession_WriteToDisk sessionWrite;
    bp_primary_if_base_t bundleMetaData;
    bundleMetaData.flags = (priorityIndex & 3) << 7;
    bundleMetaData.dst_node = linkId;
    bundleMetaData.length = size;
    bundleMetaData.creation = 0;
    bundleMetaData.lifetime = absExpirationUsec;

    boost::uint64_t totalSegmentsRequired = bsm.Push(sessionWrite, bundleMetaData);
    //std::cout << "totalSegmentsRequired " << totalSegmentsRequired << "\n";
    if (totalSegmentsRequired == 0) {
        std::cerr << "out of space\n";
        return;
    }
    //totalSegmentsStoredOnDisk += totalSegmentsRequired;
    //totalBytesWrittenThisTest += size;

    for (boost::uint64_t i = 0; i < totalSegmentsRequired; ++i) {
        std::size_t bytesToCopy = BUNDLE_STORAGE_PER_SEGMENT_SIZE;
        if (i == totalSegmentsRequired - 1) {
            boost::uint64_t modBytes = (size % BUNDLE_STORAGE_PER_SEGMENT_SIZE);
            if (modBytes != 0) {
                bytesToCopy = modBytes;
            }
        }

        bsm.PushSegment(sessionWrite, &data[i*BUNDLE_STORAGE_PER_SEGMENT_SIZE], bytesToCopy);
    }
}
/*
static void ReleaseData(uint32_t flow, uint64_t rate, uint64_t duration, zmq::socket_t *egressSock, BundleStorageManagerMT & bsm) {
    std::cout << "release worker triggered." << std::endl;
    //int dataReturned = 0;
    //uint64_t totalReturned = 0;
    hdtn::BlockHdr block;
    memset(&block, 0, sizeof(hdtn::BlockHdr));
    const boost::uint64_t largestBundleSize = HDTN_BLOSC_MAXBLOCKSZ * 2;
    std::vector<boost::uint8_t> bundleReadBack(largestBundleSize, 0); //initialize it to zero

    //timeval tv;
    //gettimeofday(&tv, NULL);
    //double start = (tv.tv_sec + (tv.tv_usec / 1000000.0));

    unsigned int numBundlesReadBack = 0;
    while(1) {

        boost::this_thread::sleep(boost::posix_time::milliseconds(1)); //TODO: storage reads too fast for egress to send data.. need an acking mechanism.
            std::vector<boost::uint64_t> availableDestLinks = { flow }; //fifo mode, only put in the one link you want to read (could be more tho)


            //std::cout << "reading\n";
            BundleStorageManagerSession_ReadFromDisk sessionRead;
            boost::uint64_t bytesToReadFromDisk = bsm.PopTop(sessionRead, availableDestLinks);
            //std::cout << "bytesToReadFromDisk " << bytesToReadFromDisk << "\n";
            if (bytesToReadFromDisk == 0) { //no more of these links to read
                    break;
            }
            else {//this link has a bundle in the fifo


                    //USE THIS COMMENTED OUT CODE IF YOU DECIDE YOU DON'T WANT TO READ THE BUNDLE AFTER PEEKING AT IT (MAYBE IT'S TOO BIG RIGHT NOW)
                    //return top then take out again
                    //bsm.ReturnTop(sessionRead);
                    //bytesToReadFromDisk = bsm.PopTop(sessionRead, availableDestLinks); //get it back


                    const std::size_t numSegmentsToRead = sessionRead.chainInfo.second.size();
                    std::size_t totalBytesRead = 0;
                    for (std::size_t i = 0; i < numSegmentsToRead; ++i) {
                            totalBytesRead += bsm.TopSegment(sessionRead, &bundleReadBack[i*BUNDLE_STORAGE_PER_SEGMENT_SIZE]);
                    }
                    //std::cout << "totalBytesRead " << totalBytesRead << "\n";
                    if(totalBytesRead != bytesToReadFromDisk){
                        std::cout << "error: totalBytesRead != bytesToReadFromDisk\n";
                    }




                    //if you're happy with the bundle data you read back, then officially remove it from the disk
                    bool successRemoveBundle = bsm.RemoveReadBundleFromDisk(sessionRead);
                    if(!successRemoveBundle) {
                        std::cout << "error freeing bundle from disk\n";
                    }
                    ++numBundlesReadBack;
                    block.base.type = HDTN_MSGTYPE_EGRESS;
                    block.flowId = flow;
                    egressSock->send(zmq::const_buffer(&block, sizeof(hdtn::BlockHdr)), zmq::send_flags::none);// 0 ZMQ_MORE
                    egressSock->send(zmq::const_buffer(bundleReadBack.data(), bytesToReadFromDisk), zmq::send_flags::none);
            }


    }



    //gettimeofday(&tv, NULL);
    //double end = (tv.tv_sec + (tv.tv_usec / 1000000.0));
    std::cout << "numBundlesReadBack = " << numBundlesReadBack << std::endl;
    //workerStats.flow.read_rate = ((totalReturned * 8.0) / (1024.0 * 1024)) / (end - start);
    //workerStats.flow.read_ts = end - start;
    //std::cout << "Total bytes returned: " << totalReturned << ", Mbps released: " << workerStats.flow.read_rate << " in " << workerStats.flow.read_ts << " sec" << std::endl;
    //hdtn::flow_stats stats = storeFlow.stats();
    //workerStats.flow.disk_rbytes=stats.disk_rbytes;
    //workerStats.flow.disk_rcount=stats.disk_rcount;
    //std::cout << "[storage-worker] " <<  stats.disk_wcount << " w count " << stats.disk_wbytes << " w bytes " << stats.disk_rcount << " r count " << stats.disk_rbytes << " r bytes \n";
}
*/
//return number of bytes to read for specified links
static uint64_t PeekOne(const std::vector<boost::uint64_t> & availableDestLinks, BundleStorageManagerMT & bsm) {
    BundleStorageManagerSession_ReadFromDisk  sessionRead;
    const boost::uint64_t bytesToReadFromDisk = bsm.PopTop(sessionRead, availableDestLinks);
    if (bytesToReadFromDisk == 0) { //no more of these links to read
        return 0; //no bytes to read
    }

    //this link has a bundle in the fifo
    bsm.ReturnTop(sessionRead);
    return bytesToReadFromDisk;
    
}

static boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk> ReleaseOne_NoBlock(const std::vector<boost::uint64_t> & availableDestLinks, zmq::socket_t *egressSock, BundleStorageManagerMT & bsm, const uint64_t maxBundleSizeToRead) {
    
    //std::cout << "reading\n";
    boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk> sessionReadPtr = boost::make_shared<BundleStorageManagerSession_ReadFromDisk>();
    BundleStorageManagerSession_ReadFromDisk & sessionRead = *sessionReadPtr;
    const boost::uint64_t bytesToReadFromDisk = bsm.PopTop(sessionRead, availableDestLinks);
    //std::cout << "bytesToReadFromDisk " << bytesToReadFromDisk << "\n";
    if (bytesToReadFromDisk == 0) { //no more of these links to read
        return boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk>(); //null
    }

    //this link has a bundle in the fifo
        

    //IF YOU DECIDE YOU DON'T WANT TO READ THE BUNDLE AFTER PEEKING AT IT (MAYBE IT'S TOO BIG RIGHT NOW)
    if (bytesToReadFromDisk > maxBundleSizeToRead) {
        std::cerr << "error: bundle to read from disk is too large right now" << std::endl;
        bsm.ReturnTop(sessionRead);
        return boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk>(); //null
        //bytesToReadFromDisk = bsm.PopTop(sessionRead, availableDestLinks); //get it back
    }
        
    zmq::message_t zmqMsg(bytesToReadFromDisk);
    boost::uint8_t * bundleReadBack = (uint8_t*)zmqMsg.data();


    const std::size_t numSegmentsToRead = sessionRead.chainInfo.second.size();
    std::size_t totalBytesRead = 0;
    for (std::size_t i = 0; i < numSegmentsToRead; ++i) {
        totalBytesRead += bsm.TopSegment(sessionRead, &bundleReadBack[i*BUNDLE_STORAGE_PER_SEGMENT_SIZE]);
    }
    //std::cout << "totalBytesRead " << totalBytesRead << "\n";
    if (totalBytesRead != bytesToReadFromDisk) {
        std::cout << "error: totalBytesRead != bytesToReadFromDisk\n";
        return boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk>(); //null
    }


    hdtn::BlockHdr block;
    memset(&block, 0, sizeof(hdtn::BlockHdr));
    block.base.type = HDTN_MSGTYPE_EGRESS;
    block.flowId = static_cast<uint32_t>(sessionRead.destLinkId);
    //get the first logical segment id for the bundle unique id
    {
        const chain_info_t & chainInfo = sessionRead.chainInfo;
        const segment_id_chain_vec_t & segmentIdChainVec = chainInfo.second;
        const segment_id_t segmentId = segmentIdChainVec[0];
        block.zframe = segmentId;
    }
    if (!egressSock->send(zmq::const_buffer(&block, sizeof(hdtn::BlockHdr)), zmq::send_flags::sndmore | zmq::send_flags::dontwait)) {
        std::cout << "error: zmq could not send" << std::endl;
        bsm.ReturnTop(sessionRead);
        return boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk>(); //null
    }
    if (!egressSock->send(std::move(zmqMsg), zmq::send_flags::dontwait)) {
        std::cout << "error: zmq could not send bundle" << std::endl;
        bsm.ReturnTop(sessionRead);
        return boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk>(); //null
    }
    /*
    //if you're happy with the bundle data you read back, then officially remove it from the disk
    if (deleteFromDiskNow) {
        bool successRemoveBundle = bsm.RemoveReadBundleFromDisk(sessionRead);
        if (!successRemoveBundle) {
            std::cout << "error freeing bundle from disk\n";
            return false;
        }
    }
        */
        
        
    return sessionReadPtr;
    

}

void hdtn::ZmqStorageInterface::ThreadFunc() {
    zmq::message_t rhdr;
    zmq::message_t rmsg;
    std::cout << "[storage-worker] Worker thread starting up." << std::endl;

    zmq::socket_t workerSock(*m_zmqContextPtr, zmq::socket_type::pair);
    workerSock.connect(m_queue.c_str());
    zmq::socket_t egressSock(*m_zmqContextPtr, zmq::socket_type::push);
    egressSock.connect(HDTN_CONNECTING_STORAGE_TO_BOUND_EGRESS_PATH); // egress should bind
    zmq::socket_t fromEgressSock(*m_zmqContextPtr, zmq::socket_type::pull);
    fromEgressSock.connect(HDTN_BOUND_EGRESS_TO_CONNECTING_STORAGE_PATH); // egress should bind
    zmq::socket_t toIngressSock(*m_zmqContextPtr, zmq::socket_type::push);
    toIngressSock.connect(HDTN_CONNECTING_STORAGE_TO_BOUND_INGRESS_PATH);

    zmq::pollitem_t pollItems[2] = {
        {fromEgressSock.handle(), 0, ZMQ_POLLIN, 0},
        {workerSock.handle(), 0, ZMQ_POLLIN, 0}
    };

    // Use a form of receive that times out so we can terminate cleanly.
    static const int timeout = 250;  // milliseconds
    workerSock.set(zmq::sockopt::rcvtimeo, timeout);
    fromEgressSock.set(zmq::sockopt::rcvtimeo, timeout);

    std::cout << "[ZmqStorageInterface] Initializing BundleStorageManagerMT ... " << std::endl;
    CommonHdr startupNotify = {
        HDTN_MSGTYPE_IOK,
        0};
    BundleStorageManagerMT bsm(m_storageConfigFilePath);
    bsm.Start();
    //if (!m_storeFlow.init(m_root)) {
    //    startupNotify.type = HDTN_MSGTYPE_IABORT;
    //    workerSock.send(&startupNotify, sizeof(common_hdr));
    //    return;
    //}
    workerSock.send(zmq::const_buffer(&startupNotify, sizeof(CommonHdr)), zmq::send_flags::none);
    std::cout << "[ZmqStorageInterface] Notified parent that startup is complete." << std::endl;

    typedef boost::shared_ptr<BundleStorageManagerSession_ReadFromDisk> session_read_ptr;
    typedef std::map<segment_id_t, session_read_ptr> segid_session_map_t;
    typedef std::map<uint64_t, segid_session_map_t> flowid_opensessions_map_t;
    
    m_totalBundlesErasedFromStorage = 0;
    m_totalBundlesSentToEgressFromStorage = 0;
    std::size_t totalEventsAllLinksClogged = 0;
    std::size_t totalEventsNoDataInStorageForAvailableLinks = 0;
    std::size_t totalEventsDataInStorageForCloggedLinks = 0;

    std::set<uint64_t> availableDestLinksSet;
    flowid_opensessions_map_t flowIdToOpenSessionsMap;

    static const long DEFAULT_BIG_TIMEOUT_POLL = 250;
    long timeoutPoll = DEFAULT_BIG_TIMEOUT_POLL; //0 => no blocking
    while (m_running) {        
        if (zmq::poll(pollItems, 2, timeoutPoll) > 0) {            
            if (pollItems[0].revents & ZMQ_POLLIN) { //from egress sock
                if (!fromEgressSock.recv(rhdr, zmq::recv_flags::none)) {
                    continue;
                }
                if (rhdr.size() < sizeof(hdtn::CommonHdr)) {
                    std::cerr << "[storage-worker] Invalid message format - header size too small (" << rhdr.size() << ")" << std::endl;
                    continue;
                }
                hdtn::CommonHdr commonHdr;
                memcpy(&commonHdr, rhdr.data(), sizeof(hdtn::CommonHdr));
                const uint16_t type = commonHdr.type;
                if (type == HDTN_MSGTYPE_EGRESS_TRANSFERRED_CUSTODY) {
                    if (rhdr.size() != sizeof(hdtn::BlockHdr)) {
                        std::cerr << "[storage-worker] Invalid message format - header size mismatch HDTN_MSGTYPE_EGRESS_TRANSFERRED_CUSTODY (" << rhdr.size() << ")" << std::endl;
                    }
                    else {
                        hdtn::BlockHdr blockHdr;
                        memcpy(&blockHdr, rhdr.data(), sizeof(hdtn::BlockHdr));
                        segid_session_map_t & segIdToSessionMap = flowIdToOpenSessionsMap[blockHdr.flowId];
                        segid_session_map_t::iterator it = segIdToSessionMap.find(blockHdr.zframe);
                        if (it != segIdToSessionMap.end()) {                            
                            bool successRemoveBundle = bsm.RemoveReadBundleFromDisk(*(it->second));
                            if (!successRemoveBundle) {
                                std::cout << "error freeing bundle from disk\n";
                            }
                            segIdToSessionMap.erase(it);
                            //std::cout << "remove flow " << blockHdr.flowId << " sz " << flowIdToOpenSessionsMap[blockHdr.flowId].size() << std::endl;
                            ++m_totalBundlesErasedFromStorage;
                        }
                    }
                }
            }
            if (pollItems[1].revents & ZMQ_POLLIN) { //worker inproc
                if (!workerSock.recv(rhdr, zmq::recv_flags::none)) {
                    continue;
                }
                if (rhdr.size() < sizeof(hdtn::CommonHdr)) {
                    std::cerr << "[storage-worker] Invalid message format - header size too small (" << rhdr.size() << ")" << std::endl;
                    continue;
                }
                hdtn::CommonHdr commonHdr;
                memcpy(&commonHdr, rhdr.data(), sizeof(hdtn::CommonHdr));
                const uint16_t type = commonHdr.type;
                if(type == HDTN_MSGTYPE_STORE) {
                    for (unsigned int attempt = 0; attempt < 10; ++attempt) {
                        if (workerSock.recv(rmsg, zmq::recv_flags::none)) {
                            break;
                        }
                        else {
                            std::cerr << "error: timeout in ZmqStorageInterface::ThreadFunc() at workerSock.recv(rmsg)" << std::endl;
                            if (attempt == 9) {
                                m_running = false;
                            }
                        }
                    }

                    hdtn::BlockHdr *block = (hdtn::BlockHdr *)rhdr.data();
                    if (rhdr.size() != sizeof(hdtn::BlockHdr)) {
                        std::cerr << "[storage-worker] Invalid message format - header size mismatch (" << rhdr.size() << ")" << std::endl;
                    }
                    if (rmsg.size() > 100) { //need to fix problem of writing message header as bundles
                        Write(block, &rmsg, bsm);
                        //send ack message by echoing back the block
                        if (!toIngressSock.send(zmq::const_buffer(block, sizeof(hdtn::BlockHdr)), zmq::send_flags::dontwait)) {
                            std::cout << "error: zmq could not send ingress an ack from storage" << std::endl;
                        }
                    }
                }
                else if(type == HDTN_MSGTYPE_IRELSTART) {
                    hdtn::IreleaseStartHdr iReleaseStartHdr;
                    memcpy(&iReleaseStartHdr, rhdr.data(), sizeof(hdtn::IreleaseStartHdr));
                    //ReleaseData(iReleaseStartHdr.flowId, iReleaseStartHdr.rate, iReleaseStartHdr.duration, &egressSock, bsm);
                    const uint64_t flowId = iReleaseStartHdr.flowId;
                    availableDestLinksSet.insert(flowId);
                    std::cout << "flow ID " << flowId << " will be released from storage" << std::endl;
                    //availableDestLinksVec.clear();
                    std::string strVals = "[";
                    for (std::set<uint64_t>::const_iterator it = availableDestLinksSet.cbegin(); it != availableDestLinksSet.cend(); ++it) {
                        //availableDestLinksVec.push_back(*it);
                        strVals += boost::lexical_cast<std::string>(*it) + ", ";
                    }
                    strVals += "]";
                    std::cout << "Currently Releasing Flow Ids: " << strVals << std::endl;
                    //storageStillHasData = true;
                }
                else if(type == HDTN_MSGTYPE_IRELSTOP) {
                    hdtn::IreleaseStopHdr iReleaseStoptHdr;
                    memcpy(&iReleaseStoptHdr, rhdr.data(), sizeof(hdtn::IreleaseStopHdr));
                    const uint64_t flowId = iReleaseStoptHdr.flowId;
                    std::cout << "flow ID " << flowId << " will STOP BEING released from storage" << std::endl;
                    availableDestLinksSet.erase(flowId);
                    //availableDestLinksVec.clear();
                    std::string strVals = "[";
                    for (std::set<uint64_t>::const_iterator it = availableDestLinksSet.cbegin(); it != availableDestLinksSet.cend(); ++it) {
                        //availableDestLinksVec.push_back(*it);
                        strVals += boost::lexical_cast<std::string>(*it) + ", ";
                    }
                    strVals += "]";
                    std::cout << "Currently Releasing Flow Ids: " << strVals << std::endl;
                }
                
            }            
        }
        
        //Send and maintain a maximum of 5 unacked bundles (per flow id) to Egress.
        //When a bundle is acked from egress using the head segment Id, the bundle is deleted from disk and a new bundle can be sent.
        static const uint64_t maxBundleSizeToRead = 65535 * 10;
        if (availableDestLinksSet.empty()) {
            timeoutPoll = DEFAULT_BIG_TIMEOUT_POLL;
        }
        else {
            std::vector<uint64_t> availableDestLinksNotCloggedVec;
            std::vector<uint64_t> availableDestLinksCloggedVec;
            for (std::set<uint64_t>::const_iterator it = availableDestLinksSet.cbegin(); it != availableDestLinksSet.cend(); ++it) {
                const uint64_t flowId = *it;
                //std::cout << "flow " << flowId << " sz " << flowIdToOpenSessionsMap[flowId].size() << std::endl;
                if (flowIdToOpenSessionsMap[flowId].size() < 5) {
                    availableDestLinksNotCloggedVec.push_back(flowId);
                }
                else {
                    availableDestLinksCloggedVec.push_back(flowId);
                }
            }
            if (availableDestLinksNotCloggedVec.size() > 0) {
                if (session_read_ptr sessionPtr = ReleaseOne_NoBlock(availableDestLinksNotCloggedVec, &egressSock, bsm, maxBundleSizeToRead)) { //not null (successfully sent to egress)
                    const uint64_t flowId = sessionPtr->destLinkId;
                    //get the first logical segment id for the map key
                    const chain_info_t & chainInfo = sessionPtr->chainInfo;
                    const segment_id_chain_vec_t & segmentIdChainVec = chainInfo.second;
                    const segment_id_t segmentId = segmentIdChainVec[0];
                    flowIdToOpenSessionsMap[flowId][segmentId] = sessionPtr;
                    //std::cout << "add flow " << flowId << " sz " << flowIdToOpenSessionsMap[flowId].size() << std::endl;
                    timeoutPoll = 0; //no timeout as we need to keep feeding to egress
                    ++m_totalBundlesSentToEgressFromStorage;
                }
                else if (PeekOne(availableDestLinksCloggedVec, bsm) > 0) { //data available in storage for clogged links
                    timeoutPoll = 1; //shortest timeout 1ms as we wait for acks
                    ++totalEventsDataInStorageForCloggedLinks;
                }
                else { //no data in storage for any available links
                    timeoutPoll = DEFAULT_BIG_TIMEOUT_POLL;
                    ++totalEventsNoDataInStorageForAvailableLinks;
                }
            }
            else { //all links clogged up and need acks
                timeoutPoll = 1; //shortest timeout 1ms as we wait for acks
                ++totalEventsAllLinksClogged;
            }
        }
        
        //}
        

        /*hdtn::flow_stats stats = m_storeFlow.stats();
        m_workerStats.flow.disk_wbytes = stats.disk_wbytes;
        m_workerStats.flow.disk_wcount = stats.disk_wcount;
        m_workerStats.flow.disk_rbytes = stats.disk_rbytes;
        m_workerStats.flow.disk_rcount = stats.disk_rcount;*/
        
    }
    std::cout << "totalEventsAllLinksClogged: " << totalEventsAllLinksClogged << std::endl;
    std::cout << "totalEventsNoDataInStorageForAvailableLinks: " << totalEventsNoDataInStorageForAvailableLinks << std::endl;
    std::cout << "totalEventsDataInStorageForCloggedLinks: " << totalEventsDataInStorageForCloggedLinks << std::endl;
}




void hdtn::ZmqStorageInterface::launch() {
    if (!m_running) {
        m_running = true;
        std::cout << "[ZmqStorageInterface] Launching worker thread ..." << std::endl;
        m_threadPtr = boost::make_shared<boost::thread>(
                boost::bind(&ZmqStorageInterface::ThreadFunc, this)); //create and start the worker thread
    }
}
