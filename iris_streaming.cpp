// Copyright (c) 2017 Skylark Wireless LLC
// SPDX-License-Identifier: BSD-3-Clause

//-------------------------------------------------------------
//-- Streaming over IP/UDP implementation
//-------------------------------------------------------------

#include <SoapySDR/Formats.hpp>
#include <SoapySDR/Logger.hpp>
#include "iris_device.hpp"
#include "SoapySocketDefs.hpp"
#include <SoapyRPCSocket.hpp>
#include <SoapyURLUtils.hpp>
#include <ThreadPrioHelper.hpp>
#include "iris_formats.hpp"
#include "twbw_helper.h"
#include <iostream>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <queue>
#include <future>
#include <condition_variable>

#define MAX_TX_STATUS_DEPTH 64

#define RX_SOCKET_BUFFER_BYTES 50*1024*1024 //arbitrary and large PC buffer size

#define ETHERNET_MTU 1500 //L2 MTU without the 14-byte eth header
#define ROUTE_HDR_SIZE 16 //128-bit transfer for routing header
#define PADDED_ETH_HDR_SIZE 16 //14 bytes + 2 bytes padding (holds size in bytes)
#define IPv6_UDP_SIZE (40 + 8) //40 bytes of IPv6 + 8 bytes of UDP header
#define TWBW_HDR_SIZE (sizeof(uint64_t)*4) //4 transfers at 64-bits width

void sockAddrInterfaceLookup(const sockaddr *sa, std::string &ethName, unsigned long long &mac64, int &scopeId);

/*******************************************************************
 * Thread prio is a good idea with sockets
 ******************************************************************/
struct ThreadPrioInit
{
    ThreadPrioInit(const double prio, const char *what)
    {
        auto result = setThreadPrio(prio);
        if (result.empty()) return;
        SoapySDR::logf(SOAPY_SDR_WARNING, "Could not set thread priority %.1f in %s: %s", prio, what, result.c_str());
    }
};

#define THREAD_PRIO(prio) static thread_local ThreadPrioInit __prio(prio, __FUNCTION__)

/*******************************************************************
 * Stream data
 ******************************************************************/
struct StreamStatusEntry
{
    StreamStatusEntry(const int ret = 0):
        ret(ret), flags(0), timeTicks(0){}
    int ret;
    int flags;
    long long timeTicks;
};

struct IrisLocalStream
{
    SoapySDR::Stream *remoteStream;
    SoapyRPCSocket sock;
    int direction;
    StreamFormat format; //!< requested stream format
    char buff[2048];

    size_t bytesPerElement;
    size_t numHostChannels;
    size_t hostFormatSize;
    size_t mtuElements;

    //read channel partial
    size_t readHandle;
    size_t readElemsLeft;
    size_t readOffset;

    //burst tracking
    long long tickCount;
    bool inBurst;
    bool burstUsesTime;
    long long packetCount;

    //tx sequence tracking
    std::atomic<uint16_t> nextSeqSend;
    std::atomic<uint16_t> lastSeqRecv;
    uint16_t windowSize;
    std::mutex mutex;
    std::condition_variable cond;
    std::thread thread;
    std::atomic<bool> running;
    std::queue<StreamStatusEntry> queue;
    void statusLoop(void);

    //async activate support
    std::shared_future<int> async;
    bool syncActivate;
};

/*******************************************************************
 * Stream config
 ******************************************************************/
std::vector<std::string> SoapyIrisLocal::getStreamFormats(const int /*direction*/, const size_t /*channel*/) const
{
    //formats supported by local read/write stream conversions
    return {SOAPY_SDR_CF32, SOAPY_SDR_CS16, SOAPY_SDR_CS12, SOAPY_SDR_CS8};
}

std::string SoapyIrisLocal::getNativeStreamFormat(const int /*direction*/, const size_t /*channel*/, double &fullScale) const
{
    fullScale = (1 << 11)-1;
    return SOAPY_SDR_CS12;
}

SoapySDR::ArgInfoList SoapyIrisLocal::getStreamArgsInfo(const int direction, const size_t channel) const
{
    SoapySDR::ArgInfoList infos;

    {
        SoapySDR::ArgInfo info;
        info.key = "WIRE";
        info.name = "Stream wire format";
        info.type = SoapySDR::ArgInfo::STRING;
        info.value = "";
        info.description = "Specify a specific wire format for the stream.";
        info.options = {SOAPY_SDR_CS16, SOAPY_SDR_CS12, SOAPY_SDR_CS8};
        info.optionNames = {"Complex int16", "Complex int12", "Complex int8"};
        infos.push_back(info);
    }

    {
        SoapySDR::ArgInfo info;
        info.key = "MTU";
        info.name = "Ethernet MTU in bytes";
        info.type = SoapySDR::ArgInfo::INT;
        info.value = std::to_string(ETHERNET_MTU);
        info.description = "Configure a larger MTU for jumbo packets.";
        infos.push_back(info);
    }

    //use remote infos that come from the driver itself
    //and filter out remote: from soapy remote (not applicable)
    for (const auto &info : _remote->getStreamArgsInfo(direction, channel))
    {
        if (info.key.find("remote:") == std::string::npos) infos.push_back(info);
    }

    return infos;
}

SoapySDR::Stream *SoapyIrisLocal::setupStream(
    const int direction,
    const std::string &format,
    const std::vector<size_t> &_channels,
    const SoapySDR::Kwargs &_args)
{
    std::unique_ptr<IrisLocalStream> data(new IrisLocalStream);
    std::vector<size_t> channels(_channels);
    if (channels.empty()) channels.push_back(0);

    //format configuration settings
    std::string remoteFormat;
    const auto &requestedWireFormat = _args.count("WIRE")?_args.at("WIRE"):"";
    resolveFormats(channels.size(), format, requestedWireFormat, data->format, remoteFormat, data->bytesPerElement);

    //query remote iris endpoint configuration
    auto remoteIPv6Addr       = _remote->readSetting("ETH0_IPv6_ADDR");
    const auto remoteServPort = _remote->readSetting("UDP_SERVICE_PORT");
    const auto rfTxFifoDepth = std::stoul(_remote->readSetting("RF_TX_FIFO_DEPTH"));
    if (remoteIPv6Addr.empty()) throw std::runtime_error("Iris::setupStream: Failed to query Iris IPv6 address");
    if (remoteServPort.empty()) throw std::runtime_error("Iris::setupStream: Failed to query Iris UDP service port");

    //ipv6 mac and scope for the remote socket
    std::string ethName;
    unsigned long long localMac64(0);
    int localScopeId(-1);
    {
        SoapyRPCSocket junkSock; junkSock.connect(_remoteURL);
        SoapyURL url(junkSock.getsockname());
        SockAddrData addr; auto err = url.toSockAddr(addr);
        sockAddrInterfaceLookup(addr.addr(), ethName, localMac64, localScopeId);
        if (ethName.empty()) throw std::runtime_error("Iris::setupStream: Failed to determine ethernet device name for " + url.getNode());
        if (localMac64 == 0) throw std::runtime_error("Iris::setupStream: Failed to lookup network hardware address for " + ethName);
        if (localScopeId == -1) throw std::runtime_error("Iris::setupStream: Failed to discover the IPv6 scope ID\n"
                                                         "  (Does interface='" + ethName + "' have an IPv6 address)?");
        SoapySDR::logf(SOAPY_SDR_INFO, "Using local ethernet interface: %s", ethName.c_str());
    }

    //get the scope id to get the remote ipv6 address with the local scope id
    const auto percentPos = remoteIPv6Addr.find_last_of('%');
    if (percentPos != std::string::npos)
    {
        remoteIPv6Addr = remoteIPv6Addr.substr(0, percentPos+1) + std::to_string(localScopeId);
    }

    data->direction = direction;
    data->readHandle = ~0;
    data->readElemsLeft = 0;
    data->readOffset = 0;
    data->tickCount = 0;
    data->inBurst = false;
    data->burstUsesTime = false;
    data->packetCount = 0;
    const size_t mtu = _args.count("MTU")?std::stoul(_args.at("MTU")):ETHERNET_MTU;
    const size_t mtuPayloadBytes = mtu - IPv6_UDP_SIZE - TWBW_HDR_SIZE;
    data->mtuElements = mtuPayloadBytes/data->bytesPerElement;
    data->numHostChannels = channels.size();
    data->hostFormatSize = SoapySDR::formatToSize(format);
    data->nextSeqSend = 0;
    data->lastSeqRecv = 0;
    const auto txFifoDepthBytes = rfTxFifoDepth*16;
    //what we actually buffer in the stream fifo...
    const size_t mtuLayer2Bytes = IPv6_UDP_SIZE + TWBW_HDR_SIZE + data->mtuElements*data->bytesPerElement;
    const size_t mtuBufferedBytes = ROUTE_HDR_SIZE + PADDED_ETH_HDR_SIZE + mtuLayer2Bytes;
    data->windowSize = txFifoDepthBytes/mtuBufferedBytes;

    //true by default, async can be useful, but it might cause a race w/ trigger and activate
    data->syncActivate = true;
    if (_args.count("SYNC_ACTIVATE") != 0) data->syncActivate = _args.at("SYNC_ACTIVATE") == "true";

    const SoapyURL bindURL("udp", "::", "0");
    int ret = data->sock.bind(bindURL.toString());
    if (ret != 0) throw std::runtime_error("Iris::setupStream: Failed to bind to " + bindURL.toString() + ": " + data->sock.lastErrorMsg());
    const SoapyURL connectURL("udp", remoteIPv6Addr, remoteServPort);
    ret = data->sock.connect(connectURL.toString());
    if (ret != 0) throw std::runtime_error("Iris::setupStream: Failed to connect to " + connectURL.toString() + ": " + data->sock.lastErrorMsg());

    //lookup the local mac address to program the framer
    SoapyURL localEp(data->sock.getsockname());

    //pass arguments within the args to program the framer
    SoapySDR::Kwargs args(_args);
    args["iris:eth_dst"] = std::to_string(localMac64);
    args["iris:ip6_dst"] = localEp.getNode();
    args["iris:udp_dst"] = localEp.getService();
    args["iris:mtu"] = std::to_string(data->mtuElements);

    data->remoteStream = _remote->setupStream(direction, remoteFormat, channels, args);

    //if the rx stream was left running, stop it and drain the fifo
    if (direction == SOAPY_SDR_RX)
    {
        _remote->deactivateStream(data->remoteStream, 0, 0);
        while (data->sock.selectRecv(50000))
            data->sock.recv(data->buff, sizeof(data->buff));
    }

    if (direction == SOAPY_SDR_TX)
    {
        data->running = true;
        data->thread = std::thread(&IrisLocalStream::statusLoop, data.get());
    }

    //set tx socket buffer size to match the buffering in the iris
    //set rx buffering size to be arbitrarily large for socket buffer
    size_t buffSize = (direction == SOAPY_SDR_RX)?RX_SOCKET_BUFFER_BYTES:txFifoDepthBytes;
    ret = data->sock.setBuffSize(direction == SOAPY_SDR_RX, buffSize);
    if (ret == -1) SoapySDR::logf(SOAPY_SDR_WARNING,
        "Failed to resize socket buffer to %d kib: %s", buffSize/1024, data->sock.lastErrorMsg());
    else
    {
        const size_t actualSize = data->sock.getBuffSize(direction == SOAPY_SDR_RX);
        if (actualSize < buffSize) SoapySDR::logf(SOAPY_SDR_WARNING,
            "Failed to resize socket buffer to %d kib, actual %d kib", buffSize/1024, actualSize/1024);
    }

    return (SoapySDR::Stream *)data.release();
}

void SoapyIrisLocal::closeStream(SoapySDR::Stream *stream)
{
    auto data = (IrisLocalStream *)stream;
    if (data->direction == SOAPY_SDR_TX)
    {
        data->running = false;
        data->thread.join();
    }
    _remote->closeStream(data->remoteStream);
    data->sock.close();
    delete data;
}

size_t SoapyIrisLocal::getStreamMTU(SoapySDR::Stream *stream) const
{
    auto data = (IrisLocalStream *)stream;
    return data->mtuElements;
}

int SoapyIrisLocal::activateStream(
    SoapySDR::Stream *stream,
    const int flags,
    const long long timeNs,
    const size_t numElems)
{
    auto data = (IrisLocalStream *)stream;
    if (data->syncActivate) return _remote->activateStream(data->remoteStream, flags, timeNs, numElems);
    data->async = std::async(std::launch::async, &SoapySDR::Device::activateStream, _remote, data->remoteStream, flags, timeNs, numElems);
    return 0;
}

int SoapyIrisLocal::deactivateStream(
    SoapySDR::Stream *stream,
    const int flags,
    const long long timeNs)
{
    auto data = (IrisLocalStream *)stream;
    if (data->syncActivate) return _remote->deactivateStream(data->remoteStream, flags, timeNs);
    data->async = std::async(std::launch::async, &SoapySDR::Device::deactivateStream, _remote, data->remoteStream, flags, timeNs);
    return 0;
}

int SoapyIrisLocal::readStream(
    SoapySDR::Stream *stream,
    void * const *buffs,
    const size_t numElems,
    int &flags,
    long long &timeNs,
    const long timeoutUs)
{
    auto data = (IrisLocalStream *)stream;

    const bool onePkt = (flags & SOAPY_SDR_ONE_PACKET) != 0;
    bool eop = false;
    flags = 0; //clear

    size_t numRecv = 0;
    do
    {
        int flags_i(0);
        long long timeNs_i(0);

        //direct buffer call, there is no remainder left
        if (data->readElemsLeft == 0)
        {
            const void *buff[1];
            int ret = this->acquireReadBuffer(stream, data->readHandle, buff, flags_i, timeNs_i, timeoutUs);
            //timeout after some successful sends, leave loop
            if (ret == SOAPY_SDR_TIMEOUT and numRecv != 0) break;
            if (ret < 0) return ret;
            data->readOffset = size_t(buff[0]);
            data->readElemsLeft = size_t(ret);
        }

        //always put the time in from the internally tracked tick rate
        //we do this for both new buffer handles which have good ticks
        //and for remainder buffers which get the tick interpolation
        flags_i |= SOAPY_SDR_HAS_TIME;
        timeNs_i = this->ticksToTimeNs(data->tickCount, _adcClockRate);

        //convert the buffer
        void *buffsOffset[2];
        const size_t bytesOffset = numRecv*data->hostFormatSize;
        for (size_t i = 0; i < data->numHostChannels; i++) buffsOffset[i] = reinterpret_cast<void *>(size_t(buffs[i]) + bytesOffset);
        size_t numSamples = std::min(numElems-numRecv, data->readElemsLeft);
        convertToHost(data->format, (const void *)data->readOffset, buffsOffset, numSamples);

        //next internal tick count
        data->tickCount += 2*numSamples;

        //used entire buffer, release
        if ((data->readElemsLeft -= numSamples) == 0)
        {
            this->releaseReadBuffer(stream, data->readHandle);
        }

        //increment pointers for next
        else
        {
            data->readOffset += numSamples*data->bytesPerElement;
        }

        eop = onePkt or (flags_i & (SOAPY_SDR_END_BURST | SOAPY_SDR_ONE_PACKET)) != 0;
        flags |= flags_i; //total set of any burst or time flags
        if (numRecv == 0) timeNs = timeNs_i; //save first time

        numRecv += numSamples;
    } while (numRecv != numElems and not eop);

    //ended with fragments?
    if (data->readElemsLeft != 0) flags |= SOAPY_SDR_MORE_FRAGMENTS;

    return numRecv;
}

int SoapyIrisLocal::writeStream(
    SoapySDR::Stream *stream,
    const void * const *buffs,
    const size_t numElems,
    int &flags,
    const long long timeNs,
    const long timeoutUs)
{
    auto data = (IrisLocalStream *)stream;

    const bool onePkt = (flags & SOAPY_SDR_ONE_PACKET) != 0;

    size_t numSent = 0;
    do
    {
        //acquire a new handle
        size_t handle;
        void *buff[1];
        int ret = this->acquireWriteBuffer(stream, handle, buff, timeoutUs);

        //timeout after some successful sends, leave loop
        if (ret == SOAPY_SDR_TIMEOUT and numSent != 0) break;

        //return error if present
        if (ret < 0) return ret;

        //only end burst if the last sample can be released
        const size_t numLeft = numElems-numSent;
        const size_t numSamples = std::min<size_t>(ret, numLeft);
        int flags_i = (numSent+numSamples == numElems)?flags:(flags & ~(SOAPY_SDR_END_BURST));

        //convert the samples
        const void *buffsOffset[2];
        const size_t bytesOffset = numSent*data->hostFormatSize;
        for (size_t i = 0; i < data->numHostChannels; i++) buffsOffset[i] = reinterpret_cast<const void *>(size_t(buffs[i]) + bytesOffset);
        convertToWire(data->format, buffsOffset, buff[0], numSamples);

        //release the buffer to send the samples
        this->releaseWriteBuffer(stream, handle, numSamples, flags_i, timeNs);
        flags &= ~(SOAPY_SDR_HAS_TIME); //only valid on the first release
        numSent += numSamples;

    } while (numSent != numElems and not onePkt);

    return numSent;
}

void IrisLocalStream::statusLoop(void)
{
    THREAD_PRIO(0.7);
    while (running)
    {
        if (not this->sock.selectRecv(100000)) continue;

        uint32_t buff[16];
        int ret = this->sock.recv(buff, sizeof(buff));
        if (ret < 0) //socket error, end loop
        {
            {
                std::lock_guard<std::mutex> lock(this->mutex);
                this->queue.emplace(SOAPY_SDR_STREAM_ERROR);
            }
            this->cond.notify_all();
            return;
        }

        StreamStatusEntry entry;
        bool underflow;
        int idTag = 0;
        bool hasTime;
        bool timeError;
        bool burstEnd;
        bool hasSequence;
        unsigned short sequence;
        bool seqError;
        twbw_deframer_stat_unpacker(
            buff,
            sizeof(buff),
            underflow,
            idTag,
            hasTime,
            entry.timeTicks,
            timeError,
            burstEnd,
            hasSequence,
            sequence,
            seqError);

        //every status message contains a sequence
        //hasSequence just tells us it was a requested event
        this->lastSeqRecv = sequence;

        //error indicators
        if (hasTime) entry.flags |= SOAPY_SDR_HAS_TIME;
        if (burstEnd) entry.flags |= SOAPY_SDR_END_BURST;
        if (timeError) entry.ret = SOAPY_SDR_TIME_ERROR;
        if (underflow) entry.ret = SOAPY_SDR_UNDERFLOW;
        if (seqError) entry.ret = SOAPY_SDR_CORRUPTION;

        //enqueue status messages when its not sequence only
        if (!hasSequence)
        {
            if (underflow) std::cerr << "U" << std::flush;
            if (timeError) std::cerr << "T" << std::flush;
            if (seqError) std::cerr << "S" << std::flush;
            std::lock_guard<std::mutex> lock(this->mutex);
            //constrain max queue size (if user isnt reading stream status)
            if (this->queue.size() > MAX_TX_STATUS_DEPTH) this->queue.pop();
            this->queue.push(entry);
        }

        //notify any waiters for sequence or status message
        this->cond.notify_all();
    }
}

int SoapyIrisLocal::readStreamStatus(
    SoapySDR::Stream *stream,
    size_t &chanMask,
    int &flags,
    long long &timeNs,
    const long timeoutUs)
{
    auto data = (IrisLocalStream *)stream;
    if (data->direction == SOAPY_SDR_RX) return SOAPY_SDR_NOT_SUPPORTED;

    //wait for an entry to become available
    std::unique_lock<std::mutex> lock(data->mutex);
    if (not data->cond.wait_for(lock,
        std::chrono::microseconds(timeoutUs),
        [data]{return not data->queue.empty();})) return SOAPY_SDR_TIMEOUT;

    //copy queue entry into the output fields
    auto entry = data->queue.front();
    data->queue.pop();
    chanMask = (data->numHostChannels == 2)?0x3:0x1;
    flags = entry.flags;
    timeNs = this->ticksToTimeNs(entry.timeTicks, _dacClockRate);
    return entry.ret;
}

size_t SoapyIrisLocal::getNumDirectAccessBuffers(SoapySDR::Stream *)
{
    return 1; //single local buffer
}

int SoapyIrisLocal::getDirectAccessBufferAddrs(SoapySDR::Stream *stream, const size_t /*handle*/, void **buffs)
{
    auto data = (IrisLocalStream *)stream;
    buffs[0] = data->buff + TWBW_HDR_SIZE;
    return 0;
}

int SoapyIrisLocal::acquireReadBuffer(
    SoapySDR::Stream *stream,
    size_t &handle,
    const void **buffs,
    int &flags,
    long long &timeNs,
    const long timeoutUs)
{
    THREAD_PRIO(1.0);
    auto data = (IrisLocalStream *)stream;

    if (not data->sock.selectRecv(timeoutUs)) return SOAPY_SDR_TIMEOUT;
    handle = 0; //always 0, its just one buffer
    this->getDirectAccessBufferAddrs(stream, handle, (void**)buffs);

    int ret = data->sock.recv(data->buff, sizeof(data->buff));
    if (ret < 0) return SOAPY_SDR_STREAM_ERROR;

    size_t numSamps;
    bool overflow;
    int idTag;
    bool hasTime;
    long long timeTicks;
    bool timeError;
    bool isBurst;
    bool isTrigger;
    bool burstEnd;
    twbw_framer_data_unpacker(
        data->buff,
        size_t(ret),
        sizeof(uint64_t),
        data->bytesPerElement,
        buffs[0],
        numSamps,
        overflow,
        idTag,
        hasTime,
        timeTicks,
        timeError,
        isBurst,
        isTrigger,
        burstEnd);
    //std::cout << "numSamps " << numSamps << std::endl;
    //std::cout << "burstEnd " << burstEnd << std::endl;

    flags = 0;
    ret = 0;

    //detect gaps in a burst due to drops
    if (data->inBurst && data->tickCount != timeTicks)
    {
        flags |= SOAPY_SDR_END_ABRUPT;
        std::cerr << "D" << std::flush;
        //std::cout << "\nDBG overflow " << data->packetCount << "\n\t"
        //    << "expected: " << data->tickCount << ", but got " << timeTicks << std::endl;
    }

    //gather time even if its not valid
    timeNs = this->ticksToTimeNs(timeTicks, _adcClockRate);
    data->tickCount = timeTicks;

    //error indicators
    if (overflow) flags |= SOAPY_SDR_END_ABRUPT;
    /*if (hasTime)*/ flags |= SOAPY_SDR_HAS_TIME; //always has time
    if (burstEnd) flags |= SOAPY_SDR_END_BURST;
    if (isTrigger) flags |= SOAPY_SDR_WAIT_TRIGGER;

    //a bad time was specified in the command packet
    else if (timeError)
    {
        std::cerr << "L" << std::flush;
        ret = SOAPY_SDR_TIME_ERROR;
    }

    //otherwise the error was an overflow
    else if (overflow)
    {
        std::cerr << "O" << std::flush;
        ret = SOAPY_SDR_OVERFLOW;
    }

    //restart streaming when error in continuous mode
    if (ret != 0 and not isBurst)
    {
        //not implemented (and it probably wont backup anyway)
    }

    //release on error
    if (ret != 0)
    {
        releaseReadBuffer(stream, handle);
        return ret;
    }

    data->inBurst = !burstEnd;
    data->packetCount++;
    return numSamps;
}

void SoapyIrisLocal::releaseReadBuffer(SoapySDR::Stream *, const size_t)
{
    return; //nothing to do, buffer is reused, no ring present at this level
}

int SoapyIrisLocal::acquireWriteBuffer(
    SoapySDR::Stream *stream,
    size_t &handle,
    void **buffs,
    const long timeoutUs)
{
    THREAD_PRIO(1.0);
    auto data = (IrisLocalStream *)stream;

    //ran out of sequences, wait for response
    auto ready = [data]{return uint16_t(data->nextSeqSend-data->lastSeqRecv) < data->windowSize;};
    if (not ready()) //first check without locking, we only lock when backing up completely
    {
        std::unique_lock<std::mutex> lock(data->mutex);
        if (not data->cond.wait_for(lock, std::chrono::microseconds(timeoutUs), ready)) return SOAPY_SDR_TIMEOUT;
    }

    handle = 0; //always 0, its just one buffer
    this->getDirectAccessBufferAddrs(stream, handle, buffs);
    return data->mtuElements;
}

void SoapyIrisLocal::releaseWriteBuffer(
    SoapySDR::Stream *stream,
    const size_t /*handle*/,
    const size_t numElems,
    int &flags,
    const long long timeNs)
{
    auto data = (IrisLocalStream *)stream;

    //pack the header
    void *payload;
    size_t len = 0;
    bool hasTime((flags & SOAPY_SDR_HAS_TIME) != 0);
    if (hasTime) data->tickCount = this->timeNsToTicks(timeNs, _dacClockRate);
    else if (data->inBurst and data->burstUsesTime) hasTime = true;
    const bool burstEnd((flags & SOAPY_SDR_END_BURST) != 0);
    const bool trigger((flags & SOAPY_SDR_WAIT_TRIGGER) != 0);

    //request sequence packets once in a while with this metric
    const bool seqRequest = (data->nextSeqSend)%(data->windowSize/8) == 0;

    twbw_deframer_data_packer(
        data->buff,
        len,
        sizeof(uint64_t),
        data->bytesPerElement,
        payload,
        numElems,
        0,
        hasTime,
        data->tickCount,
        burstEnd,
        trigger,
        seqRequest and not burstEnd, //burst end produces a status message anyway
        data->nextSeqSend++);

    int ret = data->sock.send(data->buff, len);
    if (ret != int(len)) SoapySDR::logf(SOAPY_SDR_ERROR,
        "releaseWriteBuffer() sock send(%d) failed: %d", int(len), ret);
    else
    {
        if (!data->inBurst) data->burstUsesTime = hasTime;
        data->inBurst = !burstEnd;
        data->packetCount++;
        data->tickCount += numElems*2;
    }
}
