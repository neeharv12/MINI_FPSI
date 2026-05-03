#include "helper/common.hpp"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include <future>
#include <thread>
#include <vector>
#include <cstdint>
#include <algorithm>

template<typename F>
static void parallelFor(std::uint64_t begin, std::uint64_t end, std::uint64_t threadCount, F&& fn)
{
    if (end <= begin)
        return;

    if (threadCount <= 1)
    {
        for (std::uint64_t i = begin; i < end; ++i) fn(i);
        return;
    }

    const std::uint64_t total = end - begin;
    const std::uint64_t tasks = std::min<std::uint64_t>(threadCount, total);
    const std::uint64_t block = (total + tasks - 1) / tasks;

    std::vector<std::future<void>> futs;
    futs.reserve(static_cast<size_t>(tasks));
    for (std::uint64_t t = 0; t < tasks; ++t)
    {
        const std::uint64_t s = begin + t * block;
        const std::uint64_t e = std::min<std::uint64_t>(end, s + block);
        if (s >= e) break;
        futs.emplace_back(std::async(std::launch::async, [s, e, &fn]() {
            for (std::uint64_t i = s; i < e; ++i) fn(i);
        }));
    }
    for (auto& f : futs) f.get();
}


#ifdef ENABLE_IKNP
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#endif

#ifdef ENABLE_SILENTOT
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#endif

#ifdef ENABLE_SOFTSPOKEN_OT
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#endif

template<typename OtReceiver>
static void runReceiver(
    OtReceiver&                             recver,
    const MINI::Options&                    opt,
    const std::vector<std::string>&         B,
    coproto::AsioSocket&                    sock)
{
    using namespace MINI;
    using osuCrypto::BitVector;

    std::array<block, 1> recvHdr;
    coproto::sync_wait(sock.recv(recvHdr));
    const u64 aCount = recvHdr[0].get<u64>(0);

    const u64 bCount = static_cast<u64>(B.size());
    const std::array<block, 1> sendHdr{ block(0, bCount) };
    coproto::sync_wait(sock.send(sendHdr));

    if (opt.verbose)
        std::cout << "[receiver] addr=" << opt.address
                  << " |A|=" << aCount << " |B|=" << bCount
                  << " ot=" << otSchemeName(opt.scheme) << "\n";

    const u64 totalPairs = aCount * bCount;

    auto prngOt = makePrngDomain(opt.seed, 0);
    const osuCrypto::AES aes1(osuCrypto::toBlock(0, 0));
    const osuCrypto::AES aes2(osuCrypto::toBlock(0, 1));

    std::vector<BitVector> cachedChoices(B.size());
    parallelFor(0, static_cast<std::uint64_t>(B.size()), static_cast<std::uint64_t>(opt.verbose ? 1 : opt.threads), [&](std::uint64_t i)
    {
        cachedChoices[static_cast<size_t>(i)] = buildChoices(B[static_cast<size_t>(i)], opt);
    });

    for (u64 chunkStart = 0; chunkStart < totalPairs; chunkStart += PAIRS_PER_CHUNK)
    {
        const u64 chunkPairs = std::min<u64>(PAIRS_PER_CHUNK, totalPairs - chunkStart);
        const u64 chunkOts   = chunkPairs * opt.n();

        if (opt.verbose)
            std::cout << "[receiver] chunk start=" << chunkStart
                      << " pairs=" << chunkPairs
                      << " ots=" << chunkOts << "\n";

        BitVector allChoices(chunkOts);

        parallelFor(0, static_cast<std::uint64_t>(chunkPairs), static_cast<std::uint64_t>(opt.verbose ? 1 : opt.threads), [&](std::uint64_t lp64)
        {
            const u64 lp = static_cast<u64>(lp64);
            const auto [_, bi]       = pairToIndices(chunkStart + lp, bCount);
            const BitVector& choices = cachedChoices[static_cast<size_t>(bi)];
            const u64 base           = lp * opt.n();
            for (u64 i = 0; i < opt.n(); ++i)
                allChoices[base + i] = choices[i];
        });

        osuCrypto::AlignedUnVector<block> recv(chunkOts);
        auto proto = recver.receiveChosen(
            allChoices,
            osuCrypto::span<block>(recv.data(), recv.size()),
            prngOt,
            static_cast<osuCrypto::Socket&>(sock));
        coproto::sync_wait(std::move(proto));

        std::vector<std::array<block, 2>> replies(static_cast<size_t>(chunkPairs));

        parallelFor(0, static_cast<std::uint64_t>(chunkPairs), static_cast<std::uint64_t>(opt.verbose ? 1 : opt.threads), [&](std::uint64_t lp64)
        {
            const u64 lp = static_cast<u64>(lp64);
            const auto [ai, bi]      = pairToIndices(chunkStart + lp, bCount);
            const BitVector& choices = cachedChoices[static_cast<size_t>(bi)];
            const u64 base           = lp * opt.n();

            if (opt.verbose)
            {
                std::cout << "[receiver] pair (a[" << ai << "], b[" << bi << "])"
                          << " b=" << B[static_cast<size_t>(bi)] << "\n";
            }

            std::uint64_t DeltaPrime = 0;
            for (u64 i = 0; i < opt.l; ++i)
                DeltaPrime = (DeltaPrime + recv[base + i].get<std::uint64_t>(0)) % opt.mod();

            BitVector Eval(kappa);
            for (u64 i = 0; i < kappa; ++i)
                Eval[i] = unpackBlockToBitVector(recv[base + opt.l + i], opt.mod())[DeltaPrime];

            const block hash1 = aes1.ecbEncBlock(packBitVectorToBlock(Eval));
            const block hash2 = aes2.ecbEncBlock(packBitVectorToBlock(Eval));

            BitVector output(kappa);
            for (u64 i = 0; i < opt.l; ++i)
                output[i] = choices[i];
            output ^= unpackBlockToBitVector(hash1, kappa);

            if (opt.verbose)
                std::cout << "[receiver]   DeltaPrime=" << DeltaPrime
                          << " output=" << output << "\n";

            replies[static_cast<size_t>(lp)] = { packBitVectorToBlock(output), hash2 };
        });

        coproto::sync_wait(sock.send(replies));
    }

    coproto::sync_wait(sock.flush());
    coproto::sync_wait(sock.close());
}

int main(int argc, char** argv)
{
    using namespace MINI;
    try
    {
        auto opt = parseArgs(argc, argv, "receiver");
        if (opt.b.empty()) throw std::runtime_error("Receiver requires --b B.txt");
        const auto B = loadBitstrings(opt.b, opt.l);

        AsioRuntime rt(opt.threads);
        coproto::AsioAcceptor acceptor(opt.address, rt.ioc);
        coproto::AsioSocket sock = coproto::sync_wait(acceptor.accept());

        switch (opt.scheme)
        {
            case OtScheme::Iknp:
            {
#ifdef ENABLE_IKNP
                osuCrypto::IknpOtExtReceiver recver;
                runReceiver(recver, opt, B, sock);
#else
                throw std::runtime_error("IKNP OT is not enabled in this build.");
#endif
                break;
            }
            case OtScheme::Silent:
            {
#ifdef ENABLE_SILENTOT
                osuCrypto::SilentOtExtReceiver recver;
                runReceiver(recver, opt, B, sock);
#else
                throw std::runtime_error("Silent OT is not enabled in this build.");
#endif
                break;
            }
            case OtScheme::SoftSpoken:
            {
#ifdef ENABLE_SOFTSPOKEN_OT
                osuCrypto::SoftSpokenShOtReceiver<> recver(opt.k);
                runReceiver(recver, opt, B, sock);
#else
                throw std::runtime_error("SoftSpoken OT is not enabled in this build.");
#endif
                break;
            }
        }

        return 0;
    }
    catch (const std::exception& e)
    { std::cerr << "[receiver] error: " << e.what() << "\n"; return 1; }
}
/*
./build/Bob \
  --addr 127.0.0.1:1212 \
  --b inputs/B.txt \
  --ot softspoken \
  --k 2 \
  --l 32 \
  --t 16 \
  --verbose
*/