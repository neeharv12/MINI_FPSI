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
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#endif

#ifdef ENABLE_SILENTOT
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#endif

#ifdef ENABLE_SOFTSPOKEN_OT
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
#endif

template<typename OtSender>
static void runSender(
    OtSender&                               sender,
    const MINI::Options&                opt,
    const std::vector<std::string>&         A,
    coproto::AsioSocket&                    sock)
{
    using namespace MINI;
    using osuCrypto::BitVector;
    using Clock = std::chrono::steady_clock;
    const auto totalStart = Clock::now();

    const auto commSent0 = sock.bytesSent();
    const auto commRecv0 = sock.bytesReceived();

    const u64 aCount = static_cast<u64>(A.size());

    const std::array<block, 1> sendHdr{ block(0, aCount) };
    coproto::sync_wait(sock.send(sendHdr));

    std::array<block, 1> recvHdr;
    coproto::sync_wait(sock.recv(recvHdr));
    const u64 bCount = recvHdr[0].get<u64>(0);

    if (opt.verbose)
        std::cout << "[Alice] addr=" << opt.address
                  << " |A|=" << aCount << " |B|=" << bCount
                  << " ot=" << otSchemeName(opt.scheme) << "\n";

    const u64 totalPairs = aCount * bCount;

    auto prngOt  = makePrngDomain(opt.seed, 0);
    const osuCrypto::AES aes1(osuCrypto::toBlock(0, 0));
    const osuCrypto::AES aes2(osuCrypto::toBlock(0, 1));

    struct PendingPair
    {
        u64 ai = 0;
        u64 bj = 0;
        u64 Delta = 0;
        std::vector<osuCrypto::block> t1Blocks;
    };

    std::vector<std::vector<std::pair<u64, std::string>>> matches(
        static_cast<size_t>(aCount));
    
    
    for (u64 chunkStart = 0; chunkStart < totalPairs; chunkStart += PAIRS_PER_CHUNK)
    {
        const u64 chunkPairs = std::min<u64>(PAIRS_PER_CHUNK, totalPairs - chunkStart);
        const u64 chunkOts   = chunkPairs * opt.n();

        if (opt.verbose)
            std::cout << "[Alice] chunk start=" << chunkStart
                      << " pairs=" << chunkPairs
                      << " ots=" << chunkOts << "\n";

        std::vector<PendingPair> pending(static_cast<size_t>(chunkPairs));

        std::vector<std::array<osuCrypto::block, 2>> allMsgs(static_cast<size_t>(chunkOts));

        parallelFor(0, static_cast<std::uint64_t>(chunkPairs), static_cast<std::uint64_t>(opt.verbose ? 1 : opt.threads), [&](std::uint64_t localPair64)
        {
            const u64 localPair     = static_cast<u64>(localPair64);
            const u64 globalPair    = chunkStart + localPair;
            const auto [ai, bj]     = pairToIndices(globalPair, bCount);

            auto prngMsg = makePrngDomain(opt.seed, 1 + globalPair);
            auto built = buildMessagePairsFromA(A[static_cast<size_t>(ai)], prngMsg, opt);

            PendingPair p;
            p.ai    = ai;
            p.bj    = bj;
            p.Delta = built.Delta;
            p.t1Blocks.resize(kappa);
            for (u64 i = 0; i < kappa; ++i)
                p.t1Blocks[i] = built.msgs[opt.l + i][0];

            pending[static_cast<size_t>(localPair)] = std::move(p);
            const size_t msgBase = static_cast<size_t>(localPair * opt.n());
            for (u64 i = 0; i < opt.n(); ++i)
                allMsgs[msgBase + static_cast<size_t>(i)] = built.msgs[static_cast<size_t>(i)];
        });

        auto proto = sender.sendChosen(
            osuCrypto::span<std::array<osuCrypto::block, 2>>(
                allMsgs.data(), allMsgs.size()),
            prngOt,
            static_cast<osuCrypto::Socket&>(sock));
        coproto::sync_wait(std::move(proto));

        std::vector<std::array<osuCrypto::block, 2>> replies(static_cast<size_t>(chunkPairs));

        coproto::sync_wait(sock.recv(replies));

        for (u64 localPair = 0; localPair < chunkPairs; ++localPair)
        {
            const auto& reply         = replies[static_cast<size_t>(localPair)];
            const auto& p             = pending[static_cast<size_t>(localPair)];
            const BitVector output    = unpackBlockToBitVector(reply[0], kappa);
            const block     recvHash2 = reply[1];

            if (opt.verbose)
                std::cout << "[Alice] pair (a[" << p.ai << "], b[" << p.bj << "])"
                          << " Delta=" << p.Delta << "\n";

            std::array<BitVector, kappa> t1Cache;
            for (u64 i = 0; i < kappa; ++i)
                t1Cache[i] = unpackBlockToBitVector(p.t1Blocks[i], opt.mod());

            for (u64 k = 0; k <= opt.t; ++k)
            {
                const u64 candidate = (p.Delta + opt.mod() - k) % opt.mod();

                BitVector Eval(kappa);
                for (u64 i = 0; i < kappa; ++i)
                    Eval[i] = t1Cache[i][candidate];

                const block hash1 = aes1.ecbEncBlock(packBitVectorToBlock(Eval));
                const block hash2 = aes2.ecbEncBlock(packBitVectorToBlock(Eval));

                if (opt.verbose)
                    std::cout << "[Alice]   candidate=" << candidate
                              << " match=" << (hash2 == recvHash2) << "\n";

                if (hash2 == recvHash2)
                {
                    BitVector recovered = output;
                    recovered ^= unpackBlockToBitVector(hash1, kappa);
                    BitVector recoveredL(recovered.data(), opt.l);
                    matches[static_cast<size_t>(p.ai)].emplace_back(
                        p.bj, bitVectorToString(recoveredL));
                    if (opt.verbose)
                        std::cout << "[Alice]   match! b=" << recoveredL << "\n";
                    break;
                }
            }
        }
    }
    const double totalSeconds = std::chrono::duration<double>(Clock::now() - totalStart).count();
    
    for (size_t ai = 0; ai < aCount; ++ai)
    {
        if(opt.verbose)
        {
        if (matches[ai].empty())
            std::cout << "[Alice] a[" << ai << "] = " << A[ai] << " -> no matches\n";
        else
        {
            std::cout << "[Alice] a[" << ai << "] = " << A[ai] << " -> matches:\n";
            for (const auto& m : matches[ai])
                std::cout << "  b[" << m.first << "] = " << m.second << "\n";
        }
    }
    }

    coproto::sync_wait(sock.flush());
    const auto commSent1 = sock.bytesSent();
    const auto commRecv1 = sock.bytesReceived();
    const auto commSent = commSent1 - commSent0;
    const auto commRecv = commRecv1 - commRecv0;

    std::cout << "[Alice] summary: total_time=" << std::fixed << std::setprecision(3) << totalSeconds << " s\n";
    std::cout << "[communication] Alice->Bob=" << static_cast<double>(commSent) / 1e6
              << " Bob->Alice=" << static_cast<double>(commRecv) / 1e6
              << " total=" << static_cast<double>(commSent + commRecv) / 1e6
              << " MB\n";
}

int main(int argc, char** argv)
{
    using namespace MINI;
    try
    {
        auto opt = parseArgs(argc, argv, "sender");
        if (opt.a.empty()) throw std::runtime_error("Sender requires --a A.txt");
        const auto A = loadBitstrings(opt.a, opt.l);

        AsioRuntime rt(opt.threads);
        coproto::AsioConnect connector(opt.address, rt.ioc);
        coproto::AsioSocket sock = coproto::sync_wait(std::move(connector));

        switch (opt.scheme)
        {
            case OtScheme::Iknp:
            {
#ifdef ENABLE_IKNP
                osuCrypto::IknpOtExtSender sender;
                runSender(sender, opt, A, sock);
#else
                throw std::runtime_error("IKNP OT is not enabled in this build.");
#endif
                break;
            }
            case OtScheme::Silent:
            {
#ifdef ENABLE_SILENTOT
                osuCrypto::SilentOtExtSender sender;
                runSender(sender, opt, A, sock);
#else
                throw std::runtime_error("Silent OT is not enabled in this build.");
#endif
                break;
            }
            case OtScheme::SoftSpoken:
            {
#ifdef ENABLE_SOFTSPOKEN_OT
                osuCrypto::SoftSpokenShOtSender<> sender(opt.k);
                runSender(sender, opt, A, sock);
#else
                throw std::runtime_error("SoftSpoken OT is not enabled in this build.");
#endif
                break;
            }
        }

        coproto::sync_wait(sock.close());
        return 0;
    }
    catch (const std::exception& e)
    { std::cerr << "[Alice] error: " << e.what() << "\n"; return 1; }
}
/*
./build/Alice \
  --addr 127.0.0.1:1212 \
  --a inputs/A.txt \
  --ot iknp \
  --k 2 \
  --l 32 \
  --t 16 \
  --verbose
*/