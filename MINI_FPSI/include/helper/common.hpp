//common.hpp
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include "coproto/coproto.h"
#include "coproto/Socket/AsioSocket.h"

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace MINI
{

using osuCrypto::u64;
using osuCrypto::block;

constexpr std::uint64_t kappa           = 128;
constexpr std::uint64_t PAIRS_PER_CHUNK = 65536;

////////////////////////////////////////////////////////////////
// OT scheme
////////////////////////////////////////////////////////////////

enum class OtScheme { Iknp, Silent, SoftSpoken };

inline OtScheme parseOtScheme(const std::string& s)
{
    if (s == "iknp")       return OtScheme::Iknp;
    if (s == "silent")     return OtScheme::Silent;
    if (s == "softspoken") return OtScheme::SoftSpoken;
    throw std::runtime_error(
        "Unknown OT scheme '" + s + "'. Valid choices: iknp, silent, softspoken");
}

inline const char* otSchemeName(OtScheme scheme)
{
    switch (scheme)
    {
        case OtScheme::Iknp:       return "iknp";
        case OtScheme::Silent:     return "silent";
        case OtScheme::SoftSpoken: return "softspoken";
    }
    return "unknown";
}

////////////////////////////////////////////////////////////////
// Options
////////////////////////////////////////////////////////////////

struct Options
{
    std::string address = "127.0.0.1:1212";
    int  threads = 2;
    u64  seed    = 0;
    bool verbose = false;
    OtScheme scheme = OtScheme::Iknp;
    std::string b, a;

    u64 l = 32;
    u64 t = 16;
    u64 k = 6;  // SoftSpoken field bits (only used when scheme == SoftSpoken)

    u64 n() const { return l + kappa; }
    u64 mod() const { return l + 1; }
};

inline void usage(const char* exe, const char* role)
{
    std::cerr
        << "Usage (" << role << "): " << exe
        << " [--addr ip:port] [--threads T] [--seed S] [--verbose]"
        << " [--ot iknp|silent|softspoken] [--l L] [--t T] [--k K]"
        << " [--b B.txt] [--a A.txt]\n";
}

inline Options parseArgs(int argc, char** argv, const char* role)
{
    Options opt;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        auto needValue = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                usage(argv[0], role);
                throw std::runtime_error(std::string("Missing value for ") + flag);
            }
            return argv[++i];
        };
        if      (a == "--addr")    opt.address = needValue("--addr");
        else if (a == "--threads") opt.threads = std::stoi(needValue("--threads"));
        else if (a == "--seed")    opt.seed    = static_cast<u64>(std::stoull(needValue("--seed")));
        else if (a == "--verbose") opt.verbose = true;
        else if (a == "--ot")      opt.scheme  = parseOtScheme(needValue("--ot"));
        else if (a == "--b")       opt.b       = needValue("--b");
        else if (a == "--a")       opt.a       = needValue("--a");
        else if (a == "--l")       opt.l       = static_cast<u64>(std::stoull(needValue("--l")));
        else if (a == "--t")       opt.t       = static_cast<u64>(std::stoull(needValue("--t")));
        else if (a == "--k")       opt.k       = static_cast<u64>(std::stoull(needValue("--k")));
        else if (a == "--help" || a == "-h") { usage(argv[0], role); std::exit(0); }
        else { usage(argv[0], role); throw std::runtime_error("Unknown argument: " + a); }
    }
    if (opt.threads <= 0) opt.threads = 1;
    if (opt.l == 0) throw std::runtime_error("--l must be > 0");
    if (opt.l + 1 > 128) throw std::runtime_error("--l must satisfy l+1 <= 128");
    if (opt.t > opt.l) throw std::runtime_error("--t must satisfy t <= l");
    if (opt.k == 0) throw std::runtime_error("--k must be > 0");
    return opt;
}

////////////////////////////////////////////////////////////////
// Asio runtime
////////////////////////////////////////////////////////////////

struct AsioRuntime
{
    boost::asio::io_context ioc;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work;
    std::vector<std::thread> threads;

    explicit AsioRuntime(int threadCount) : work(ioc.get_executor())
    {
        threads.reserve(static_cast<size_t>(threadCount));
        for (int i = 0; i < threadCount; ++i)
            threads.emplace_back([this] { ioc.run(); });
    }
    ~AsioRuntime()
    {
        work.reset(); ioc.stop();
        for (auto& t : threads) if (t.joinable()) t.join();
    }
    AsioRuntime(const AsioRuntime&) = delete;
    AsioRuntime& operator=(const AsioRuntime&) = delete;
};

////////////////////////////////////////////////////////////////
// PRNG
////////////////////////////////////////////////////////////////

inline osuCrypto::PRNG makePrngDomain(u64 seed, u64 domain)
{
    if (seed == 0) return osuCrypto::PRNG(osuCrypto::sysRandomSeed());
    return osuCrypto::PRNG(block(domain, seed));
}

////////////////////////////////////////////////////////////////
// File helpers
////////////////////////////////////////////////////////////////

inline std::vector<std::string> loadBitstrings(const std::string& path, u64 lValue)
{
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open file: " + path);
    std::vector<std::string> out;
    std::string line;
    while (std::getline(in, line))
    {
        if (line.empty()) continue;
        if (line.size() != lValue)
            throw std::runtime_error("bitstring length must equal l");
        for (char c : line)
            if (c != '0' && c != '1')
                throw std::runtime_error("invalid bitstring in file: " + line);
        out.push_back(line);
    }
    if (out.empty()) throw std::runtime_error("empty file: " + path);
    return out;
}

inline std::string bitVectorToString(const osuCrypto::BitVector& v)
{
    std::string s; s.reserve(v.size());
    for (u64 i = 0; i < v.size(); ++i) s.push_back(v[i] ? '1' : '0');
    return s;
}

////////////////////////////////////////////////////////////////
// Bit helpers
////////////////////////////////////////////////////////////////

inline osuCrypto::BitVector buildChoices(
    const std::string& bStr,
    const Options& opt)
{
    if (bStr.size() != opt.l)
        throw std::runtime_error("--b string must have length l");

    osuCrypto::BitVector choices(opt.n());

    for (u64 i = 0; i < opt.l; ++i)
    {
        if      (bStr[i] == '0') choices[i] = 0;
        else if (bStr[i] == '1') choices[i] = 1;
        else throw std::runtime_error("--b must contain only 0 or 1");
    }

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    for (u64 i = 0; i < kappa; ++i)
        choices[opt.l + i] = prng.get<std::uint8_t>() & 1;

    return choices;
}

////////////////////////////////////////////////////////////////
// Math helpers
////////////////////////////////////////////////////////////////

inline std::uint64_t modZ(std::int64_t x, std::uint64_t modValue)
{
    std::int64_t r = x % static_cast<std::int64_t>(modValue);
    if (r < 0) r += static_cast<std::int64_t>(modValue);
    return static_cast<std::uint64_t>(r);
}

inline std::pair<std::uint64_t, std::vector<std::uint64_t>>
shareDeltaAdditive(std::uint64_t lValue, osuCrypto::PRNG& prng)
{
    const std::uint64_t modValue = lValue + 1;
    const std::uint64_t Delta    = prng.get<std::uint64_t>() % modValue;
    std::vector<std::uint64_t> deltas(lValue, 0);
    std::uint64_t sum = 0;
    for (std::uint64_t i = 0; i + 1 < lValue; ++i)
    {
        deltas[i] = prng.get<std::uint64_t>() % modValue;
        sum = (sum + deltas[i]) % modValue;
    }
    deltas[lValue - 1] = (Delta + modValue - sum) % modValue;
    return { Delta, deltas };
}

// laneTag removed: always encodes with tag 0
inline osuCrypto::block encodeZ(std::uint64_t value)
{
    return osuCrypto::block(0, value);
}

////////////////////////////////////////////////////////////////
// BitVector <-> block
////////////////////////////////////////////////////////////////

inline osuCrypto::block packBitVectorToBlock(const osuCrypto::BitVector& v)
{
    if (v.size() > 128) throw std::runtime_error("packBitVectorToBlock: size > 128");
    osuCrypto::block b = osuCrypto::ZeroBlock;
    std::memcpy(&b, v.data(), v.sizeBytes());
    return b;
}

inline osuCrypto::BitVector unpackBlockToBitVector(const osuCrypto::block& b, u64 L)
{
    if (L > 128) throw std::runtime_error("unpackBlockToBitVector: size > 128");
    osuCrypto::BitVector v(L);
    std::memcpy(v.data(), &b, v.sizeBytes());
    if (L % 8)
    {
        std::uint8_t mask = static_cast<std::uint8_t>((1u << (L % 8)) - 1u);
        v.data()[v.sizeBytes() - 1] &= mask;
    }
    return v;
}

////////////////////////////////////////////////////////////////
// Pair index helper (shared by sender and receiver)
////////////////////////////////////////////////////////////////

inline std::pair<u64, u64> pairToIndices(u64 pairIdx, u64 bCount)
{
    return { pairIdx / bCount, pairIdx % bCount };
}

////////////////////////////////////////////////////////////////
// Message building
////////////////////////////////////////////////////////////////

struct MessageBuildResult
{
    std::uint64_t Delta = 0;
    std::vector<std::uint64_t> deltas;
    std::vector<std::array<osuCrypto::block, 2>> msgs;
};

namespace detail
{
inline std::vector<std::uint8_t> bitsFromString01(const std::string& s)
{
    if (s.empty()) throw std::runtime_error("--a cannot be empty");
    std::vector<std::uint8_t> bits; bits.reserve(s.size());
    for (char c : s)
    {
        if      (c == '0') bits.push_back(0);
        else if (c == '1') bits.push_back(1);
        else throw std::runtime_error("--a must contain only '0' and '1'");
    }
    return bits;
}
} // namespace detail

inline MessageBuildResult
buildMessagePairsFromA(const std::string& aStr, osuCrypto::PRNG& prng, const Options& opt)
{
    auto bits = detail::bitsFromString01(aStr);
    if (bits.size() != opt.l)
        throw std::runtime_error("--a must have length l");

    MessageBuildResult out;

    auto [Delta, deltas] = shareDeltaAdditive(opt.l, prng);
    out.Delta  = Delta;
    out.deltas = std::move(deltas);
    out.msgs.resize(opt.n());

    for (std::uint64_t i = 0; i < opt.l; ++i)
    {
        const std::uint64_t ai = bits[i];
        const std::uint64_t di = out.deltas[i];

        const std::uint64_t m0 = modZ(
            static_cast<std::int64_t>(di) - static_cast<std::int64_t>(ai), opt.mod());
        const std::uint64_t m1 = modZ(
            static_cast<std::int64_t>(di) - static_cast<std::int64_t>(1 - ai), opt.mod());

        out.msgs[i][0] = encodeZ(m0);
        out.msgs[i][1] = encodeZ(m1);
    }

    osuCrypto::BitVector TT(opt.mod());
    for (u64 i = 0; i < opt.mod(); ++i)
    {
        TT[i] = 1;
        if ((Delta + opt.mod() - i) % opt.mod() <= opt.t) TT[i] = 0;
    }

    osuCrypto::BitVector T1(opt.mod());
    for (u64 i = 0; i < kappa; ++i)
    {
        T1.randomize(prng);
        osuCrypto::BitVector T2 = T1;
        T2 ^= TT;
        out.msgs[opt.l + i][0] = packBitVectorToBlock(T1);
        out.msgs[opt.l + i][1] = packBitVectorToBlock(T2);
    }

    return out;
}

} // namespace MINI