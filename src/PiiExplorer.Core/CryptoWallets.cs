using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PiiExplorer.Core;

// Address checksums make wallet detection precise: a Base58Check, Bech32 or EIP-55
// candidate that verifies is almost never an accidental string.
internal static class CryptoWallets
{
    private const string Base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const string Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    public static double Bitcoin(string text, int start, string value)
    {
        BigInteger number = BigInteger.Zero;
        foreach (char c in value) { int digit = Base58.IndexOf(c); if (digit < 0) return 0; number = number * 58 + digit; }
        byte[] payload = number.ToByteArray(isUnsigned: true, isBigEndian: true);
        int leading = 0; while (leading < value.Length && value[leading] == '1') leading++;
        byte[] full = new byte[leading + payload.Length]; payload.CopyTo(full, leading);
        if (full.Length != 25 || full[0] is not (0x00 or 0x05 or 0x6f or 0xc4)) return 0;
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(full.AsSpan(0, 21), hash); SHA256.HashData(hash, hash);
        return hash[..4].SequenceEqual(full.AsSpan(21, 4)) ? .95 : 0;
    }

    public static double Bech32(string text, int start, string value)
    {
        if (value.Length > 90) return 0;
        string lower = value.ToLowerInvariant();
        if (value != lower && value != value.ToUpperInvariant()) return 0;
        int separator = lower.LastIndexOf('1');
        if (separator < 1 || separator + 8 > lower.Length) return 0;
        string hrp = lower[..separator];
        if (hrp is not ("bc" or "tb")) return 0;
        var values = new List<int>();
        foreach (char c in hrp) values.Add(c >> 5);
        values.Add(0);
        foreach (char c in hrp) values.Add(c & 31);
        foreach (char c in lower.AsSpan(separator + 1)) { int digit = Bech32Charset.IndexOf(c); if (digit < 0) return 0; values.Add(digit); }
        uint checksum = 1;
        ReadOnlySpan<uint> generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        foreach (int v in values)
        {
            uint top = checksum >> 25;
            checksum = ((checksum & 0x1ffffff) << 5) ^ (uint)v;
            for (int i = 0; i < 5; i++) if (((top >> i) & 1) != 0) checksum ^= generator[i];
        }
        // A generic Bech32 checksum alone does not establish a SegWit address.
        // BIP-350 also constrains witness version, program length and bit padding.
        int version = Bech32Charset.IndexOf(lower[separator + 1]);
        if (version is < 0 or > 16 || checksum != (version == 0 ? 1u : 0x2bc830a3u)) return 0;
        int bits = 0, accumulator = 0, bytes = 0;
        foreach (char c in lower.AsSpan(separator + 2, lower.Length - separator - 8))
        {
            accumulator = ((accumulator << 5) | Bech32Charset.IndexOf(c)) & 0xfff;
            bits += 5;
            if (bits >= 8) { bytes++; bits -= 8; }
        }
        if (bits >= 5 || (accumulator & ((1 << bits) - 1)) != 0 || bytes is < 2 or > 40) return 0;
        return version != 0 || bytes is 20 or 32 ? .95 : 0;
    }

    public static double Ethereum(string text, int start, string value)
    {
        string hex = value[2..];
        bool hasUpper = hex.Any(char.IsUpper), hasLower = hex.Any(char.IsLower);
        if (!hasUpper || !hasLower) return hex.All(c => c == '0') ? 0 : .6; // No EIP-55 case information to verify.
        byte[] hash = Keccak256(Encoding.ASCII.GetBytes(hex.ToLowerInvariant()));
        for (int i = 0; i < 40; i++)
        {
            if (!char.IsAsciiLetter(hex[i])) continue;
            int nibble = i % 2 == 0 ? hash[i / 2] >> 4 : hash[i / 2] & 0xf;
            if (char.IsUpper(hex[i]) != nibble >= 8) return 0;
        }
        return .95;
    }

    private static readonly ulong[] RoundConstants = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008 };
    private static readonly int[] Rotations = { 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

    // Keccak-256 (original padding, as used by Ethereum), not the NIST SHA3-256 variant.
    internal static byte[] Keccak256(ReadOnlySpan<byte> data)
    {
        const int rate = 136;
        var state = new ulong[25];
        Span<byte> block = stackalloc byte[rate];
        int offset = 0;
        while (data.Length - offset >= rate) { Absorb(state, data.Slice(offset, rate)); offset += rate; }
        block.Clear(); data[offset..].CopyTo(block);
        block[data.Length - offset] ^= 0x01; block[rate - 1] ^= 0x80;
        Absorb(state, block);
        byte[] output = new byte[32];
        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(i * 8), state[i]);
        return output;
    }

    private static void Absorb(ulong[] state, ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < block.Length / 8; i++) state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));
        Span<ulong> c = stackalloc ulong[5], d = stackalloc ulong[5], b = stackalloc ulong[25];
        for (int round = 0; round < 24; round++)
        {
            for (int x = 0; x < 5; x++) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            for (int x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
            for (int i = 0; i < 25; i++) state[i] ^= d[i % 5];
            for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = BitOperations.RotateLeft(state[x + 5 * y], Rotations[x + 5 * y]);
            for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
                state[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            state[0] ^= RoundConstants[round];
        }
    }
}
