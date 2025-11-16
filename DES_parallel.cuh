#ifndef DES_D_DES_CUH
#define DES_D_DES_CUH

#include "utility.h"
using namespace constants;

template<int FROM, int TO>
__device__  // può essere chiamata solo da funzioni che girano su GPU
auto permute_p(const uint64_t source,const int *table) -> uint64_t{
    uint64_t  p = 0;
    for(int i = 0; i < TO; i++){
        p |= ( (source >> (FROM-table[i])) & 1) << (TO-1-i);
    }
    return p;
}

__host__
bool * parallelCrack(uint64_t *pwdList, int pwdNum, uint64_t *pwdToCrack, int numCrack, uint64_t key, int blockSize);

__device__
uint64_t feistelFunction_p(uint64_t subkey, uint64_t right);

__device__
uint64_t desEncrypt_p(uint64_t key56, uint64_t plaintext);

// Kernel 1: Cifra l'intero dizionario
__global__
void kernelEncrypt(const uint64_t *pwdList, int pwdNum, uint64_t *encryptedDictionaryGPU, uint64_t key);

// Kernel 2: Confronta il dizionario cifrato con le password target
__global__
void kernelCompare(const uint64_t *encryptedDictionaryGPU, int pwdNum, const uint64_t *pwdToCrack, int numCrack, bool *found);

#endif //DES_D_DES_CUH