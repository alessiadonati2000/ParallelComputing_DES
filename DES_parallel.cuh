#ifndef DES_D_DES_CUH
#define DES_D_DES_CUH

#include "utility.h"
using namespace constants;

template<int FROM, int TO>
__device__  // può essere chaimata solo da funzioni che girano su GPU
auto permute_p(const uint64_t source,const int *table) -> uint64_t{
    uint64_t  p = 0;
    for(int i = 0; i < TO; i++){
        p |= ( (source >> (FROM-table[i])) & 1) << (TO-1-i);
    }
    return p;
}
__host__
bool * parallelCrack(uint64_t *pwdList, int N, uint64_t *pwdToCrack, int numCrack, uint64_t key, int blockSize);

__device__
uint64_t feistelFunction_p(uint64_t subkey, uint64_t bits);

__device__
uint64_t desEncrypt_p(uint64_t key56, uint64_t message);

__global__
void kernelCrack(const uint64_t *pwdList, int nPwd, const uint64_t *pwdToCrack, int nCrack, bool *found, uint64_t key);
#endif //DES_D_DES_CUH
