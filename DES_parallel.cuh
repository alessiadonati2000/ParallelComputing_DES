#ifndef DES_D_DES_CUH
#define DES_D_DES_CUH

#include "utility.h"

template<int FROM, int TO>
__device__
/**
 * @brief Funzione che esegue la permutazione secondo la tabella in input
 */
auto permute_p(const uint64_t source,const int *table) -> uint64_t{
    uint64_t  p = 0;
    for(int i = 0; i < TO; i++){
        p |= ( (source >> (FROM-table[i])) & 1ULL) << (TO-1-i);
    }
    return p;
}

__host__
/**
 * @brief Funzione host (chiamata da CPU): prepara i dati e lancia il kernel
 */
bool * parallelCrack(uint64_t *pwdList, int pwdNum, uint64_t *pwdToCrack, int numCrack, uint64_t key, int blockSize);

__device__
/**
 * @brief Funzione che implementa la funzione di Feistel ma utilizzando le tabelle in costant memory
 */
uint64_t feistelFunction_p(uint64_t subkey, uint64_t right);

__device__
/**
 * @brief Funzione che implementa i 16 round dell'algoritmo DES utilizzando le tabelle in costant memory
 */
uint64_t desEncrypt_p(uint64_t key56, uint64_t plaintext);

__global__
/**
 * @brief Funzione che esegue l'algoritmo DES
 */
void kernelCrack(const uint64_t *pwdList, int numPwd, const uint64_t *pwdToCrack, int numCrack, bool *found, uint64_t key);

#endif //DES_D_DES_CUH