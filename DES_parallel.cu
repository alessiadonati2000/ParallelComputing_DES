#include <iostream>
#include "DES_parallel.cuh"

// Costanti globabli su GPU: tabelle statiche DES
// calls to cudaMemcpyToSymbol() have to reside in the same file where the constant data is defined.
// vivono nella constant memory della GPU: memoria veloce (cache dedicata)
// ideale quando tutti i thread leggono gli stessi valori
__constant__ int initialPerm_p[BLOCK];
__constant__ int finalPerm_p[BLOCK];
__constant__ int expansion_p[ROUND_KEY];
__constant__ int hS1_p[BLOCK];
__constant__ int hS2_p[BLOCK];
__constant__ int hS3_p[BLOCK];
__constant__ int hS4_p[BLOCK];
__constant__ int hS5_p[BLOCK];
__constant__ int hS6_p[BLOCK];
__constant__ int hS7_p[BLOCK];
__constant__ int hS8_p[BLOCK];
__constant__ int *hS_p[8] = {
        hS1_p, hS2_p, hS3_p, hS4_p, hS5_p, hS6_p, hS7_p, hS8_p};
__constant__ int permutation_p[HALF_BLOCK];
__constant__ int permutedChoice1_p[56];
__constant__ int permutedChoice2_p[ROUND_KEY];
__constant__ int keyShiftArray_p[ROUNDS];


// Funzione host (chiamata da CPU) parallelCrack: prepara i dati e lancia il kernel
__host__
bool * parallelCrack(uint64_t *pwdList, int N, uint64_t *pwdToCrack, int nCrack, uint64_t key, int blockSize){
    // copia le tabelle in constant memory
    cudaMemcpyToSymbol(initialPerm_p, initialPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(finalPerm_p, finalPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(expansion_p, expansion, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(hS1_p, hS1, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(hS2_p, hS2, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(hS3_p, hS3, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(hS4_p, hS4, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(hS5_p, hS5, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(hS6_p, hS6, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(hS7_p, hS7, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(hS8_p, hS8, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(permutation_p, permutation, sizeof(int) * HALF_BLOCK);
    cudaMemcpyToSymbol(permutedChoice1_p, permutedChoice1, sizeof(int) * 56);
    cudaMemcpyToSymbol(permutedChoice2_p, permutedChoice2, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(keyShiftArray_p, keyShiftArray, sizeof(int) * ROUNDS);

    // alloca e copia i dati del dizionario e delle password target
    uint64_t *pwdList_p, *pwdToCrack_p;
    cudaMalloc((void **)&pwdList_p, N * sizeof(uint64_t));
    cudaMemcpy(pwdList_p, pwdList, N*sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMalloc((void **) &pwdToCrack_p, nCrack * sizeof(uint64_t));
    cudaMemcpy(pwdToCrack_p, pwdToCrack, nCrack * sizeof(uint64_t), cudaMemcpyHostToDevice);

    // alloca array found su device (per marcare quali password sono state trovate
    bool *found_p;
    cudaMalloc((void **) &found_p, nCrack * sizeof(bool));
    cudaMemset(found_p, 0, nCrack * sizeof(bool));

    // lancia il kernel
    // numero di blocchi: (N + blockSize - 1) / blockSize
    // ogni thread cifra una password del dizionaio
    kernelCrack<<<(N + blockSize - 1) / blockSize, blockSize>>>(pwdList_p, N, pwdToCrack_p, nCrack, found_p, key);
    auto err = cudaGetLastError();
    if (err != cudaSuccess){
        printf("\n### %s: %s ###\n", cudaGetErrorName(err), cudaGetErrorString(err));
    }

    // copia i risultati indietro
    bool *found = new bool[nCrack];
    cudaMemcpy(found, found_p, nCrack * sizeof(bool), cudaMemcpyDeviceToHost);

    // libera la memoria GPU
    cudaFree(pwdList_p);
    cudaFree(pwdToCrack_p);
    cudaFree(found_p);

    return found;
}


// Kernel kernelCrack: ogni thread cifra una password e la confronta con quelle da crackare
__global__
void kernelCrack(const uint64_t *pwdList, int nPwd, const uint64_t *pwdToCrack, int nCrack, bool *found, uint64_t key) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;    // codice identificativo del thread
    // il dizionario ha N password
    if (tid < nPwd){
        // prende una password(pwdList[tid] e la cifra con DES (d_desEncrypt)
        uint64_t e = desEncrypt_p(key, pwdList[tid]);
        // Confronta con tutte le nCrack password target
        for(int i = 0; i < nCrack; i++){
            if (!found[i] && e == pwdToCrack[i]){
                found[i] = true;    // ha trovato una corrispondenza
                printf("Thread-%d found password %d\n", tid, i); //era commentato
            }
        }
    }
}

// Funzione device: implementazione DES e Feistel function su GPU
__device__
uint64_t feistelFunction_p(const uint64_t subkey, const uint64_t bits){
    // Expansion
    uint64_t exp = permute_p<HALF_BLOCK, ROUND_KEY>(bits, expansion_p);

    // Key mixing
    uint64_t xored = subkey ^ exp;

    // Substitution
    exp = 0;
    for(int j = 8-1; j >= 0; j--){
        uint8_t block = (xored >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(hS_p[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    return permute_p<HALF_BLOCK, HALF_BLOCK>(exp, permutation_p);
}


// è la copia della versione CPU
__device__ //chiamabile solo da funzioni CUDA
uint64_t desEncrypt_p(uint64_t key56, const uint64_t message){
    // Initial permutation
    uint64_t ip = permute_p<BLOCK, BLOCK>(message, initialPerm_p);
    // Split in two halves
    uint32_t lhs = (ip >> HALF_BLOCK),
            rhs = ip;


    // Rounds, with subkey generation
    key56 = permute_p<BLOCK, 56>(key56, permutedChoice1_p);

    uint32_t lhs_rk = (key56 >> 28) & 0xfffffff;
    uint32_t rhs_rk = (key56) & 0xfffffff;

    for(int shift : keyShiftArray_p){

        lhs_rk = (lhs_rk << shift) | (lhs_rk >> (28 - shift));
        rhs_rk = (rhs_rk << shift) | (rhs_rk >> (28 - shift));
        lhs_rk &= 0xfffffff;
        rhs_rk &= 0xfffffff;

        uint64_t roundKey = (uint64_t(lhs_rk) << 28) | rhs_rk;

        roundKey = permute_p<56, ROUND_KEY>(roundKey, permutedChoice2_p);


        uint64_t feistel = feistelFunction_p(roundKey, rhs);

        auto old_lhs = lhs;
        lhs = rhs;
        rhs = old_lhs ^ feistel;

    }
    uint64_t res = (uint64_t(rhs) << HALF_BLOCK) | lhs;

    // Final permutation
    res = permute_p<BLOCK, BLOCK>(res, finalPerm_p);

    return res;
}