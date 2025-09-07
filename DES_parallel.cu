#include <iostream>
#include "d_DES.cuh"

// Costanti globabli su GPU: tabelle statiche DES
// calls to cudaMemcpyToSymbol() have to reside in the same file where the constant data is defined.
// vivono nella constant memory della GPU: memoria veloce (cache dedicata)
// ideale quando tutti i thread leggono gli stessi valori
__constant__ int d_initialPerm[BLOCK];
__constant__ int d_finalPerm[BLOCK];
__constant__ int d_expansion[ROUND_KEY];
__constant__ int d_hS1[BLOCK];
__constant__ int d_hS2[BLOCK];
__constant__ int d_hS3[BLOCK];
__constant__ int d_hS4[BLOCK];
__constant__ int d_hS5[BLOCK];
__constant__ int d_hS6[BLOCK];
__constant__ int d_hS7[BLOCK];
__constant__ int d_hS8[BLOCK];
__constant__ int *d_hS[8] = {
        d_hS1, d_hS2, d_hS3, d_hS4, d_hS5, d_hS6, d_hS7, d_hS8};
__constant__ int d_permutation[HALF_BLOCK];
__constant__ int d_permutedChoice1[56];
__constant__ int d_permutedChoice2[ROUND_KEY];
__constant__ int d_keyShiftArray[ROUNDS];


// Funzione host (chiamata da CPU) parallelCrack: prepara i dati e lancia il kernel
__host__
bool * parallelCrack(uint64_t *pwdList, int N, uint64_t *pwdToCrack, int nCrack, uint64_t key, int blockSize){
    // copia le tabelle in constant memory
    cudaMemcpyToSymbol(d_initialPerm, initialPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_finalPerm, finalPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_expansion, expansion, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(d_hS1, hS1, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_hS2, hS2, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_hS3, hS3, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_hS4, hS4, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_hS5, hS5, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_hS6, hS6, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_hS7, hS7, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_hS8, hS8, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(d_permutation, permutation, sizeof(int) * HALF_BLOCK);
    cudaMemcpyToSymbol(d_permutedChoice1, permutedChoice1, sizeof(int) * 56);
    cudaMemcpyToSymbol(d_permutedChoice2, permutedChoice2, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(d_keyShiftArray, keyShiftArray, sizeof(int) * ROUNDS);

    // alloca e copia i dati del dizionario e delle password target
    uint64_t *d_pwdList, *d_pwdToCrack;
    cudaMalloc((void **)&d_pwdList, N * sizeof(uint64_t));
    cudaMemcpy(d_pwdList, pwdList, N*sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMalloc((void **) &d_pwdToCrack, nCrack * sizeof(uint64_t));
    cudaMemcpy(d_pwdToCrack, pwdToCrack, nCrack * sizeof(uint64_t), cudaMemcpyHostToDevice);

    // alloca array found su device (per marcare quali password sono state trovate
    bool *d_found;
    cudaMalloc((void **) &d_found, nCrack * sizeof(bool));
    cudaMemset(d_found, 0, nCrack * sizeof(bool));

    // lancia il kernel
    // numero di blocchi: (N + blockSize - 1) / blockSize
    // ogni thread cifra una password del dizionaio
    kernelCrack<<<(N + blockSize - 1) / blockSize, blockSize>>>(d_pwdList, N, d_pwdToCrack, nCrack, d_found, key);
    auto err = cudaGetLastError();
    if (err != cudaSuccess){
        printf("\n### %s: %s ###\n", cudaGetErrorName(err), cudaGetErrorString(err));
    }

    // copia i risultati indietro
    bool *found = new bool[nCrack];
    cudaMemcpy(found, d_found, nCrack * sizeof(bool), cudaMemcpyDeviceToHost);

    // libera la memoria GPU
    cudaFree(d_pwdList);
    cudaFree(d_pwdToCrack);
    cudaFree(d_found);

    return found;
}


// Kernel kernelCrack: ogni thread cifra una password e la confronta con quelle da crackare
__global__
void kernelCrack(const uint64_t *pwdList, int nPwd, const uint64_t *pwdToCrack, int nCrack, bool *found, uint64_t key) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;    // codice identificativo del thread
    // il dizionario ha N password
    if (tid < nPwd){
        // prende una password(pwdList[tid] e la cifra con DES (d_desEncrypt)
        uint64_t e = d_desEncrypt(key, pwdList[tid]);
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
uint64_t d_feistelFunction(const uint64_t subkey, const uint64_t bits){
    // Expansion
    uint64_t exp = d_permute<HALF_BLOCK, ROUND_KEY>(bits, d_expansion);

    // Key mixing
    uint64_t xored = subkey ^ exp;

    // Substitution
    exp = 0;
    for(int j = 8-1; j >= 0; j--){
        uint8_t block = (xored >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(d_hS[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    return d_permute<HALF_BLOCK, HALF_BLOCK>(exp, d_permutation);
}


// è la copia della versione CPU
__device__ //chiamabile solo da funzioni CUDA
uint64_t d_desEncrypt(uint64_t key56, const uint64_t message){
    // Initial permutation
    uint64_t ip = d_permute<BLOCK, BLOCK>(message, d_initialPerm);
    // Split in two halves
    uint32_t lhs = (ip >> HALF_BLOCK),
            rhs = ip;


    // Rounds, with subkey generation
    key56 = d_permute<BLOCK, 56>(key56, d_permutedChoice1);

    uint32_t lhs_rk = (key56 >> 28) & 0xfffffff;
    uint32_t rhs_rk = (key56) & 0xfffffff;

    for(int shift : d_keyShiftArray){

        lhs_rk = (lhs_rk << shift) | (lhs_rk >> (28 - shift));
        rhs_rk = (rhs_rk << shift) | (rhs_rk >> (28 - shift));
        lhs_rk &= 0xfffffff;
        rhs_rk &= 0xfffffff;

        uint64_t roundKey = (uint64_t(lhs_rk) << 28) | rhs_rk;

        roundKey = d_permute<56, ROUND_KEY>(roundKey, d_permutedChoice2);


        uint64_t feistel = d_feistelFunction(roundKey, rhs);

        auto old_lhs = lhs;
        lhs = rhs;
        rhs = old_lhs ^ feistel;

    }
    uint64_t res = (uint64_t(rhs) << HALF_BLOCK) | lhs;

    // Final permutation
    res = d_permute<BLOCK, BLOCK>(res, d_finalPerm);

    return res;
}