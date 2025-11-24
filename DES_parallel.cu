#include <iostream>
#include "DES_parallel.cuh"

// Costanti globabli su GPU: tabelle statiche DES
__constant__ int initialPerm_p[BLOCK];
__constant__ int finalPerm_p[BLOCK];
__constant__ int expansion_p[ROUND_KEY];
__constant__ int S1_p[BLOCK];
__constant__ int S2_p[BLOCK];
__constant__ int S3_p[BLOCK];
__constant__ int S4_p[BLOCK];
__constant__ int S5_p[BLOCK];
__constant__ int S6_p[BLOCK];
__constant__ int S7_p[BLOCK];
__constant__ int S8_p[BLOCK];
__constant__ int *S_p[8] = {
        S1_p, S2_p, S3_p, S4_p, S5_p, S6_p, S7_p, S8_p};
__constant__ int permutation_p[HALF_BLOCK];
__constant__ int permutedChoice1_p[56];
__constant__ int permutedChoice2_p[ROUND_KEY];
__constant__ int keyShiftArray_p[ROUNDS];

__host__
bool * parallelCrack(uint64_t *pwdList, int pwdNum, uint64_t *pwdToCrack, int numCrack, uint64_t key, int blockSize){

    // Copia le tabelle in constant memory
    cudaMemcpyToSymbol(initialPerm_p, constants::initialPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(finalPerm_p, constants::finalPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(expansion_p, constants::expansion, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(S1_p, constants::S1, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S2_p, constants::S2, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S3_p, constants::S3, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S4_p, constants::S4, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S5_p, constants::S5, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S6_p, constants::S6, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S7_p, constants::S7, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S8_p, constants::S8, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(permutation_p, constants::permutation, sizeof(int) * HALF_BLOCK);
    cudaMemcpyToSymbol(permutedChoice1_p, constants::permutedChoice1, sizeof(int) * 56);
    cudaMemcpyToSymbol(permutedChoice2_p, constants::permutedChoice2, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(keyShiftArray_p, constants::keyShiftArray, sizeof(int) * ROUNDS);

    // Alloca e copia i dati del dizionario, delle password target e found in memoria globale GPU
    uint64_t *pwdList_p, *pwdToCrack_p;

    cudaMalloc((void **)&pwdList_p, pwdNum * sizeof(uint64_t));
    cudaMemcpy(pwdList_p, pwdList, pwdNum * sizeof(uint64_t), cudaMemcpyHostToDevice);

    cudaMalloc((void **) &pwdToCrack_p, numCrack * sizeof(uint64_t));
    cudaMemcpy(pwdToCrack_p, pwdToCrack, numCrack * sizeof(uint64_t), cudaMemcpyHostToDevice);

    bool *found_p;
    cudaMalloc((void **) &found_p, numCrack * sizeof(bool));
    cudaMemset(found_p, 0, numCrack * sizeof(bool));

    kernelCrack<<<(pwdNum + blockSize - 1) / blockSize, blockSize>>>(pwdList_p, pwdNum, pwdToCrack_p, numCrack, found_p, key);

    cudaPeekAtLastError();
    cudaDeviceSynchronize();
    auto err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA launch error (code=%d): %s\n", (int)err,
                (cudaGetErrorString(err) ? cudaGetErrorString(err) : "cudaGetErrorString returned NULL"));
    }

    // Copia i risultati indietro
    bool *found = new bool[numCrack];
    cudaMemcpy(found, found_p, numCrack * sizeof(bool), cudaMemcpyDeviceToHost);
    // Libera la memoria GPU
    cudaFree(pwdList_p);
    cudaFree(pwdToCrack_p);
    cudaFree(found_p);

    return found;
}

__global__
void kernelCrack(const uint64_t *pwdList, int numPwd, const uint64_t *pwdToCrack, int numCrack, bool *found, uint64_t key) {
    // Calcolo dell'ID globale del thread
    int tid = blockIdx.x * blockDim.x + threadIdx.x;

    if (tid < numPwd){
        uint64_t e = desEncrypt_p(key, pwdList[tid]);
        for(int i = 0; i < numCrack; i++){
            if (!found[i] && e == pwdToCrack[i]){
                found[i] = true;
                // printf("Thread-%d found password %d\n", tid, i);
            }
        }
    }
}

__device__
uint64_t feistelFunction_p(const uint64_t subkey, const uint64_t right){
    uint64_t exp = permute_p<HALF_BLOCK, ROUND_KEY>(right, expansion_p);

    uint64_t xored = subkey ^ exp;

    exp = 0;
    for(int j = 8-1; j >= 0; j--){
        uint8_t block = (xored >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(S_p[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    return permute_p<HALF_BLOCK, HALF_BLOCK>(exp, permutation_p);
}


__device__
uint64_t desEncrypt_p(uint64_t key64, const uint64_t plaintext){
    uint64_t initialPermutation = permute_p<BLOCK, BLOCK>(plaintext, initialPerm_p);

    uint32_t left = (initialPermutation >> HALF_BLOCK),
            right = initialPermutation;

    uint64_t key56 = permute_p<BLOCK, 56>(key64, permutedChoice1_p);
    uint32_t leftRoundKey = (key56 >> 28) & 0xfffffff;
    uint32_t rightRoundKey = (key56) & 0xfffffff;

    for(int shift : keyShiftArray_p){

        leftRoundKey = (leftRoundKey << shift) | (leftRoundKey >> (28 - shift));
        rightRoundKey = (rightRoundKey << shift) | (rightRoundKey >> (28 - shift));
        leftRoundKey &= 0xfffffff;
        rightRoundKey &= 0xfffffff;

        uint64_t roundKey = (uint64_t(leftRoundKey) << 28) | rightRoundKey;

        roundKey = permute_p<56, ROUND_KEY>(roundKey, permutedChoice2_p);

        uint64_t feistel = feistelFunction_p(roundKey, right);

        auto old_left = left;
        left = right;
        right = old_left ^ feistel;

    }
    uint64_t result = (uint64_t(right) << HALF_BLOCK) | left;

    uint64_t ciphertext = permute_p<BLOCK, BLOCK>(result, finalPerm_p);

    return ciphertext;
}