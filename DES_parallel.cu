#include <iostream>
#include "DES_parallel.cuh"

// Costanti globabli su GPU: tabelle statiche DES
// calls to cudaMemcpyToSymbol() have to reside in the same file where the constant data is defined.
// vivono nella constant memory della GPU: memoria veloce (cache dedicata)
// ideale quando tutti i thread leggono gli stessi valori
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


// Funzione host (chiamata da CPU) parallelCrack: prepara i dati e lancia il kernel
__host__
bool * parallelCrack(uint64_t *pwdList, int pwdNum, uint64_t *pwdToCrack, int numCrack, uint64_t key, int blockSize){
    // copia le tabelle in constant memory, è molto veloce quando TUTTI i thread leggono gli stessi valori
    cudaMemcpyToSymbol(initialPerm_p, initialPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(finalPerm_p, finalPerm, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(expansion_p, expansion, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(S1_p, S1, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S2_p, S2, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S3_p, S3, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S4_p, S4, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S5_p, S5, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S6_p, S6, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S7_p, S7, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(S8_p, S8, sizeof(int) * BLOCK);
    cudaMemcpyToSymbol(permutation_p, permutation, sizeof(int) * HALF_BLOCK);
    cudaMemcpyToSymbol(permutedChoice1_p, permutedChoice1, sizeof(int) * 56);
    cudaMemcpyToSymbol(permutedChoice2_p, permutedChoice2, sizeof(int) * ROUND_KEY);
    cudaMemcpyToSymbol(keyShiftArray_p, keyShiftArray, sizeof(int) * ROUNDS);

    // alloca e copia i dati del dizionario e delle password target in memoria globale GPU
    uint64_t *pwdList_p, *pwdToCrack_p;
    bool *found_p;

    // dizionario
    cudaMalloc((void **) &pwdList_p, pwdNum * sizeof(uint64_t));
    cudaMemcpy(pwdList_p, pwdList, pwdNum * sizeof(uint64_t), cudaMemcpyHostToDevice);

    // testi cifrati
    cudaMalloc((void **) &pwdToCrack_p, numCrack * sizeof(uint64_t));
    cudaMemcpy(pwdToCrack_p, pwdToCrack, numCrack * sizeof(uint64_t), cudaMemcpyHostToDevice);

    // alloca array found su device (per marcare quali password sono state trovate
    cudaMalloc((void **) &found_p, numCrack * sizeof(bool));
    cudaMemset(found_p, 0, numCrack * sizeof(bool));

    // lancia il kernel
    // numero di blocchi: (N + blockSize - 1) / blockSize
    // ogni thread cifra una password del dizionaio e la confronta con tutti i target
    kernelCrack<<<(pwdNum + blockSize - 1) / blockSize, blockSize>>>(pwdList_p, pwdNum, pwdToCrack_p, numCrack, found_p, key);
    /*auto err = cudaGetLastError();
    if (err != cudaSuccess){
        printf("\n### %s: %s ###\n", cudaGetErrorName(err), cudaGetErrorString(err));
    }*/
    // Controllo immediato dell'errore di launch
    auto err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA launch error (code=%d): %s\n", (int)err,
                (cudaGetErrorString(err) ? cudaGetErrorString(err) : "cudaGetErrorString returned NULL"));
    }

    // Synchronize per catturare eventuali errori di runtime del kernel
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        fprintf(stderr, "CUDA runtime error after kernel (code=%d): %s\n", (int)err,
                (cudaGetErrorString(err) ? cudaGetErrorString(err) : "cudaGetErrorString returned NULL"));
    } else {
        fprintf(stdout, "Kernel completed successfully (synchronized)\n");
    }

    // copia i risultati indietro
    bool *found = (bool*)malloc(numCrack * sizeof(bool));
    cudaMemcpy(found, found_p, numCrack * sizeof(bool), cudaMemcpyDeviceToHost);
    // libera la memoria GPU
    cudaFree(pwdList_p);
    cudaFree(pwdToCrack_p);
    cudaFree(found_p);

    return found;
}


// Kernel kernelCrack: ogni thread cifra una password e la confronta con quelle da crackare
__global__
void kernelCrack(const uint64_t *pwdList, int pwdNum, const uint64_t *pwdToCrack, int numCrack, bool *found, uint64_t key) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;    // codice identificativo del thread
    // il dizionario ha N password
    if (tid < pwdNum){
        // prende una password(pwdList[tid] e la cifra con DES (d_desEncrypt)
        uint64_t pwdEncrypt = desEncrypt_p(key, pwdList[tid]);
        // Confronta con tutte le nCrack password target
        for(int i = 0; i < numCrack; i++){
            if (!found[i] && pwdEncrypt == pwdToCrack[i]){
                found[i] = true;    // ha trovato una corrispondenza
                //printf("Thread-%d found password %d\n", tid, i); //era commentato
            }
        }
    }
}

// Funzione device: implementazione DES e Feistel function su GPU
__device__
uint64_t feistelFunction_p(const uint64_t subkey, const uint64_t right){
    int numSBlock = 7;
    // Expansion
    uint64_t exp = permute_p<HALF_BLOCK, ROUND_KEY>(right, expansion_p);

    // Key mixing
    uint64_t xored = subkey ^ exp;

    // Substitution
    exp = 0;
    for(int j = numSBlock; j >= 0; j--){
        uint8_t block = (xored >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(S_p[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    return permute_p<HALF_BLOCK, HALF_BLOCK>(exp, permutation_p);
}


// è la copia della versione CPU
__device__ //chiamabile solo da funzioni CUDA
uint64_t desEncrypt_p(uint64_t key64, const uint64_t plaintext){
    // Initial permutation
    uint64_t initialPermutation = permute_p<BLOCK, BLOCK>(plaintext, initialPerm_p);
    // Split in two halves
    uint32_t left = (initialPermutation >> HALF_BLOCK),
            right = initialPermutation;


    // Rounds, with subkey generation
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

    // Final permutation
    uint64_t ciphertext = permute_p<BLOCK, BLOCK>(result, finalPerm_p);

    return ciphertext;
}