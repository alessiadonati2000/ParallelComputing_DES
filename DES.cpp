#include "DES.h"
#include "utility.h"

uint64_t feistelFunction(uint64_t subkey, uint64_t right){
    // Espansione (E-box)
    uint64_t exp = permute<HALF_BLOCK, ROUND_KEY>(right, constants::expansion);

    // XOR
    uint64_t xored = subkey ^ exp;

    // Sostituzione (S-box)
    exp = 0;
    for(int j = 8-1; j >= 0; j--){
        uint8_t block = (xored >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(constants::S[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    // Permutazione (P-box)
    return permute<HALF_BLOCK, HALF_BLOCK>(exp, constants::permutation);
}

uint64_t desEncrypt(uint64_t key64, uint64_t plaintext){
    // Permutazione iniziale
    uint64_t initialPermutation = permute<BLOCK, BLOCK>(plaintext, constants::initialPerm);

    // Divido in due parti il testo (ciascuno da 32 bit)
    uint32_t left = (initialPermutation >> HALF_BLOCK),
             right = initialPermutation;

    // Preparazione della chiave
    uint64_t key56 = permute<BLOCK, 56>(key64, constants::permutedChoice1);
    uint32_t leftRoundKey = (key56 >> 28) & 0xfffffff;
    uint32_t rightRoundKey = (key56) & 0xfffffff;

    // Per ogni round (fino a 16)
    for(int shift : constants::keyShiftArray){
        // Rotazione dei 28 bit
        leftRoundKey = (leftRoundKey << shift) | (leftRoundKey >> (28 - shift));
        rightRoundKey = (rightRoundKey << shift) | (rightRoundKey >> (28 - shift));

        // Mascheratura a 28 bit, per essere sicuri che solo i primi 28 bit siano significativi
        leftRoundKey &= 0xfffffff;
        rightRoundKey &= 0xfffffff;

        // Ricostruzione della chiave a 56 bit
        uint64_t roundKey = (uint64_t(leftRoundKey) << 28) | rightRoundKey;

        // Riduce a 48 bit con permutedChoice2
        roundKey = permute<56, ROUND_KEY>(roundKey, constants::permutedChoice2);

        // Calcola la funzione di Feistel su right
        uint64_t feistel = feistelFunction(roundKey, right);

        // Aggiorna le due metà testo con lo schema Feistel
        auto old_left = left;
        left = right;
        right = old_left ^ feistel;

    }

    // Scambio le due metà
    plaintext = (uint64_t(right) << HALF_BLOCK) | left;

    // Permutazione finale
    uint64_t ciphertext = permute<BLOCK, BLOCK>(plaintext, constants::finalPerm);

    return ciphertext; // testo cifrato a 64 bit
}
