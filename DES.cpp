// source file
#include "DES.h"
#include "utility.h"
using namespace constants;

uint64_t feistelFunction(uint64_t subkey, uint64_t right){
    int numSBlock = 7;
    // Espansione (E-box)
    // bits è la metà destra del blocco (32 bit), viene espansa a 48 bit tramite la tabella expansion
    uint64_t exp = permute<HALF_BLOCK, ROUND_KEY>(right, expansion);

    // XOR
    // fa lo XOR tra la subkey di questo round e i bit espansi
    uint64_t xored = subkey ^ exp;

    // Sostituzione (S-box)
    // i 48 bit vengono divisi in 8 blocchi da 6 bit
    // ogni blocco passa in una S-box, una tabella non lineare che restituisce 4 bit
    // viene ricostruito il blocco da 32 bit
    exp = 0;
    for(int j = numSBlock; j >= 0; j--){
        uint8_t block = (xored >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(S[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    // Permutazione (P-box)
    // exp viene rimescolato secondo la tabella fissa permutation
    return permute<HALF_BLOCK, HALF_BLOCK>(exp, permutation);
}

uint64_t desEncrypt(uint64_t key64, uint64_t plaintext){
    // Permutazione iniziale
    uint64_t initialPermutation = permute<BLOCK, BLOCK>(plaintext, initialPerm);

    // Divido in due parti il testo (ciascuno da 32 bit)
    uint32_t left = (initialPermutation >> HALF_BLOCK),
             right = initialPermutation;

    // Preparazione della chiave
    // la chiave viene ridotta da 64 bit a 56 bit con permutedChoice1
    // e viene divisa un due parti da 28 bit
    uint64_t key56 = permute<BLOCK, 56>(key64, permutedChoice1);
    uint32_t leftRoundKey = (key56 >> 28) & 0xfffffff;
    uint32_t rightRoundKey = (key56) & 0xfffffff;

    // Per ogni round (fino a 16)
    for(int shift : keyShiftArray){
        // rotazione dei 28 bit
        leftRoundKey = (leftRoundKey << shift) | (leftRoundKey >> (28 - shift));
        rightRoundKey = (rightRoundKey << shift) | (rightRoundKey >> (28 - shift));

        // mascheratura a 28 bit, per essere sicuri che solo i primi 28 bit siano significativi
        leftRoundKey &= 0xfffffff;
        rightRoundKey &= 0xfffffff;

        // ricostruzione della chiave a 56 bit
        uint64_t roundKey = (uint64_t(leftRoundKey) << 28) | rightRoundKey;

        // Riduce a 48 bit con permutedChoice2
        roundKey = permute<56, ROUND_KEY>(roundKey, permutedChoice2);

        // calcola la funzione di Feistel su rhs
        uint64_t feistel = feistelFunction(roundKey, right);

        // aggiorna le due metà testo con lo schema classico Feistel
        auto old_left = left;
        left = right;
        right = old_left ^ feistel;

    }

    // scambio le due metà
    plaintext = (uint64_t(right) << HALF_BLOCK) | left;

    // permutazione finale
    uint64_t ciphertext = permute<BLOCK, BLOCK>(plaintext, finalPerm);
    return ciphertext; // testo cifrato a 64 bit
}
