// source file
#include "DES.h"
#include "utility.h"
using namespace constants;

uint64_t feistelFunction(uint64_t subkey, uint64_t bits){
    // Espansione (E-box)
    // bits è la metà destra del blocco (32 bit), viene espansa a 48 bit tramite la tabella expansion
    uint64_t exp = permute<HALF_BLOCK, ROUND_KEY>(bits, expansion);

    // XOR
    // fa lo XOR tra la subkey di questo round e i bit espansi
    subkey = subkey ^ exp;

    // Sostituzione (S-box)
    // i 48 bit vengono divisi in 8 blocchi da 6 bit
    // ogni blocco passa in una S-box, una tabella non lineare che restituisce 4 bit
    // viene ricostruito il blocco da 32 bit
    exp = 0;
    for(int j = 8-1; j >= 0; j--){
        uint8_t block = (subkey >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(hS[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    // Permutazione (P-box)
    // exp viene rimescolato secondo la tabella fissa permutation
    return permute<HALF_BLOCK, HALF_BLOCK>(exp, permutation);
}

uint64_t desEncrypt(uint64_t key56, uint64_t message){
    // Permutazione iniziale
    uint64_t ip = permute<BLOCK, BLOCK>(message, initialPerm);

    // Divido in due parti il testo (ciascuno da 32 bit)
    uint32_t lhs = (ip >> HALF_BLOCK),
             rhs = ip;

    // Preparazione della chiave
    // la chiave viene ridotta da 64 bit a 56 bit con permutedChoice1
    // e viene divisa un due parti da 28 bit
    key56 = permute<BLOCK, 56>(key56, permutedChoice1);
    uint32_t lhs_rk = (key56 >> 28) & 0xfffffff;
    uint32_t rhs_rk = (key56) & 0xfffffff;

    // Per ogni round (fino a 16)
    for(int shift : keyShiftArray){

        // ruota i 28 bit delle chiavi secondo lo schedule (keyShiftArray)
        lhs_rk = (lhs_rk << shift) | (lhs_rk >> (28 - shift));
        rhs_rk = (rhs_rk << shift) | (rhs_rk >> (28 - shift));
        lhs_rk &= 0xfffffff;
        rhs_rk &= 0xfffffff;
        uint64_t roundKey = (uint64_t(lhs_rk) << 28) | rhs_rk;
        // ricostruisce una chiave a 56 bit e la riduce a 48 bit con permutedChoice2
        roundKey = permute<56, ROUND_KEY>(roundKey, permutedChoice2);

        // calcola la funzione di Feistel su rhs
        uint64_t feistel = feistelFunction(roundKey, rhs);

        // aggiorna le due metà chiave con lo schema classico Feistel
        auto old_lhs = lhs;
        lhs = rhs;
        rhs = old_lhs ^ feistel;

    }

    // scambio le due metà
    message = (uint64_t(rhs) << HALF_BLOCK) | lhs;

    // permutazione finale
    ip = permute<BLOCK, BLOCK>(message, finalPerm);
    return ip; // testo cifrato a 64 bit
}
