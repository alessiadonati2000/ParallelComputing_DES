#ifndef DES_DES_H
#define DES_DES_H
#include <cstdint>

/**
 * @brief Funzione generica per eseguire permutazioni richieste da DES.cpp
 * FROM: lunghezza blocco sorgente
 * TO:   lunghezza blocco risultante
 * table: array di indici che specifica come mappare i bit
 */
template<size_t FROM, size_t TO>
static auto permute(uint64_t source, const int* table) -> uint64_t {
    uint64_t p = 0;
    // Cicla su tutti i bit della tabella
    for (size_t i = 0; i < TO; i++)
        // Prende il bit corrispondente da source
            // Lo sposta nella posizione corretta di p
                p |= ((source >> (FROM - table[i])) & 1) << (TO - 1 - i);
    return p;
}

/**
 * @brief Funzione che implementa la funzione di Feistel
 */
uint64_t feistelFunction(uint64_t subkey, uint64_t right);

/**
 * @brief Funzione che implementa i 16 round dell'algoritmo DES
 */
uint64_t desEncrypt(uint64_t key64, uint64_t plaintext);

#endif //DES_DES_H