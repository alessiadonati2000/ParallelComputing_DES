#ifndef DES_UTILS_H
#define DES_UTILS_H

#include <string>
#include <random>

#define BLOCK 64        // dimensione blocco in bit
#define HALF_BLOCK 32   // metà blocco
#define ROUND_KEY 48    // lunghezza subkey per round
#define ROUNDS 16       // numero di roud DES

using namespace std;
namespace constants
{
    // insieme di caratteri usato per generare le password casuali
    const char charSet[64] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                              'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                              'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '!'};

    // permutazione iniziale 64->64
    const int initialPerm[BLOCK] = {58, 50, 42, 34, 26, 18, 10, 2,
                                    60, 52, 44, 36, 28, 20, 12, 4,
                                    62, 54, 46, 38, 30, 22, 14, 6,
                                    64, 56, 48, 40, 32, 24, 16, 8,
                                    57, 49, 41, 33, 25, 17, 9, 1,
                                    59, 51, 43, 35, 27, 19, 11, 3,
                                    61, 53, 45, 37, 29, 21, 13, 5,
                                    63, 55, 47, 39, 31, 23, 15, 7};

    // permutazione finale 64->64
    const int finalPerm[BLOCK] = {40, 8, 48, 16, 56, 24, 64, 32,
                                  39, 7, 47, 15, 55, 23, 63, 31,
                                  38, 6, 46, 14, 54, 22, 62, 30,
                                  37, 5, 45, 13, 53, 21, 61, 29,
                                  36, 4, 44, 12, 52, 20, 60, 28,
                                  35, 3, 43, 11, 51, 19, 59, 27,
                                  34, 2, 42, 10, 50, 18, 58, 26,
                                  33, 1, 41, 9, 49, 17, 57, 25};

    // espansione 32->48 nella funzione Feistel
    const int expansion[ROUND_KEY] = {32, 1, 2, 3, 4, 5, 4, 5,
                                      6, 7, 8, 9, 8, 9, 10, 11,
                                      12, 13, 12, 13, 14, 15, 16, 17,
                                      16, 17, 18, 19, 20, 21, 20, 21,
                                      22, 23, 24, 25, 24, 25, 26, 27,
                                      28, 29, 28, 29, 30, 31, 32, 1};

    // 8 S-box (ciascuna prende 6 bit e restituisce 4)
    const int hS1[BLOCK] = {
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    };

    const int hS2[BLOCK] = {
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    };

    const int hS3[BLOCK] = {
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    };

    const int hS4[BLOCK] = {
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    };

    const int hS5[BLOCK] = {
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    };

    const int hS6[BLOCK] = {
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    };

    const int hS7[BLOCK] = {
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    };

    const int hS8[BLOCK] = {
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    };

    // array di puntatori per accedere velocemente alle S-box
    static const int *hS[8] = {
            hS1, hS2, hS3, hS4, hS5, hS6, hS7, hS8
    };

    // P-box, rimescola i 32 bit usciti dalle S-box
    const int permutation[HALF_BLOCK] = {16,  7, 20, 21,
                                         29, 12, 28, 17,
                                         1, 15, 23, 26,
                                         5, 18, 31, 10,
                                         2,  8, 24, 14,
                                         32, 27,  3,  9,
                                         19, 13, 30,  6,
                                         22, 11,  4, 25};

    // riduce la chiave da 64 a 56
    const int permutedChoice1[56] = {57, 49, 41, 33, 25, 17, 9,
                                     1, 58, 50, 42, 34, 26, 18,
                                     10, 2, 59, 51, 43, 35, 27,
                                     19, 11, 3, 60, 52, 44, 36,
                                     63, 55, 47, 39, 31, 23, 15,
                                     7, 62, 54, 46, 38, 30, 22,
                                     14, 6, 61, 53, 45, 37, 29,
                                     21, 13, 5, 28, 20, 12, 4};

    // riduce la chiave da 56 a 48
    const int permutedChoice2[ROUND_KEY] = {14, 17, 11, 24, 1, 5,
                                            3, 28, 15, 6, 21, 10,
                                            23, 19, 12, 4, 26, 8,
                                            16, 7, 27, 20, 13, 2,
                                            41, 52, 31, 37, 47, 55,
                                            30, 40, 51, 45, 33, 48,
                                            44, 49, 39, 56, 34, 53,
                                            46, 42, 50, 36, 29, 32};

    // definisce di quanti bit ruotare le chiavi a ogni round
    const int keyShiftArray[ROUNDS] = {1, 1, 2, 2, 2, 2, 2, 2,
                                       1, 2, 2, 2, 2, 2, 2, 1};

}

// Genera N parole casuali di lunghezza length
static vector<string> passwordsGeneration(int numPassword, int length){
    random_device rd;  // a seed source for the random number engine
    mt19937 gen(rd()); // mersenne_twister_engine seeded with rd()
    uniform_int_distribution<> distrib(0, 63);
    vector<string> passwords;
    for( int i = 0; i < numPassword; i++){
        string s;
        for(int j = 0; j < length; j++){
            s += constants::charSet[distrib(gen)];
        }
        passwords.push_back(s);
    }
    return passwords;
}

// Converte una stringa max 8 caratteri in un intero 64 bit
static uint64_t toUint64_T(const string &s){
    uint64_t result = 0;
    if (s.length() <= 8){
        for (int i = 0; i < s.length(); i++){
            result = result << 8 | s[i];
        }
    } else
        printf("String is too long, maximum 8 characters");

    return result;
}


template<typename T>
static string toString(const vector<T>& v) {
    string s = "[";
    for(int i = 0; i < v.size(); i++){
        s += to_string(v[i]);
        if (i < v.size() - 1)
            s += ", ";
        else
            s += "]";
    }
    return s;
}
#endif //DES_UTILS_H