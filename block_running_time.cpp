//C internal library 
#include <iostream>
using std::endl;
using std::cout;
using std::cin;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;
#include "assert.h"

//Cryptopp Librari
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#endif

#include <chrono>
#include <locale>
#include <string>
using std::string;
#include <cstdlib>
using std::exit;
#include "assert.h"

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

using namespace std;
using namespace CryptoPP;

#include "mypackages/AES_Cipher.h"
#include "mypackages/convert.h"
#include "mypackages/userio.h"

int main(){
    #ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
    #endif
  
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
    
    // Select mode
    int modeSelection = selectMode();
    // Set mode
    AES_Cipher aes(modeSelection);

    while (true){
        int userChoice;
        cout << "What would you like to do?" << endl
             << "1. Generate KEY/IV" << endl
             << "2. Encrypt" << endl
             << "3. Decrypt" << endl
             << "4. Quit" << endl
             << "> ";
        cin >> userChoice;
        cin.ignore();
        switch (userChoice){
            case 1:{
                // Generate KEY
                aes.key = generateBlock(aes.keySize, "KEY");

                if (aes.mode != "ECB"){
                    // Generate iv
                    aes.iv = generateBlock(aes.ivSize, "IV");
                    aes.setIV(aes.iv, aes.ivSize);
                }
                break;
            }
            case 2:{
                if (aes.key == nullptr){
                    cout << "Please generate key before!" << endl;
                    break;
                }
                
                string plaintext, ciphertext, encoded;
                getData(plaintext, "PLAINTEXT");
                
                auto start = chrono::high_resolution_clock::now();
        
                for (int i = 0; i < 1000; ++i) {
                    ciphertext = aes.encrypt(plaintext);
                }

                auto end = chrono::high_resolution_clock::now();
                auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
                double averageTimeEncrypt = static_cast<double>(duration) / 1000.0;
                cout << "Average time for encryption over 1000 rounds of plaintext is " << averageTimeEncrypt << " ms" << endl;
                printData(encodeOutput(ciphertext, "CIPHERTEXT"), "CIPHERTEXT");
                break;
            }
            case 3:{
                if (aes.key == nullptr){
                    cout << "Please generate key before!" << endl;
                    break;
                }
                string ciphertext, decoded, plaintext;
                getData(ciphertext, "CIPHERTEXT");
                decoded = decodeInput(ciphertext, "CIPHERTEXT");
                auto start = chrono::high_resolution_clock::now();
        
                for (int i = 0; i < 1000; ++i) {
                    plaintext = aes.decrypt(decoded);
                }

                auto end = chrono::high_resolution_clock::now();
                auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
                double averageTimeDecrypt = static_cast<double>(duration) / 1000.0;
                cout << "Average time for decryption over 1000 rounds of ciphertext is " << averageTimeDecrypt << " ms" << endl;
                printData(plaintext, "PLAINTEXT");
                break;
            }
            case 4:{
                return cout << "Bye!" << endl, 0;
                break;
            }
            default:{
                cout << "Invalid input!" << endl;
                exit(0);
                break;
            }
        }
    }
    return 0;
}