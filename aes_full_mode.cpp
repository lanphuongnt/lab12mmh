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
    
    // Generate KEY
    aes.key = generateBlock(aes.keySize, "KEY");

    if (aes.mode != "ECB"){
        // Generate iv
        aes.iv = generateBlock(aes.ivSize, "IV");
        aes.setIV(aes.iv, aes.ivSize);
    }

    // Decrypt or Encrypt
    int aescipher = selectEncryptOrDecrypt();

    switch(aescipher){
        case 1:{
            string plaintext, ciphertext, encoded;
            getData(plaintext, "PLAINTEXT");
            
            ciphertext = aes.encrypt(plaintext);

            printData(encodeOutput(ciphertext, "CIPHERTEXT"), "CIPHERTEXT");
            break;
        }
        case 2:{
            string ciphertext, decoded, plaintext;
            getData(ciphertext, "CIPHERTEXT");
            decoded = decodeInput(ciphertext, "CIPHERTEXT");
            plaintext = aes.decrypt(decoded);
            
            printData(plaintext,"PLAINTEXT");
            break;
        }
        default:{
            cout << "Invalid input" << endl;
            exit(0);
            break;
        }
    }
    return 0;
}