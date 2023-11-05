#pragma once

#ifndef MY_AES_CIPHER_H
#define MY_AES_CIPHER_H
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

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

// Block cipher
#include "cryptopp/des.h"
using CryptoPP::DES;
#include "cryptopp/aes.h"
using CryptoPP::AES;

//Mode of operations
#include "cryptopp/modes.h" //ECB, CBC, CBC-CTS, CFB, OFB, CTR
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include <cryptopp/ccm.h>
using CryptoPP::CCM;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
//Ref: more here https://www.cryptopp.com/wiki/AEAD_Comparison


/* Set utf8 support for windows*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string <--> utf8*/ 
#include <locale>

using namespace std;
using namespace CryptoPP;

// #include "convert.h"
// #include "userio.h"
// #include "AES_Cipher.h"

class AES_Cipher{
public:
    CryptoPP::byte *key = nullptr;
    CryptoPP::byte *iv = nullptr;
    string mode;
    int keySize;
    int ivSize;
    AES_Cipher(int modeSelection);
    void setKey(CryptoPP::byte *_key, int _keySize);
    void setIV(CryptoPP::byte *_iv, int _ivSize);
    string encrypt(string plain);
    string decrypt(string cipher);
};

AES_Cipher::AES_Cipher(int modeSelection){
    AES_Cipher::keySize = AES::DEFAULT_KEYLENGTH, AES_Cipher::ivSize = AES::BLOCKSIZE;
    switch (modeSelection) {
        case 1: 
            AES_Cipher::mode = "ECB";
            AES_Cipher::ivSize = 0;
            break;
        case 2: 
            AES_Cipher::mode = "CBC";
            break;
        case 3: 
            AES_Cipher::mode = "OFB";
            break;
        case 4: 
            AES_Cipher::mode = "CFB";
            break;
        case 5: 
            AES_Cipher::mode = "CTR";
            break;
        case 6: 
            AES_Cipher::mode = "XTS";
            AES_Cipher::keySize = 32;
            break;
        case 7: 
            AES_Cipher::mode = "CCM";
            AES_Cipher::ivSize = 12;
            break;
        case 8: 
            AES_Cipher::mode = "GCM";
            break;
        default:
            cout << "Invalid input!" << endl;
            exit(0);
            break;
    }
}

void AES_Cipher::setKey(CryptoPP::byte *_key, int _keySize){
    AES_Cipher::key = _key;
    AES_Cipher::keySize = _keySize;
}

void AES_Cipher::setIV(CryptoPP::byte *_iv, int _ivSize){
    AES_Cipher::iv = _iv;
    AES_Cipher::ivSize = _ivSize;
}

string AES_Cipher::encrypt(string plain){
    string cipher;
    if (AES_Cipher::mode == "ECB"){ //ok
        ECB_Mode< AES >::Encryption e;
        e.SetKey(AES_Cipher::key, AES_Cipher::keySize);
        StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    else if (AES_Cipher::mode == "CBC"){//ok
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    else if (AES_Cipher::mode == "OFB"){//ok
        OFB_Mode< AES >::Encryption e;
        e.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    else if (AES_Cipher::mode == "CFB"){//ok
        CFB_Mode< AES >::Encryption e;
        e.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    else if (AES_Cipher::mode == "CTR"){
        CTR_Mode< AES >::Encryption e;
        e.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    else if (AES_Cipher::mode == "XTS"){// ok
        XTS< AES >::Encryption e;
        e.SetKeyWithIV(AES_Cipher::key, 32, iv );
        StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING)); // StringSource
    }
    else if (AES_Cipher::mode == "CCM"){
        const int TAG_SIZE = 8;
        CCM< AES, TAG_SIZE >::Encryption e;
        e.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv, 12);
        e.SpecifyDataLengths(0, plain.size(), 0);
        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher)));
    }
    else if (AES_Cipher::mode == "GCM"){//ok
        GCM< AES >::Encryption e;
        e.SetKeyWithIV( AES_Cipher::key, AES_Cipher::keySize, iv, AES_Cipher::ivSize);
        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher))); 
    }
    else {
        cout << "Error!";
        exit(0);
    }
    return cipher;
}
string AES_Cipher::decrypt(string cipher){
    string plain;
    if (AES_Cipher::mode == "ECB"){
        ECB_Mode< AES >::Decryption d;
        d.SetKey(AES_Cipher::key, AES_Cipher::keySize);
        StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));
    }
    else if (AES_Cipher::mode == "CBC"){
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));
    }
    else if (AES_Cipher::mode == "OFB"){
        OFB_Mode< AES >::Decryption d;
        d.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));
    }
    else if (AES_Cipher::mode == "CFB"){
        CFB_Mode< AES >::Decryption d;
        d.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));
    }
    else if (AES_Cipher::mode == "CTR"){
        CTR_Mode< AES >::Decryption d;
        d.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv);
        StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain)));
    }
    else if (AES_Cipher::mode == "XTS"){
        XTS< AES >::Decryption d;
        d.SetKeyWithIV(AES_Cipher::key, 32, iv );
        StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain), StreamTransformationFilter::NO_PADDING)); // StringSource
    }
    else if (AES_Cipher::mode == "CCM"){
        const int TAG_SIZE = 8;
        CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv, 12);
        d.SpecifyDataLengths(0, cipher.size() - TAG_SIZE, 0);
        AuthenticatedDecryptionFilter df(d, new StringSink(plain));
        StringSource s(cipher, true, new Redirector(df));
    }
    else if (AES_Cipher::mode == "GCM"){
        GCM< AES >::Decryption d;
        d.SetKeyWithIV(AES_Cipher::key, AES_Cipher::keySize, iv, AES_Cipher::ivSize);
        StringSource s(cipher, true, new AuthenticatedDecryptionFilter(d, new StringSink(plain)));
    }
    else {
        cout << "Error!";
        exit(0);
    }
    return plain;
}

#endif