#pragma once

#ifndef CONVERT_H
#define CONVERT_H
//C internal library 

#include <string>
using std::string;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;

using CryptoPP::byte;

// convert string
// Hex <---> Binary
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// Base64 <---> Binary
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

using namespace std;
using namespace CryptoPP;

#include "convert.h"

string base64encode(string decoded){
    string encoded;
    encoded.clear();
    StringSource(decoded, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded; 
}
string base64decode(string encoded){
    string decoded;
    decoded.clear();
    StringSource(encoded, true, new Base64Decoder(new StringSink(decoded)));
    return decoded; 
}
string hexencode(string decoded){
    string encoded;
    encoded.clear();
    StringSource(decoded, true, new HexEncoder(new StringSink(encoded), false));
    return encoded; 
}
string hexdecode(string encoded){
    string decoded;
    decoded.clear();
    StringSource(encoded, true, new HexDecoder(new StringSink(decoded)));
    return decoded; 
}

string base64encode(CryptoPP::byte decoded[], unsigned int size){
    string encoded;
    encoded.clear();
    StringSource(decoded, size, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded; 
}
string base64decode(CryptoPP::byte encoded[], unsigned int size){
    string decoded;
    decoded.clear();
    StringSource(encoded, size, true, new Base64Decoder(new StringSink(decoded)));
    return decoded; 
}
string hexencode(CryptoPP::byte decoded[], unsigned int size){
    string encoded;
    encoded.clear();
    StringSource(decoded, size, true, new HexEncoder(new StringSink(encoded), false));
    return encoded; 
}
string hexdecode(CryptoPP::byte encoded[], unsigned int size){
    string decoded;
    decoded.clear();
    StringSource(encoded, size, true, new HexDecoder(new StringSink(decoded)));
    return decoded; 
}

#endif