#ifndef __SOURCETEXT_H__
#define __SOURCETEXT_H__
#include <string>
using std::string;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;



#include <iostream>
#include <string>
using namespace std;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

string printHex(string &str){
	string encoded;
	encoded.clear();
	StringSource(str, true, 
			new HexEncoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printHex(CryptoPP::byte *str){
	string encoded;
	encoded.clear();
	StringSource(str, sizeof(str), true, 
			new HexEncoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printHex(SecByteBlock &str){
	string encoded;
	encoded.clear();
	StringSource(str, str.size(), true, 
			new HexEncoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printBase64(string &str){
	string encoded;
	encoded.clear();
	StringSource(str, true, 
			new Base64Encoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printBase64(CryptoPP::byte *str){
	string encoded;
	encoded.clear();
	StringSource(str, sizeof(str), true, 
			new Base64Encoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string printBase64(SecByteBlock &str){
	string encoded;
	encoded.clear();
	StringSource(str, str.size(), true, 
			new Base64Encoder(
				new StringSink(encoded)
			) // StreamTransformationFilter      
		);
	return encoded;
}

string hexDecode(string& str){
    string decoded;
    decoded.clear();
    StringSource(str, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

string Base64Decode(string& str){
    string decoded;
    decoded.clear();
    StringSource(str, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}

#endif