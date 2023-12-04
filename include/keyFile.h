#ifndef __KEYFILE_H__
#define __KEYFILE_H__

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
// phai xai sha256
using CryptoPP::RSAES_OAEP_SHA256_Decryptor;
using CryptoPP::RSAES_OAEP_SHA256_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/pem.h"
using CryptoPP::PEM_Load;
using CryptoPP::PEM_Save;

#include <assert.h>

void saveKey(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void savePubKey(const string &filename, const RSA::PublicKey &pubkey)
{
    ByteQueue queue;
    pubkey.DEREncodePublicKey(queue);
    saveKey(filename + ".ber", queue);
    FileSink file((filename + ".pem").c_str());
    PEM_Save(file, pubkey);
}

void savePriKey(const string &filename, const RSA::PrivateKey &prikey)
{
    ByteQueue queue;
    prikey.DEREncodePrivateKey(queue);
    saveKey(filename + ".ber", queue);
    FileSink file((filename + ".pem").c_str());
    PEM_Save(file, prikey);
}

void loadKey(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void loadPubKey(const string &filename, RSA::PublicKey &pubkey)
{
    if (filename.find(".pem") != string::npos)
    {
        string str;
        FileSource file(filename.c_str(), true /*pumpAll*/);
        PEM_Load(file, pubkey);
        return;
    }
    ByteQueue queue;
    loadKey(filename, queue);
    pubkey.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

void loadPriKey(const string &filename, RSA::PrivateKey &prikey)
{
    if (filename.find(".pem") != string::npos)
    {
        string str;
        FileSource file(filename.c_str(), true /*pumpAll*/);
        PEM_Load(file, prikey);
        return;
    }
    ByteQueue queue;
    loadKey(filename, queue);
    prikey.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

#endif