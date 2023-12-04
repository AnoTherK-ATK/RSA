
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

#include "textProcess.h"
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

/* Convert string <--> utf8*/
#include <locale>
using std::wstring_convert;
#include <codecvt>

extern "C"
{
    __declspec(dllexport) void saveKey(const string& filename, const BufferedTransformation& bt);
    __declspec(dllexport) void savePubKey(const string& filename, const RSA::PublicKey& pubkey);
    __declspec(dllexport) void savePriKey(const string& filename, const RSA::PrivateKey& prikey);
    __declspec(dllexport) void loadKey(const string& filename, BufferedTransformation& bt);
    __declspec(dllexport) void loadPubKey(const string& filename, RSA::PublicKey& pubkey);
    __declspec(dllexport) void loadPriKey(const string& filename, RSA::PrivateKey& prikey);
    __declspec(dllexport) void randomkey(RSA::PrivateKey& privKey, RSA::PublicKey& pubKey);
    __declspec(dllexport) void encrypt(string& plain, string& cipher, RSA::PublicKey& pubKey);
    __declspec(dllexport) void decrypt(string& cipher, string& recovered, RSA::PrivateKey& privKey);
    __declspec(dllexport) string inputPlainMenu();
    __declspec(dllexport) string inputCipherMenu();
    __declspec(dllexport) void outputPlainMenu(string& plain);
    __declspec(dllexport) void outputCipherMenu(string& cipher);
    __declspec(dllexport) void publickeyFileMenu();
    __declspec(dllexport) void privatekeyFileMenu();
    __declspec(dllexport) void encMenu();
    __declspec(dllexport) void decMenu();
    __declspec(dllexport) void allMenu();
    __declspec(dllexport) void randomkeyMenu();
}

void saveKey(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void savePubKey(const string& filename, const RSA::PublicKey& pubkey)
{
    if (filename.find(".pem") != string::npos)
    {
        FileSink file((filename).c_str());
        PEM_Save(file, pubkey);
    }
    else
    {
        ByteQueue queue;
        pubkey.DEREncodePublicKey(queue);
        saveKey(filename, queue);
    }
}

void savePriKey(const string& filename, const RSA::PrivateKey& prikey)
{
    if (filename.find(".pem") != string::npos)
    {
        FileSink file((filename).c_str());
        PEM_Save(file, prikey);
    }
    else
    {
        ByteQueue queue;
        prikey.DEREncodePrivateKey(queue);
        saveKey(filename, queue);
    }
}

void loadKey(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void loadPubKey(const string& filename, RSA::PublicKey& pubkey)
{
    if (filename.find(".pem") != string::npos)
    {
        string str;
        FileSource file(filename.c_str(), true /*pumpAll*/);
        PEM_Load(file, pubkey);
        return;
    }
    else
    {
        ByteQueue queue;
        loadKey(filename, queue);
        pubkey.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
    }
}

void loadPriKey(const string& filename, RSA::PrivateKey& prikey)
{
    if (filename.find(".pem") != string::npos)
    {
        string str;
        FileSource file(filename.c_str(), true /*pumpAll*/);
        PEM_Load(file, prikey);
        return;
    }
    else
    {
        ByteQueue queue;
        loadKey(filename, queue);
        prikey.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
    }
}

AutoSeededRandomPool rng;
RSA::PrivateKey privateKey;
RSA::PublicKey publicKey;

void randomkey(RSA::PrivateKey& privKey, RSA::PublicKey& pubKey)
{
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 3072);
    RSA::PublicKey publicKey(privateKey);
    privKey = privateKey;
    pubKey = publicKey;
}

void encrypt(string& plain, string& cipher, RSA::PublicKey& pubKey)
{
    RSAES_OAEP_SHA256_Encryptor e(pubKey);

    StringSource(plain, true,
        new PK_EncryptorFilter(rng, e,
            new StringSink(cipher)) // PK_EncryptorFilter
    );                                                          // StringSource
}

void decrypt(string& cipher, string& recovered, RSA::PrivateKey& privKey)
{
    RSAES_OAEP_SHA256_Decryptor d(privKey);

    StringSource(cipher, true,
        new PK_DecryptorFilter(rng, d,
            new StringSink(recovered)) // PK_EncryptorFilter
    );                                                             // StringSource
}

string inputPlainMenu()
{
    cout << "Choose the input method:\n"
        << "1. From file;\n"
        << "2. From console;\n"
        << "Please enter your number?\n";
    int mode;
    cin >> mode;
    cin.ignore();
    switch (mode)
    {
    case 1:
    {
        string str;
        string filename;
        cout << "Please enter the plain text file name:\n";
        cin >> filename;
        FileSource(filename.c_str(), true, new StringSink(str));
        // wstring wstr = (str);
        // wcout << "plain text: " << wstr << endl;
        return str;
        break;
    }
    case 2:
    {
        cout << "Please enter the plain text:\n";
        // cin.ignore();
        string text;
        getline(cin, text);
        // wcin.ignore();
        cout << "plain text: " << text << endl;
        return text;
        break;
    }

    default:
    {
        cout << "Invalid input, Please try again\n";
        return inputPlainMenu();
        break;
    }
    }
}

string inputCipherMenu()
{
    cout << "Choose the input method:\n"
        << "1. From file;\n"
        << "2. From console;\n"
        << "Please enter your number?\n";
    int mode;
    cin >> mode;
    cin.ignore();
    switch (mode)
    {
    case 1:
    {
        string str;
        string filename;
        cout << "Please enter the ciphertext file name:\n";
        cin >> filename;
        FileSource(filename.c_str(), true, new StringSink(str));
        // wcout << "cipher text: " << filetext << endl;
        return str;
        break;
    }
    case 2:
    {
        cout << "Please enter the ciphertext (Base64):\n";
        // wcin.ignore();
        string text;
        cin >> text;
        cin.ignore();
        cout << "cipher text: " << text << endl;
        return text;
        break;
    }

    default:
    {
        cout << "Invalid input, Please try again\n";
        return inputCipherMenu();
        break;
    }
    }
}

void outputPlainMenu(string& plain)
{
    cout << "Choose the output method:\n"
        << "1. To file;\n"
        << "2. To console;\n"
        << "Please enter your number?\n";
    int mode;
    cin >> mode;
    cin.ignore();
    switch (mode)
    {
    case 1:
    {
        string filename;
        cout << "Please enter the plain text file name:\n";
        cin >> filename;
        StringSource(plain, true, new FileSink(filename.c_str(), false));
        break;
    }
    case 2:
    {
        cout << "plain text: " << plain << endl;
        break;
    }

    default:
    {
        cout << "Invalid input, Please try again\n";
        outputPlainMenu(plain);
        break;
    }
    }
}

void outputCipherMenu(string& cipher)
{
    cout << "Choose the output method:\n"
        << "1. To file;\n"
        << "2. To console;\n"
        << "Please enter your number?\n";
    int mode;
    cin >> mode;
    cin.ignore();
    switch (mode)
    {
    case 1:
    {
        string filename;
        cout << "Please enter the cipher text file name:\n";
        cin >> filename;
        StringSource(cipher, true, new FileSink(filename.c_str(), false));
        break;
    }
    case 2:
    {
        cout << "cipher text: " << cipher << endl;
        break;
    }

    default:
    {
        cout << "Invalid input, Please try again\n";
        outputCipherMenu(cipher);
        break;
    }
    }
}

void publickeyFileMenu()
{
    cout << "enter the filename of public key: ";
    string filename;
    getline(cin, filename);
    loadPubKey(filename, publicKey);
}

void privatekeyFileMenu()
{
    cout << "enter the filename of private key: ";
    string filename;
    getline(cin, filename);
    loadPriKey(filename, privateKey);
}

string plain, cipher, recovered;

void encMenu()
{
    publickeyFileMenu();
    plain = inputPlainMenu();
    encrypt(plain, cipher, publicKey);
    cipher = printBase64(cipher);
    outputCipherMenu(cipher);
}

void decMenu()
{
    privatekeyFileMenu();
    cipher = inputCipherMenu();
    cipher = Base64Decode(cipher);
    decrypt(cipher, recovered, privateKey);
    outputPlainMenu(recovered);
}

void randomkeyMenu()
{
    bool ok1 = false;
    bool ok2 = false;
    string filename;
    randomkey(privateKey, publicKey);
    while (!ok1)
    {
        cout << "enter the filename of public key: ";

        getline(cin, filename);
        if (filename.find(".pem") == string::npos && filename.find(".ber") == string::npos)
        {
            cout << "Please choose .pem or .ber file extension\n";
        }
        else
        {
            ok1 = 1;
        }
    }
    savePubKey(filename, publicKey);
    while (!ok2)
    {
        cout << "enter the filename of private key: ";
        getline(cin, filename);
        if (filename.find(".pem") == string::npos && filename.find(".ber") == string::npos)
        {
            cout << "Please choose .pem or .ber file extension\n";
        }
        else
        {
            ok2 = 1;
        }
    }
    savePriKey(filename, privateKey);
}

void allMenu() {
    cout << "1. generate keys" << endl
        << "2. encrypt" << endl
        << "3. decrypt" << endl;
    int choice;
    cin >> choice;
    cin.ignore();
    switch (choice)
    {
    case 1:
    {
        randomkeyMenu();
        break;
    }
    case 2:
    {
        encMenu();
        break;
    }
    case 3:
    {
        decMenu();
        break;
    }
    default:
    {
        break;
    }
    }
}

int main(int argc, char* argv[])
{
#ifdef __linux__
    std::locale::global(std::locale("C.UTF-8"));
#endif

#ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    allMenu();
    return 0;
}
