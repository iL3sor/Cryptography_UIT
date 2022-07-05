#include <iostream>
using namespace std;
#include <sstream>

#include <string>
using std::string;
using std::wstring;
// convert string
#include <codecvt>
using std::codecvt_utf8;
wstring s2ws(const std::string &str);
string ws2s(const std::wstring &str);
string permutate(string input, int arr[], int n);
// set mode
#include <locale>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

// External library
#include <cryptopp/files.h>
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

// random number
#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

// Hex encode and decode
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
#include <cstdlib>
using std::exit;

// string method
#include <cryptopp/filters.h>
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

// RSA
#include "assert.h"
#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include <cryptopp/cryptlib.h>
using CryptoPP::DecodingResult;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;
using namespace CryptoPP;

// tính toán module
#include <cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;

/* convert string to wstring */
wstring s2ws(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}
/* convert wstring to string */
string ws2s(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
string integer_to_string(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;                       // pumb t to oss
    std::string encoded(oss.str()); // to string
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    wstring res = towstring.from_bytes(encoded); // string to wstring
    string result = ws2s(res);
    return result;
}
wstring integer_to_wstring(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;                       // pumb t to oss
    std::string encoded(oss.str()); // to string
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded); // string to wstring
}

void Save(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}
void SavePublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}
void SavePrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}
void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}
void LoadPublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);    
}
void Encode(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}
void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.DEREncodePrivateKey(queue);

	Encode(filename, queue);
}
void EncodePublicKey(const string& filename, const RSA::PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.DEREncodePublicKey(queue);

	Encode(filename, queue);
}

void Decode(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}
void DecodePrivateKey(const string& filename, RSA::PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Decode(filename, queue);
	key.BERDecodePrivateKey(queue, false /*optParams*/, queue.MaxRetrievable());
}
void DecodePublicKey(const string& filename, RSA::PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Decode(filename, queue);
	key.BERDecodePublicKey(queue, false /*optParams*/, queue.MaxRetrievable());
}

int main()
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif


    RSA::PrivateKey rsaPrivate, rsaPrivate2;
    RSA::PublicKey rsaPublic;

    wcout << "Encrypt or Decrypt   1.Encrypt   2.Decrypt   ";
    int ed;
    wcin >> ed;
    switch (ed)
    {
    case 1:
    {
        //Generate a large prime number p = 2q + - 1;
        AutoSeededRandomPool prng;
        Integer p, q, g;
        PrimeAndGenerator pg;
        pg.Generate(1, prng, 512, 511); // length p is 512 bits, q is 511 bits
        p = pg.Prime();
        q = pg.SubPrime();
        g = pg.Generator();

        wcout << L"RSA - CÓ HỖ TRỢ TIẾNG VIỆT" << endl;

        ////////////////////////////////////////////////////////////////////////////////////
        //rsaPrivate.GenerateRandomWithKeySize(prng, 3072);
        //RSA::PublicKey rsaPublic(rsaPrivate);

        DecodePrivateKey("rsa-private.key", rsaPrivate);
        DecodePublicKey("rsa-public.key", rsaPublic);

        //////////////////////////////////////////////////////////////////////////////////
        Integer modul = rsaPrivate.GetModulus();
        Integer prime1 = rsaPrivate.GetPrime1();
        Integer prime2 = rsaPrivate.GetPrime2();

        Integer SK = rsaPrivate.GetPrivateExponent();
        Integer PK = rsaPrivate.GetPublicExponent();

        RSA::PrivateKey privKey;
        privKey.Initialize(modul, PK, SK);

        RSA::PublicKey pubKey;
        pubKey.Initialize(modul, PK);
        /////////////////////////////////// TAKE PLAIN TEXT/////////////////////////////////////////////////
        wcout << L"Nguồn plaintext  1.Screen    2. File   ";
        int plainsource;
        wcin >> plainsource;
        wstring wname;  // file name
        string plain;   // string plaintext
        wstring wplain; // wstring plaintext
        switch (plainsource)
        {
        case 1:
        {
            // input message
            wcout << "Input message: ";
            fflush(stdin);
            getline(wcin, wplain);
            plain = ws2s(wplain);
            break;
        }
        case 2:
        {
            wcout << "Plaintext file name : " << endl;
            fflush(stdin);
            getline(wcin, wname);
            string fn = ws2s(wname);
            FileSource file(fn.c_str(), true, new StringSink(plain));
            wplain = s2ws(plain);
            break;
        }
        default:
            break;
        } // end choose plain source
          // Encryption
        string tmpcipher;
        RSAES_OAEP_SHA_Encryptor e(rsaPublic);
        StringSource(plain, true, new PK_EncryptorFilter(prng, e, new StringSink(tmpcipher)));
        string encode;
        encode.clear();
        StringSource(tmpcipher, true, new HexEncoder(new StringSink(encode)));
        StringSource(encode, true, new FileSink("RSA_cipher.txt"));
        wcout << L"Đã encrypt và lưu ciphertext vào RSA_cipher.txt" << endl;
        wcout << endl;
        wcout << "Hex Cipher --   " << s2ws(encode);
        break; // break encrypt
    }          // case 1 encrypt
    case 2:
    {
        DecodePrivateKey("rsa-private.key", rsaPrivate2);
        /////////////////////////////////// TAKE CIPHERTEXT/////////////////////////////////////////////////
        wcout << L"Nguồn Ciphertext  1.Screen    2. File   ";
        int ciphersource;
        wcin >> ciphersource;
        wstring wname;   // file name
        string decipher; // string ciphertext
        wstring wcipher; // wstring ciphertext
        switch (ciphersource)
        {
        case 1:
        {
            // input message
            wcout << "Input cipher: ";
            fflush(stdin);
            getline(wcin, wcipher);
            decipher = ws2s(wcipher);
            break;
        }
        case 2:
        {
            wcout << "Ciphertext file name :  ";
            fflush(stdin);
            getline(wcin, wname);
            string fn = ws2s(wname);
            FileSource file(fn.c_str(), true, new StringSink(decipher));
            break;
        }
        default:
            break;
        } // end choose cipher source

        // Generate keys
        AutoSeededRandomPool prng;

        // Decryption
        RSAES_OAEP_SHA_Decryptor d(rsaPrivate2);
        string decode, recovered;
        StringSource(decipher, true, new HexDecoder(new StringSink(decode)));
        StringSource(decode, true, new PK_DecryptorFilter(prng, d, new StringSink(recovered)));
        wcout << endl;
        wcout << "Recovered Text: " << s2ws(recovered) << endl;
        break; // break decrypt
    }          // end case 2 decrypt
    default:
        break;
    } // end en or de
}
