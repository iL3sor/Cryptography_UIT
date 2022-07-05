#include <iostream>
using namespace std;

#include <string>
using std::string;
using std::wstring;

// convert string

#include <locale>
using std::wstring;

#include <codecvt>
using std::codecvt_utf8;
wstring s2ws(const std::string &str);
string ws2s(const std::wstring &str);
string permutate(string input, int arr[], int n);

// set mode
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

// base64 encode and decode
#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

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
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

// aes
#include <cryptopp/aes.h>
using CryptoPP::AES;
// aes

#include <cryptopp/des.h>
using CryptoPP::DES;

#include "cryptopp/modes.h" //ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM.
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
#include "cryptopp/xts.h"
using CryptoPP::XTS;
#include "cryptopp/gcm.h"
using CryptoPP::GCM;
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
// comparision
#include "assert.h"

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

int main()
{
#ifdef __linux__
    setlocale(LC_ALL, "");
#elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
#else
#endif

    int scheme;
    wcout << "Select scheme: 1.AES  2>DES" << endl;
    wcin >> scheme;

    switch (scheme)
    {
    case 1:
    {
        int mode;
        wcout << "Select mode: 1.ECB, 2.CBC, 3.OFB, 4.CFB, 5.CTR, 6.XTS, 7.CCM, 8.GCM.\n";
        wcin >> mode;
        switch (mode)
        {
        case 1:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        ECB_Mode<AES>::Encryption e;
                        e.SetKey(key, sizeof(key));
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        ECB_Mode<AES>::Encryption e;
                        e.SetKey(key, sizeof(key));
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        ECB_Mode<AES>::Encryption e;
                        e.SetKey(key, sizeof(key));
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            ECB_Mode<AES>::Decryption d;
                            d.SetKey(dekey, sizeof(dekey));
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            ECB_Mode<AES>::Decryption d;
                            d.SetKey(dekey, sizeof(dekey));
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            ECB_Mode<AES>::Decryption d;
                            d.SetKey(key, sizeof(key));
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            ECB_Mode<AES>::Decryption d;
                            d.SetKey(key, sizeof(key));
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }

        // CBC mode
        case 2:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CBC_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CBC_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CBC_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CBC_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CBC_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CBC_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CBC_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }

        // OFB mode
        case 3:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        OFB_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        OFB_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        OFB_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            OFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            OFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            OFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            OFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        // CFB mode
        case 4:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CFB_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CFB_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CFB_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CFB_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        // CTR MODE
        case 5:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CTR_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CTR_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CTR_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CTR_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CTR_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CTR_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CTR_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        // xts MODE
        case 6:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        XTS_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        XTS_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        XTS_Mode<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            XTS_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            XTS_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            XTS_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            XTS_Mode<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        case 7:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CCM<AES, 12>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        e.SpecifyDataLengths(0, plain.size(), 0);
                        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e,
                                                                                      new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CCM<AES, 12>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        e.SpecifyDataLengths(0, plain.size(), 0);
                        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e,
                                                                                      new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CCM<AES, 12>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        e.SpecifyDataLengths(0, plain.size(), 0);
                        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e,
                                                                                      new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CCM<AES, 12>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            d.SpecifyDataLengths(0, decipher.size() - 12, 0);
                            StringSource s(decipher, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CCM<AES, 12>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            d.SpecifyDataLengths(0, decipher.size() - 12, 0);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CCM<AES, 12>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            d.SpecifyDataLengths(0, decipher.size() - 12, 0);
                            StringSource s(decipher, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CCM<AES, 12>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            d.SpecifyDataLengths(0, decipher.size() - 12, 0);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        case 8:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[32], fkey[32];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("AES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("AES_IV.key"));

                    // reading key from file
                    FileSource fs("AES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "AES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        GCM<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e,
                                                                                      new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        GCM<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e,
                                                                                      new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        GCM<AES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new AuthenticatedEncryptionFilter(e,
                                                                                      new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("AES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[32];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[AES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            GCM<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            GCM<AES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[AES::BLOCKSIZE];
                    CryptoPP::byte key[32];

                    FileSource fs("AES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("AES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            GCM<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("AES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            GCM<AES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new AuthenticatedDecryptionFilter(d,
                                                                             new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        default:
            break;
        }
        break;
    }

    // DES
    case 2:
    {
        int mode;
        wcout << "Select mode: 1.ECB, 2.CBC, 3.OFB, 4.CFB, 5.CTR.\n";
        wcin >> mode;
        switch (mode)
        {
        case 1:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH], fkey[DES::DEFAULT_KEYLENGTH];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("DES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("DES_IV.key"));

                    // reading key from file
                    FileSource fs("DES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "DES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        ECB_Mode<DES>::Encryption e;
                        e.SetKey(key, sizeof(key));
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        ECB_Mode<DES>::Encryption e;
                        e.SetKey(key, sizeof(key));
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        ECB_Mode<DES>::Encryption e;
                        e.SetKey(key, sizeof(key));
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[DES::DEFAULT_KEYLENGTH];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[DES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            ECB_Mode<DES>::Decryption d;
                            d.SetKey(dekey, sizeof(dekey));
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            ECB_Mode<DES>::Decryption d;
                            d.SetKey(dekey, sizeof(dekey));
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            ECB_Mode<DES>::Decryption d;
                            d.SetKey(key, sizeof(key));
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            ECB_Mode<DES>::Decryption d;
                            d.SetKey(key, sizeof(key));
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }

        // CBC mode
        case 2:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH], fkey[DES::DEFAULT_KEYLENGTH];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("DES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("DES_IV.key"));

                    // reading key from file
                    FileSource fs("DES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "DES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CBC_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CBC_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CBC_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[DES::DEFAULT_KEYLENGTH];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[DES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CBC_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CBC_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CBC_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CBC_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }

        // OFB mode
        case 3:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH], fkey[DES::DEFAULT_KEYLENGTH];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("DES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("DES_IV.key"));

                    // reading key from file
                    FileSource fs("DES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "DES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        OFB_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        OFB_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        OFB_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[DES::DEFAULT_KEYLENGTH];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[DES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            OFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            OFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            OFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            OFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        // CFB mode
        case 4:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH], fkey[DES::DEFAULT_KEYLENGTH];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("DES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("DES_IV.key"));

                    // reading key from file
                    FileSource fs("DES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "DES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CFB_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CFB_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CFB_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[DES::DEFAULT_KEYLENGTH];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[DES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CFB_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }
        // CTR MODE
        case 5:
        {
            int ed;
            wcout << "Encrypt or Decrypt: 1. Encrypt  2.Decrypt" << endl;
            wcin >> ed;
            switch (ed)
            {
            case 1:
            {
                wcout << "Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
                int ikv;
                wcin >> ikv;
                switch (ikv)
                {
                case 1:
                {
                    AutoSeededRandomPool prng;
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH], fkey[DES::DEFAULT_KEYLENGTH];

                    // create random key
                    prng.GenerateBlock(fkey, sizeof(fkey));
                    StringSource ss(fkey, sizeof(fkey), true, new HexEncoder(new FileSink("DES_key.key")));

                    // IV generation
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    prng.GenerateBlock(iv, sizeof(iv));
                    StringSource(iv, sizeof(iv), true, new FileSink("DES_IV.key"));

                    // reading key from file
                    FileSource fs("DES_key.key", false);
                    // create space for key
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    // copy key from "DES_key.key to key"
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key)); // Pump first 32 bytes

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));

                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;

                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CTR_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];
                    wcout << "Key input (hex): ";
                    wstring wskey;
                    fflush(stdin);
                    getline(wcin, wskey);
                    string skey = ws2s(wskey);
                    StringSource(skey, true, new HexDecoder(new CryptoPP::ArraySink(key, sizeof(key))));
                    wcout << "IV input (hex): ";
                    wstring wiv;
                    fflush(stdin);
                    getline(wcin, wiv);
                    string siv = ws2s(wiv);
                    StringSource(siv, true, new HexDecoder(new CryptoPP::ArraySink(iv, sizeof(iv))));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CTR_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 3:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));

                    wstring wplain;
                    wstring wname;
                    string plain;

                    int cplain;
                    wcout << "Chon nguon plaintext 1.Screen  2. File" << endl;
                    wcin >> cplain;
                    switch (cplain)
                    {
                    case 1: // Screen
                    {
                        wcout << "Input plaintext : " << endl;
                        fflush(stdin);
                        getline(wcin, wplain);
                        plain = ws2s(wplain);
                        break;
                    }
                    case 2: // File
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
                    }
                    // encrypt
                    string ecipher, encoded;

                    encoded.clear();
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "key: " << s2ws(encoded) << endl;

                    /* Pretty print iv */
                    encoded.clear();
                    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(encoded)));
                    wcout << "IV: " << s2ws(encoded) << endl;
                    // print input before encrypt it
                    wcout << "Plaintext: " << wplain << endl;
                    try
                    {
                        CTR_Mode<DES>::Encryption e;
                        e.SetKeyWithIV(key, sizeof(key), iv);
                        StringSource s(plain, true, new StreamTransformationFilter(e,
                                                                                   new StringSink(ecipher)) // StreamTransformationFilter
                        );
                        // Print result
                        encoded.clear();
                        StringSource(ecipher, true,
                                     new Base64Encoder(
                                         new StringSink(encoded)) // Base4Encode
                        );                                        // StringSource
                    }
                    catch (const CryptoPP::Exception &e)
                    {
                        cerr << e.what() << endl;
                        exit(1);
                    }
                    int ressource;
                    wcout << "Ghi ket qua vao:  1.Screen  2.File" << endl;
                    wcin >> ressource;
                    switch (ressource)
                    {
                    case 1:
                    {
                        wcout << "Ciphertext: " << s2ws(encoded) << endl; // StringSource
                        break;
                    }
                    case 2:
                    {
                        StringSource(encoded, true, new FileSink("DES_encrypt.txt"));
                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                default:
                    break;
                }
            default:
                break;
            }
            case 2:
            {
                wcout << "Chon nguon key va IV:  1.Screen   2.File" << endl;
                int kiv;
                wcin >> kiv;
                switch (kiv)
                {
                case 1:
                {
                    wstring whexkey;
                    string hexkey, sdekey;
                    wcout << "Input key : ";
                    fflush(stdin);
                    getline(wcin, whexkey);
                    hexkey = ws2s(whexkey);
                    // decode hexstring key
                    StringSource(hexkey, true, new HexDecoder(new StringSink(sdekey)));
                    // convert from string key to byte
                    CryptoPP::byte dekey[DES::DEFAULT_KEYLENGTH];
                    StringSource(sdekey, true, new ArraySink(dekey, sizeof(dekey)));

                    wstring whexiv;
                    string hexiv, sdeiv;
                    wcout << "Input IV : ";
                    fflush(stdin);
                    getline(wcin, whexiv);
                    hexiv = ws2s(whexiv);
                    // decode hexstring key
                    StringSource(hexiv, true, new HexDecoder(new StringSink(sdeiv)));
                    // convert from string key to byte
                    CryptoPP::byte deiv[DES::BLOCKSIZE];
                    StringSource(sdeiv, true, new ArraySink(deiv, sizeof(deiv)));

                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CTR_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CTR_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(dekey, sizeof(dekey), deiv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;
                }
                case 2:
                {
                    CryptoPP::byte iv[DES::BLOCKSIZE];
                    CryptoPP::byte key[DES::DEFAULT_KEYLENGTH];

                    FileSource fs("DES_key.key", false);
                    CryptoPP::ArraySink copykey(key, sizeof(key));
                    fs.Detach(new Redirector(copykey));
                    fs.Pump(sizeof(key));
                    FileSource fss("DES_IV.key", false);
                    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
                    fss.Detach(new Redirector(copyiv));
                    fss.Pump(sizeof(iv));
                    // Ciphertext input
                    wcout << "Chon nguon ciphertext: 1.Screen   2.file" << endl;
                    int cp;
                    wcin >> cp;
                    wcin.ignore();
                    switch (cp)
                    {
                    case 1:
                    {
                        wcout << "Input cipher Based64: ";
                        wstring wb64cipher;
                        string decipher;
                        fflush(stdin);
                        getline(wcin, wb64cipher);
                        StringSource(ws2s(wb64cipher), true, new Base64Decoder(new StringSink(decipher)));
                        string recovered;
                        try
                        {
                            CTR_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            StringSource s(decipher, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));

                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    case 2:
                    {
                        string decipher;
                        FileSource fs("DES_encrypt.txt", true, new StringSink(decipher));
                        string b64outstring;
                        StringSource(decipher, true, new Base64Decoder(new StringSink(b64outstring)));
                        try
                        {
                            CTR_Mode<DES>::Decryption d;
                            d.SetKeyWithIV(key, sizeof(key), iv);
                            string recovered;
                            StringSource s(b64outstring, true,
                                           new StreamTransformationFilter(d,
                                                                          new StringSink(recovered)));
                            int outres;
                            wcout << "How to output result: 1.Screen   2. File" << endl;
                            wcin >> outres;
                            switch (outres)
                            {
                            case 1:
                                wcout << "recovered text: " << s2ws(recovered) << endl;
                                break;
                            case 2:
                            {
                                StringSource(recovered, true, new FileSink("recovered.txt"));
                                break;
                            }
                            default:
                                break;
                            }
                        }
                        catch (const CryptoPP::Exception &e)
                        {
                            cerr << e.what() << endl;
                            exit(1);
                        }

                        break;
                    }
                    default:
                        break;
                    }
                    break;

                    break;
                }
                default:
                    break;
                }

                break;
            }
            }
            break;
        }

        default:
            break;
        }
        break;
    }
    default:
        break;
    }
}