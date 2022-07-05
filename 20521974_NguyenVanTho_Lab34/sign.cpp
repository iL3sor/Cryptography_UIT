#include <iostream>
// using namespace std;
#include <sstream>

#include <string>
using std::string; // convert string
#include <codecvt>
using std::codecvt_utf8;
// set mode
#include <locale>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

// External library
#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

// random number
#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

// string method
#include <cryptopp/filters.h>
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

using namespace CryptoPP;

#include <cryptopp/eccrypto.h> //=======================>> LIBRARY FOR SIGN MESSAGE
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include <cryptopp/asn.h>
#include <cryptopp/oids.h> //
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

// Hex encode and decode
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

////////////////////////////////////////////////////////////



std::wstring s2ws(const std::string &str)
{
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}
/* convert wstring to string */
std::string ws2s(const std::wstring &str)
{
    std::wstring_convert<codecvt_utf8<wchar_t>> tostring;
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
    std::wcout<<"secp256r1"<<std::endl;
    AutoSeededRandomPool prng;
    int sign_or_verify;
    std::wcout << "Sign  or  Verify:   1.Sign   2.Verify  ";
    std::wcin >> sign_or_verify;
    switch (sign_or_verify)
    {
    case 1:
    {
        //..Get input message to sign
        std::wstring wfilename;
        std::wcout << "Message file name : " << std::endl;
        fflush(stdin);
        std::getline(std::wcin, wfilename);
        std::string sfilename = ws2s(wfilename);
        std::string plain;
        FileSource file(sfilename.c_str(), true, new StringSink(plain));
        std::wstring wplain;
        wplain = s2ws(plain);
        std::wcout << "Message: " << wplain << std::endl;

        // LoadPrivateKEy
        ECDSA<ECP, SHA256>::PrivateKey privKey;
        FileSource fs( "private.ec.der", true /*pump all*/ );
        privKey.Load( fs );
        // FileSink fs( "private.ec.der", true /*pump all*/ );
        // privKey.Save( fs );
        // ECDSA<ECP, SHA256>::PublicKey publicKey;
        // privKey.MakePublicKey(publicKey);
        // FileSink fs2( "public.ec.der", true /*binary*/ );
        // publicKey.Save( fs2 );

        // Sign message
        ECDSA<ECP, SHA256>::Signer signer(privKey);
        size_t siglen = signer.MaxSignatureLength();
        std::string signature(siglen, 0x00);
        siglen = signer.SignMessage(prng, (const byte *)&plain[0], plain.size(), (byte *)&signature[0]);
        signature.resize(siglen);

        StringSource(signature, true, new FileSink("signature.txt"));
        std::wcout << "Signed successfully!!"<<std::endl;
        std::wcout << "Signature is saved to 'signature.txt'"<<std::endl;
        break; // Break sign
    }
    case 2:
    {
        ECDSA<ECP, SHA256>::PublicKey publicKey;
        FileSource fs2( "public.ec.der", true /*pump all*/ );
        publicKey.Load( fs2 );
        ECDSA<ECP, SHA256>::Verifier verifier(publicKey);

        string signature;
        FileSource signfile("signature.txt", true, new StringSink(signature));

        //Load message to verify
        std::wstring wfilename;
        std::wcout << "Message file name : " << std::endl;
        fflush(stdin);
        std::getline(std::wcin, wfilename);
        std::string sfilename = ws2s(wfilename);
        std::string message;
        FileSource file(sfilename.c_str(), true, new StringSink(message));
        std::wstring wplain;
        wplain = s2ws(message);
        std::wcout << "Message: " << wplain << std::endl;

        //VERIFY
        bool result = verifier.VerifyMessage((const byte *)&message[0], message.size(), (const byte *)&signature[0], signature.size());
        // check if verification failure?
        if (!result)
        {
            std::wcout << "Failed to verify signature on message" << std::endl;
        }
        else
        {
            std::wcout << "All good!" << std::endl;
        }
        break; // Break Verify
    }
    default:
        break;
    }
}