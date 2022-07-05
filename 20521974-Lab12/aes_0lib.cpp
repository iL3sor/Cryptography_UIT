#include <stdio.h>
#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;
#include <vector>
using std::vector;
#include <stdlib.h>
#include <string.h>
#include <string>
using std::string;
using std::wstring;
/* Set _setmode()*/
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;


// số cột trong ma trận state
#define Nb 4
// Số round trong chương trình (là 10 nếu mã hóa với key 128, là 12 với key 192, là 14 với key 256)
int Nr = 0;
// số word (32 bits) trong key ( sẽ bằng số bit key / 32)
int Nk = 0;
// in - mảng input
// out - mảng output
// state - mảng word 4x4
unsigned char in[1024], out[1024], state[4][Nb];
// mảng chứa round key (mỗi key gồm các word 32bits)
unsigned char RoundKey[240];
// mảng key và IV
unsigned char Key[32];
unsigned char IV[16];



int getSBoxValue(int num)
{
   int sbox[256] = {
       // 0     1     2     3     4     5     6     7
       // 8     9     A     B     C     D     E     F
       0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
       0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
       0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
       0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
       0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
       0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
       0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
       0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
       0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
       0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
       0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
       0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
       0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
       0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
       0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
       0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
       0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
       0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
       0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
       0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
       0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
       0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
       0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
       0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
       0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
       0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
       0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
       0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
       0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
       0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
       0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
       0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F
   return sbox[num];
}
int getInverseSBoxValue(int num)
{
   int sbox[256] = {
       0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
       0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
       0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
       0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
       0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
       0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
       0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
       0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
       0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
       0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
       0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
       0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
       0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
       0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
       0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
       0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
   return sbox[num];
}
// Mảng RCON [j] dùng trong mở rộng khóa
int Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
    0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d,
    0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
    0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
    0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
    0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
    0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
    0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83,
    0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
    0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3,
    0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};
// Hàm mở rộng khóa -> sinh ra Nb*Nr khóa vòng


void KeyExpansion()
{
   int i, j;
   unsigned char temp[4], k;
   // Khóa vòng đầu tiên cũng chính là khóa ta nhập vào
   for (i = 0; i < Nk; i++)
   {
      RoundKey[i * 4] = Key[i * 4];
      RoundKey[i * 4 + 1] = Key[i * 4 + 1];
      RoundKey[i * 4 + 2] = Key[i * 4 + 2];
      RoundKey[i * 4 + 3] = Key[i * 4 + 3];
   }
   // Các khóa vòng tiếp theo được tạo từ khóa vòng trước đó
   // Chạy một vòng lặp từ 4-> 43, chỉ các vị trí word mà modulo 4 == 0 thì mới phải cho chạy qua hàm G
   while (i < (Nb * (Nr + 1))) // vòng lặp qua các key
   {
      for (j = 0; j < 4; j++) // lấy cái round key đầu tiên để tính cho các round key sau
      {
         temp[j] = RoundKey[(i - 1) * 4 + j];
      }
      if (i % Nk == 0)
      {
         // Function RotWord() trong hàm G
         k = temp[0];
         temp[0] = temp[1];
         temp[1] = temp[2];
         temp[2] = temp[3];
         temp[3] = k;

         // Function Subword() trong hàm G
         temp[0] = getSBoxValue(temp[0]);
         temp[1] = getSBoxValue(temp[1]);
         temp[2] = getSBoxValue(temp[2]);
         temp[3] = getSBoxValue(temp[3]);

         // Xor với RCON trong hàm G
         temp[0] = temp[0] ^ Rcon[i / Nk];
      }
      else if (Nk > 6 && i % Nk == 4) // trường hợp số bits của key =256
      {
         // Function Subword()
         temp[0] = getSBoxValue(temp[0]);
         temp[1] = getSBoxValue(temp[1]);
         temp[2] = getSBoxValue(temp[2]);
         temp[3] = getSBoxValue(temp[3]);
      }
      // nếu không thì xor temp và key[i-4]
      RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
      RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
      RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
      RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
      i++;
   }
}

// Round key được thêm vào các vòng lặp bằng cách XOR
void AddRoundKey(int round)
{
   int i, j;
   for (i = 0; i < Nb; i++) // lặp qua số cột
   {
      for (j = 0; j < 4; j++) // lặp qua số hàng
      {
         state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j]; // lấy từ cái round key thứ round ra đúng vị trí để XOR
      }
   }
}


// Hàm subByte
void SubBytes()
{
   int i, j;
   for (i = 0; i < 4; i++)
   {
      for (j = 0; j < Nb; j++)
      {
         state[i][j] = getSBoxValue(state[i][j]); // lấy giá trị thay thế trong bảng S-Box
      }
   }
}
void inverse_subbyte()
{
   int i, j;
   for (i = 0; i < 4; i++)
   {
      for (j = 0; j < Nb; j++)
      {
         state[i][j] = getInverseSBoxValue(state[i][j]); // lấy giá trị thay thế trong bảng S-Box
      }
   }
}

// Hàm shift row
// Row 0 giữ nguyên
// row 1 shif1 1 bit to left
// row 2 shift 2 bits to left
// row 3 shift 3 bits to left
/*
   0 1 2 3
   1 2 3 0
   2 3 0 1
   3 0 1 2
*/
void ShiftRows()
{
   unsigned char temp;
   // Rotate first row 1 columns to left
   temp = state[1][0];
   state[1][0] = state[1][1];
   state[1][1] = state[1][2];
   state[1][2] = state[1][3];
   state[1][3] = temp;

   // Rotate second row 2 columns to left
   temp = state[2][0];
   state[2][0] = state[2][2];
   state[2][2] = temp;

   temp = state[2][1];
   state[2][1] = state[2][3];
   state[2][3] = temp;

   // Rotate third row 3 columns to left
   temp = state[3][0];
   state[3][0] = state[3][3];
   state[3][3] = state[3][2];
   state[3][2] = state[3][1];
   state[3][1] = temp;
}

void inverse_shiftrow()
{
   unsigned char temp;
   /*
   0 1 2 3          0 1 2 3
   1 2 3 0      =>  0 1 2 3
   2 3 0 1          0 1 2 3
   3 0 1 2          0 1 2 3
   */
   temp = state[1][0];
   state[1][0] = state[1][3];
   state[1][3] = state[1][2];
   state[1][2] = state[1][1];
   state[1][1] = temp;

   temp = state[2][0];
   state[2][0] = state[2][2];
   state[2][2] = temp;
   temp = state[2][1];
   state[2][1] = state[2][3];
   state[2][3] = temp;

   temp = state[3][0];
   state[3][0] = state[3][1];
   state[3][1] = state[3][2];
   state[3][2] = state[3][3];
   state[3][3] = temp;
}

//for multiply matrix in mixcolumn (copy code)
unsigned char multiply(unsigned char a, unsigned char b)
{
   if (b == 1)
      return a;
   if (b == 2)
   {
      unsigned char tmp = (a << 1) & 0xff; // quy luật @@
      if (a < 128)
         return tmp;
      else
         return tmp ^ 0x1b;
   }
   else
   {
      return multiply(a, 2) ^ a; // 3a = 2a + (xor) a
   }
}

//for multiply in reverse_mix column (copy code)
unsigned char inverse_multiply(unsigned char a, unsigned char b)
{
   if (b == 9)
      return multiply(multiply(multiply(a, 2), 2), 2) ^ a;
   else if (b == 11)
   {
      return multiply((multiply(multiply(a, 2), 2) ^ a), 2) ^ a;
   }
   else if (b == 13)
      return multiply(multiply(multiply(a, 2) ^ a, 2), 2) ^ a;
   else // if (b==14)
   {
      return multiply(multiply(multiply(a, 2) ^ a, 2) ^ a, 2);
   }
}

// MixColumns function mixes the columns of the state matrix
void MixColumns() // mix column được định nghĩa bằng phép nhân vs ma trận M
{
   /*
    Multiply state matrix with the matrix M

        | 2 3 1 1 |
    M = | 1 2 3 1 |
        | 1 1 2 3 |
        | 3 1 1 2 |
   */
   unsigned char temp[4][4]; // copy qua matrix phụ
   for (int i = 0; i < 4; i++)
   {
      for (int j = 0; j < 4; j++)
      {
         temp[i][j] = state[i][j];
      }
   }

   for (int i = 0; i < 4; i++)
   {
      unsigned char a = state[0][i];
      unsigned char b = state[1][i];
      unsigned char c = state[2][i];
      unsigned char d = state[3][i];
      temp[0][i] = multiply(a, 2) ^ multiply(b, 3) ^ multiply(c, 1) ^ multiply(d, 1);
      temp[1][i] = multiply(a, 1) ^ multiply(b, 2) ^ multiply(c, 3) ^ multiply(d, 1);
      temp[2][i] = multiply(a, 1) ^ multiply(b, 1) ^ multiply(c, 2) ^ multiply(d, 3);
      temp[3][i] = multiply(a, 3) ^ multiply(b, 1) ^ multiply(c, 1) ^ multiply(d, 2);
   }
   for (int i = 0; i < 4; i++)
   {
      for (int j = 0; j < 4; j++)
      {
         state[i][j] = temp[i][j];
      }
   }
}

void inverse_mixcolumn()
{
   /*
   Nhân state matrix với ma trận nghịch đảo của ma trận M (m^-1)
   | 14 11 13  9 |
   |  9 14 11 14 |
   | 13  9 14 11 |
   | 11 13  9 14 |
   */
   unsigned char temp[4][4]; // copy qua matrix phụ
   for (int i = 0; i < 4; i++)
   {
      for (int j = 0; j < 4; j++)
      {
         temp[i][j] = state[i][j];
      }
   }

   for (int i = 0; i < 4; i++)
   {
      unsigned char a = state[0][i];
      unsigned char b = state[1][i];
      unsigned char c = state[2][i];
      unsigned char d = state[3][i];
      temp[0][i] = inverse_multiply(a, 0x0e) ^ inverse_multiply(b, 0x0b) ^ inverse_multiply(c, 0x0d) ^ inverse_multiply(d, 0x09);
      temp[1][i] = inverse_multiply(a, 0x09) ^ inverse_multiply(b, 0x0e) ^ inverse_multiply(c, 0x0b) ^ inverse_multiply(d, 0x0d);
      temp[2][i] = inverse_multiply(a, 0x0d) ^ inverse_multiply(b, 0x09) ^ inverse_multiply(c, 0x0e) ^ inverse_multiply(d, 0x0b);
      temp[3][i] = inverse_multiply(a, 0x0b) ^ inverse_multiply(b, 0x0d) ^ inverse_multiply(c, 0x09) ^ inverse_multiply(d, 0x0e);
   }
   for (int i = 0; i < 4; i++)
   {
      for (int j = 0; j < 4; j++)
      {
         state[i][j] = temp[i][j];
      }
   }
}

// encrypt
void Cipher(unsigned char IV[16])
{
   int i, j, round = 0;

   // Chuyển input vào state matrix
   for (i = 0; i < Nb; i++)
   {
      for (j = 0; j < 4; j++)
      {
         state[j][i] = in[i * 4 + j] ^ IV[i * 4 + j];
      }
   }
   // Add the First round key to the state before starting the rounds.
   AddRoundKey(0);

   // There will be Nr rounds.
   // The first Nr-1 rounds are identical.
   // These Nr-1 rounds are executed in the loop below.
   for (round = 1; round < Nr; round++)
   {
      SubBytes();
      ShiftRows();
      MixColumns();
      AddRoundKey(round);
   }

   //vòng lặp cuối
   SubBytes();
   ShiftRows();
   AddRoundKey(Nr);

   //trả kq về mảng output
   for (i = 0; i < Nb; i++)
   {
      for (j = 0; j < 4; j++)
      {
         out[i * 4 + j] = state[j][i];
      }
   }
}
void Decipher(unsigned char IV[16])
{
   int i, j, round = 0;
   // copy sang state matrix
   for (i = 0; i < Nb; i++)
   {
      for (j = 0; j < 4; j++)
      {
         state[j][i] = in[i * 4 + j];
      }
   }
   // Add last roundkey 
   AddRoundKey(Nr);

   for (round = Nr - 1; round >= 1; round--)
   {
      inverse_shiftrow();
      inverse_subbyte();
      AddRoundKey(round);
      inverse_mixcolumn();
   }

   // vòng lặp cuối
   inverse_shiftrow();
   inverse_subbyte();
   AddRoundKey(0);

   // sau khi decipher thì copy sang ma trận output
   for (i = 0; i < Nb; i++)
   {
      for (j = 0; j < 4; j++)
      {
         out[i * 4 + j] = state[j][i] ^ IV[i * 4 + j]; // xor with IV
      }
   }
}



int instr_to_inarray(int index, string str, unsigned char *in)
{
   // chuyển bắt đầu từ vị trí index
   int j = 0;
   int temp = index;
   while (index < temp + 16)
   {
      in[j] = (unsigned char)str[index];
      index++;
      j++;
   }
   return index;
}
int instr_to_inarray2(int index, vector<unsigned char> cipherarr, unsigned char *in)
{
   // chuyển bắt đầu từ vị trí index
   int j = 0;
   int temp = index;
   while (index < temp + 16)
   {
      in[j] = (unsigned char)cipherarr[index];
      index++;
      j++;
   }
   return index;
}

void Padding(string &str) // padding '0' at the end of string
{
   int needtopad = 16 - (str.length() % 16);
   for (int i = 0; i < needtopad; i++)
   {
      str += " ";
   }
}

/* convert string to wstring */
wstring string_to_wstring(const std::string &str)
{
   wstring_convert<codecvt_utf8<wchar_t>> towstring;
   return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
   wstring_convert<codecvt_utf8<wchar_t>> tostring;
   return tostring.to_bytes(str);
}
wstring char_to_hexwstring(unsigned char a) // Print hex output from char byte
{
   char buffer[50];
   sprintf(buffer, "%02x", a);
   return string_to_wstring(string(buffer));
}
wstring Unpad(string &str)
{
   /*code unpad here */
   return string_to_wstring(str);
}

void AES_Enc()
{

   // Get the input string
   wstring wstr;
   wcout << "Nhap vao plaintext:  ";
   fflush(stdin);
   getline(wcin, wstr);
   string str = wstring_to_string(wstr);

   Padding(str);

   wcout << "Key: ";
   for (int i = 0; i < 4 * Nk; i++)
   {
      wcout << char_to_hexwstring(Key[i]);
   }
   wcout << endl;

   wcout << "IV: ";
   for (int i = 0; i < 16; i++)
   {
      wcout << char_to_hexwstring(IV[i]);
   }
   wcout << endl;
   // Mở rộng thành 44 khóa tương ứng
   KeyExpansion();

   int itera = 0;
   while (itera < int(str.length()))
   {
      itera = instr_to_inarray(itera, str, in);
      Cipher(IV); // với mỗi IV tính được thì mã hóa khúc string đó

      wcout << "Ciphertext Block " << itera / 16 << ": 0x";
      for (int i = 0; i < Nb * 4; i++)
      {
         wcout << char_to_hexwstring(out[i]);
         IV[i] = out[i]; // cập nhật iv = last ciphertext
      }
      wcout << endl;
   }
}

// decrypt
void AES_Dec()
{
   wcout << "Input ciphertext: ";
   wstring wcipher;
   fflush(stdin);
   getline(wcin, wcipher);
   string cipher = wstring_to_string(wcipher);

   std::vector<unsigned char> cipherarr;

   for (unsigned int i = 0; i < cipher.length(); i += 2)
   {
      string byteCiphertext = cipher.substr(i, 2);
      unsigned char byte = (unsigned char)strtol(byteCiphertext.c_str(), NULL, 16); //convert to byte from hex
      cipherarr.push_back(byte);
   }

   KeyExpansion(); // Expand Key
   wcout << "Key: ";
   for (int i = 0; i < 4 * Nk; i++)
   {
      wcout << char_to_hexwstring(Key[i]);
   }
   wcout << endl;

   wcout << "IV: ";
   for (int i = 0; i < 16; i++)
   {
      wcout << char_to_hexwstring(IV[i]);
   }
   wcout << endl;

   int index = 0;
   string plain = "";
   while (index < int(cipherarr.size())) 
   {
      string tmp = "";
      index = instr_to_inarray2(index, cipherarr, in);
      Decipher(IV);
      for (int i = 0; i < Nb * 4; i++)
      {
         IV[i] = in[i];
      }
      /*  Output the encrypted block.  */
      wcout << "Plaintext Block " << index / 16 << ": ";
      for (int i = 0; i < Nb * 4; i++)
      {

         tmp += out[i];
      }
      plain += tmp;
      wcout << string_to_wstring(tmp) << endl;
   }
   wcout<<"Plaintext:  "<<Unpad(plain);
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

   wcout << "Encrypt or Decrypt:    1. Encrypt    2.Decrypt   ";
   int choice;
   wcin >> choice;

   int keysize;
   wcout << "Nhap vao keysize: 1=128, 2=192, 3=256>\n";
   wcin >> keysize;
   switch (keysize)
   {
   case 1:
      Nk = 4;
      break;
   case 2:
      Nk = 6;
      break;
   case 3:
      Nk = 8;
      break;
   default:
      Nk = 4;
      break;
   }

   // Calculate Nr from Nk and, implicitly, from Nb
   Nr = Nk + 6;

   // The key values are placed here
   wcout << "input key: ";
   fflush(stdin);
   wstring wkey;
   wcin >> wkey;

   // input IV
   wcout << "Input IV: ";
   fflush(stdin);
   wstring wIV;
   wcin >> wIV;

   // convert to byte from  hex key
   string strkey;
   strkey = wstring_to_string(wkey);
   vector<char> keybyte;
   for (unsigned int i = 0; i < strkey.length(); i += 2)
   {
      string temp = strkey.substr(i, 2);                // split each 2 character
      char Byte = char(strtol(temp.c_str(), NULL, 16)); // convert to int from base16 and ép kiểu về char
      keybyte.push_back(Byte);
   }
   for (int i = 0; i < 4 * Nk; i++)
   {
      Key[i] = keybyte[i];
   }
   // convert to byte from  hex IV
   string striv;
   striv = wstring_to_string(wIV);
   vector<char> ivbyte;
   for (unsigned int i = 0; i < striv.length(); i += 2)
   {
      string temp = striv.substr(i, 2);                 // split each 2 character
      char Byte = char(strtol(temp.c_str(), NULL, 16)); // convert to int from base16 and ép kiểu về char
      ivbyte.push_back(Byte);
   }
   for (int i = 0; i < 4 * Nk; i++)
   {
      IV[i] = ivbyte[i];
   }
   switch (choice)
   {
   case 1:
   {
      AES_Enc();
      break;
   }
   case 2:
      AES_Dec();
   default:
      break;
   }
}
