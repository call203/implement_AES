/*
 Soyeon Lee
 D23125712
 TU059 ASD
 */
#include <stdlib.h>
#include <stdio.h>
#include "rijndael.h"

#define Nb 4  // Number of columns in the state
#define Nk 4  // Number of 32-bit words in the key
#define Nr 10 // Number of rounds

/*
 * S-box
 */
static unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const unsigned char inv_s_box[256] = {
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
unsigned char R[] = {0x02, 0x00, 0x00, 0x00};
/*
 * Operations used when encrypting a block
 */
/*
 * Galois Field (256) Multiplication of two bytes
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 * https://en.wikipedia.org/wiki/Rijndael_MixColumns
 */
unsigned char g_mult(unsigned char a, unsigned char b)
{

  unsigned char p = 0, i = 0, hbs = 0;

  for (i = 0; i < 8; i++)
  {
    if (b & 1)
    {
      p ^= a;
    }

    hbs = a & 0x80;
    a <<= 1;
    if (hbs)
      a ^= 0x1b;
    b >>= 1;
  }

  return p;
}
// calculates the values of the Rijndael key schedule Rcon
unsigned char *Rcon(unsigned char i)
{

  if (i == 1)
  {
    R[0] = 0x01;
  }
  else if (i > 1)
  {
    R[0] = 0x02;
    i--;
    while (i - 1 > 0)
    {
      R[0] = g_mult(R[0], 0x02);
      i--;
    }
  }

  return R;
}

// performs a Galois Field(GF) multiplication between two arrays(temp and m)
// operates on each byte individually and combines them using XOR operation
void gf_multiply(unsigned char *temp, unsigned char *res, unsigned char *m)
{

  res[0] = g_mult(temp[0], m[0]) ^ g_mult(temp[3], m[1]) ^ g_mult(temp[2], m[2]) ^ g_mult(temp[1], m[3]);
  res[1] = g_mult(temp[1], m[0]) ^ g_mult(temp[0], m[1]) ^ g_mult(temp[3], m[2]) ^ g_mult(temp[2], m[3]);
  res[2] = g_mult(temp[2], m[0]) ^ g_mult(temp[1], m[1]) ^ g_mult(temp[0], m[2]) ^ g_mult(temp[3], m[3]);
  res[3] = g_mult(temp[3], m[0]) ^ g_mult(temp[2], m[1]) ^ g_mult(temp[1], m[2]) ^ g_mult(temp[0], m[3]);
}

// iterates over each item of arrays and performs XOR
void coef_add(unsigned char *a, unsigned char *b, unsigned char *c)
{
  int i;
  for (i = 0; i < Nb; i++)
  {
    c[i] = a[i] ^ b[i];
  }
}

// pertforms byte substitution to bit
// replaces each byte in the substitution box
void sub_bytes(unsigned char *block)
{
  unsigned char i, j;
  unsigned char row, col;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      row = (block[Nb * i + j] & 0xf0) >> 4; // extracts the upper 4 bits
      col = block[Nb * i + j] & 0x0f;        // extracts the lower 4 bits
      block[Nb * i + j] = s_box[16 * row + col];
    }
  }
}

void shift_rows(unsigned char *block)
{
  unsigned int i, j, k, temp;

  // each row is shifted to the left by a varying number of bytes
  // Fist row: not shift
  // Second row: shift one byte
  // Third row: shift two byte ...
  for (i = 1; i < 4; i++)
  {
    j = 0;
    while (j < i)
    {
      temp = block[Nb * i + 0];
      for (k = 1; k < Nb; k++)
      {
        block[Nb * i + k - 1] = block[Nb * i + k];
      }
      block[Nb * i + Nb - 1] = temp;
      j++;
    }
  }
}

void mix_columns(unsigned char *block)
{

  unsigned int i, j;
  unsigned char temp[4], res[4];
  unsigned char m[] = {0x02, 0x01, 0x01, 0x03};

  // multiply each column by m in GF
  for (i = 0; i < Nb; i++)
  {
    for (j = 0; j < 4; j++)
    {
      temp[j] = block[Nb * j + i];
    }

    gf_multiply(temp, res, m);

    for (j = 0; j < 4; j++)
    {
      block[Nb * j + i] = res[j];
    }
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block)
{
  unsigned char i, j;
  unsigned char row, col;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      row = (block[Nb * i + j] & 0xf0) >> 4;
      col = block[Nb * i + j] & 0x0f;
      block[Nb * i + j] = inv_s_box[16 * row + col];
    }
  }
}

void invert_shift_rows(unsigned char *block)
{
  unsigned int i, j, k, temp;

  // rows are shifted right
  for (i = 1; i < 4; i++)
  {
    j = 0;
    while (j < i)
    {
      temp = block[Nb * i + Nb - 1];
      for (k = Nb - 1; k > 0; k--)
      {
        block[Nb * i + k] = block[Nb * i + k - 1];
      }
      block[Nb * i + 0] = temp;
      j++;
    }
  }
}

void invert_mix_columns(unsigned char *block)
{
  unsigned int i, j;
  unsigned char temp[4], res[4];
  unsigned char m[] = {0x0e, 0x09, 0x0d, 0x0b};

  for (i = 0; i < Nb; i++)
  {
    for (j = 0; j < 4; j++)
    {
      temp[j] = block[Nb * j + i];
    }

    gf_multiply(temp, res, m);

    for (j = 0; j < 4; j++)
    {
      block[Nb * j + i] = res[j];
    }
  }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key)
{

  int i, j;
  for (int i = 0; i < 4; i++)
  {
    for (int j = 0; j < Nb; j++)
    {
      block[Nb * j + i] ^= round_key[4 * i + j];
    }
  }
}

/*
 * cyclie permutation
 */
void rot_word(unsigned char *word)
{
  unsigned char temp = word[0];
  for (int i = 0; i < 3; i++)
  {
    word[i] = word[i + 1];
  }
  word[3] = temp;
}

/*
 * applies an s_box to each of the four btyes
 */
void sub_word(unsigned char *word)
{
  for (int i = 0; i < 4; i++)
  {
    word[i] = s_box[word[i]];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
void *expand_key(unsigned char *cipher_key, unsigned char *expanded_key)
{
  unsigned char temp[4];
  unsigned char i, j;

  // copy original key
  for (i = 0; i < Nk; i++)
  {
    expanded_key[4 * i + 0] = cipher_key[4 * i + 0];
    expanded_key[4 * i + 1] = cipher_key[4 * i + 1];
    expanded_key[4 * i + 2] = cipher_key[4 * i + 2];
    expanded_key[4 * i + 3] = cipher_key[4 * i + 3];
  }

  i = 4 * Nk;
  while (i < 4 * Nb * (Nr + 1)) // (Nr+1) : the total number of arounds
  {
    // taking the last column
    temp[0] = expanded_key[i - 4 + 0];
    temp[1] = expanded_key[i - 4 + 1];
    temp[2] = expanded_key[i - 4 + 2];
    temp[3] = expanded_key[i - 4 + 3];
    if (i / 4 % Nk == 0) // if the first column of each new round
    {
      rot_word(temp);
      sub_word(temp);
      coef_add(temp, Rcon(i / (Nk * 4)), temp); // Rcon: around constant
    }
    // XOR with the original key from first column to the end column
    expanded_key[i + 0] = expanded_key[i - 4 * Nk] ^ temp[0];
    expanded_key[i + 1] = expanded_key[i + 1 - 4 * Nk] ^ temp[1];
    expanded_key[i + 2] = expanded_key[i + 2 - 4 * Nk] ^ temp[2];
    expanded_key[i + 3] = expanded_key[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
// change a list to a 4 x 4 matrix
unsigned char *list2matrix(unsigned char *plaintext)
{
  int i, j;
  unsigned char *matrix = (unsigned char *)malloc(16 * sizeof(unsigned char));
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 4; j++)
    {
      matrix[4 * i + j] = plaintext[i + j * 4];
    }
  }
  return matrix;
}
// change a 4 x 4 matrix to a list
unsigned char *matrix2list(unsigned char *matrix)
{
  int i, j;
  unsigned char *plaintext = (unsigned char *)malloc(16 * sizeof(unsigned char));
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < Nb; j++)
    {
      plaintext[i + 4 * j] = matrix[Nb * i + j];
    }
  }
  return plaintext;
}

unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key)
{
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned char *block = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned int i, j, round;

  block = list2matrix(plaintext);
  add_round_key(block, key);

  for (round = 1; round < Nr; round++)
  {
    sub_bytes(block);
    shift_rows(block);
    mix_columns(block);
    add_round_key(block, key + round * 4 * Nb);
  }

  sub_bytes(block);
  shift_rows(block);
  add_round_key(block, key + Nr * 4 * Nb);

  output = matrix2list(block);
  free(block);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key)
{
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned char *block = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned int i, j, round;

  block = list2matrix(ciphertext);

  add_round_key(block, key + Nr * 4 * Nb);

  // starting from the second to the last
  // going backwards to the first around
  for (round = Nr - 1; round >= 1; round--)
  {
    invert_shift_rows(block);
    invert_sub_bytes(block);
    add_round_key(block, key + round * 4 * Nb);
    invert_mix_columns(block);
  }

  invert_shift_rows(block);
  invert_sub_bytes(block);
  add_round_key(block, key);

  output = matrix2list(block);

  free(block);
  return output;
}