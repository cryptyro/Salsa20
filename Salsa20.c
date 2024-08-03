#include <stdint.h>  // Include the header file for standard integer types
#include <stdio.h>   // Include the header file for standard input and output operations
#include <string.h>  // Include the header file for string manipulation functions

// Implements DJB's definition of '<<<'
static uint32_t rotl(uint32_t value, int shift) {
	return (value << shift) | (value >> (32 - shift));  // Perform a left rotation operation on the input value
}

// Implements the quarterround operation
static void s20_quarterround(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3) {
	*y1 = *y1 ^ rotl(*y0 + *y3, 7);  // Apply the quarterround operation to y1
	*y2 = *y2 ^ rotl(*y1 + *y0, 9);  // Apply the quarterround operation to y2
	*y3 = *y3 ^ rotl(*y2 + *y1, 13); // Apply the quarterround operation to y3
	*y0 = *y0 ^ rotl(*y3 + *y2, 18); // Apply the quarterround operation to y0
}

// Applies the quarterround operation to each row of the state matrix
static void s20_rowround(uint32_t y[16]) {
	s20_quarterround(&y[0], &y[1], &y[2], &y[3]);     // Apply quarterround to the first row
	s20_quarterround(&y[5], &y[6], &y[7], &y[4]);     // Apply quarterround to the second row
	s20_quarterround(&y[10], &y[11], &y[8], &y[9]);   // Apply quarterround to the third row
	s20_quarterround(&y[15], &y[12], &y[13], &y[14]); // Apply quarterround to the fourth row
}

// Applies the quarterround operation to each column of the state matrix
static void s20_columnround(uint32_t x[16]) {
	s20_quarterround(&x[0], &x[4], &x[8], &x[12]);    // Apply quarterround to the first column
	s20_quarterround(&x[5], &x[9], &x[13], &x[1]);    // Apply quarterround to the second column
	s20_quarterround(&x[10], &x[14], &x[2], &x[6]);   // Apply quarterround to the third column
	s20_quarterround(&x[15], &x[3], &x[7], &x[11]);   // Apply quarterround to the fourth column
}

// Applies the column-round and row-round operations
static void s20_doubleround(uint32_t x[16]) {
	s20_columnround(x);  // Apply column-round operation
	s20_rowround(x);     // Apply row-round operation
}

// Creates a little-endian word from 4 bytes pointed to by b
static uint32_t s20_littleendian(uint8_t *b) {
	return b[0] +                                      // Extract the little-endian word from the bytes
	((uint_fast16_t) b[1] << 8) +               // Extract the little-endian word from the bytes
    ((uint_fast32_t) b[2] << 16) +              // Extract the little-endian word from the bytes
    ((uint_fast32_t) b[3] << 24);              // Extract the little-endian word from the bytes
}

// Moves the little-endian word into the 4 bytes pointed to by b
static void s20_rev_littleendian(uint8_t *b, uint32_t w) {
    b[0] = w;                                          // Store the little-endian word into bytes
    b[1] = w >> 8;                                     // Store the little-endian word into bytes
    b[2] = w >> 16;                                    // Store the little-endian word into bytes
    b[3] = w >> 24;                                    // Store the little-endian word into bytes
}

// The core function of Salsa20
static void s20_hash(uint8_t seq[64]) {
    int i;
    uint32_t x[16];
    uint32_t z[16];

    // Create two copies of the state in little-endian format
    // First copy is hashed together
    // Second copy is added to first, word-by-word
    for (i = 0; i < 16; ++i)
    	x[i] = z[i] = s20_littleendian(seq + (4 * i));

    for (i = 0; i < 10; ++i)
    	s20_doubleround(z);

    for (i = 0; i < 16; ++i) {
    	z[i] += x[i];
    	s20_rev_littleendian(seq + (4 * i), z[i]);
    }
}

// The 32-byte (256-bit) key expansion function
static void s20_expand32(uint8_t *k,
                         uint8_t n[16],
                         uint8_t keystream[64]) {
    int i, j;
    // The constants specified by the Salsa20 specification, 'sigma'
    // "expand 32-byte k"
    uint8_t o[4][4] = { { 'e', 'x', 'p', 'a' },
    					{ 'n', 'd', ' ', '3' },
    					{ '2', '-', 'b', 'y' },
    					{ 't', 'e', ' ', 'k' } };

  	// Copy all of 'sigma' into the correct spots in our keystream block
  	for (i = 0; i < 64; i += 20)
    	for (j = 0; j < 4; ++j)
    	  keystream[i + j] = o[i / 20][j];

  	// Copy the key and the nonce into the keystream block
  	for (i = 0; i < 16; ++i) {
    	keystream[4+i]  = k[i];
    	keystream[44+i] = k[i+16];
    	keystream[24+i] = n[i];
  	}

  	s20_hash(keystream);
}

// Performs up to 2^32-1 bytes of encryption or decryption under a
// 128- or 256-bit key and 64-byte nonce.
void s20_crypt(uint8_t *key,
               uint8_t nonce[8],
               uint32_t si,
               uint8_t *buf,
               uint32_t buflen) {
  	uint8_t keystream[64];
  	// 'n' is the 8-byte nonce (unique message number) concatenated
  	// with the per-block 'counter' value (4 bytes in our case, 8 bytes
  	// in the standard). We leave the high 4 bytes set to zero because
  	// we permit only a 32-bit integer for stream index and length.
  	uint8_t n[16] = { 0 };
  	uint32_t i;

  	// Set up the low 8 bytes of n with the unique message number
  	for (i = 0; i < 8; ++i)
    	n[i] = nonce[i];

  	// Walk over the plaintext byte-by-byte, xoring the keystream with
  	// the plaintext and producing new keystream blocks as needed
  	for (i = 0; i < buflen; ++i) {
    // If we've used up our entire keystream block (or have just begun
    // and happen to be on a block boundary), produce keystream block
    	if ((i) % 64 == 0) {
    	  	s20_rev_littleendian(n+8, ((i) / 64));  // Set up the counter part of the nonce
      		s20_expand32(key, n, keystream);        // Expand the key and nonce to generate keystream
    	}

    // xor one byte of plaintext with one byte of keystream
    	buf[i] ^= keystream[(si + i) % 64];       // XOR operation between plaintext and keystream
  	}
}

int main() {
  	uint8_t key[32]= {8,0,0,0,0,0,0,0,          // Initialize the key with all zero bytes
					  0,0,0,0,0,0,0,0,
                 	  0,0,0,0,0,0,0,0,
                 	  0,0,0,0,0,0,0,0};
  	uint8_t nonce[8]={0,0,0,0,0,0,0,0};        // Initialize the nonce with all zero bytes
  	uint32_t si=0;                               // Initialize the stream index to zero
  	char Str[1000];                              // Define a character array to store user input
  	printf("Enter your message: ");              // Prompt the user to enter a message
  	scanf("%1000[^\n]", Str);                    // Read the message from the user
  	const uint32_t bufflen= strlen(Str);         // Determine the length of the message
  	uint8_t buff[bufflen];                       // Define a byte array to store the message
  	for (int i = 0; i < bufflen; i++)
    	buff[i] = (uint8_t)Str[i];                 // Convert the characters of the message to bytes
  //Encrypt
  	s20_crypt(key, nonce, si, buff, bufflen);    // Encrypt the message using Salsa20 algorithm
  	printf("Encrypted message: ");
  	for (int i = 0; i < bufflen; i++)
    	printf("%u ", buff[i]);                  // Print the encrypted message byte by byte

   	//Decrypt
  	s20_crypt(key, nonce, si, buff, bufflen);    // Decrypt the message using Salsa20 algorithm
  	printf("\nDecrypted message: ");
  	for (int i = 0; i < bufflen; i++)
       printf("%c", buff[i]);                   // Print the decrypted message character by character
   	printf("\n");
   	return 0;                                    // Exit the program
}
