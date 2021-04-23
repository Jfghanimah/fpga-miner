/************************************************************************
Final Project Nios Software

Joseph Fares Ghanimah - JFG4

************************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "sha.h"

// Pointer to base address of AES module, make sure it matches Qsys
volatile unsigned int *SHA_PTR = (unsigned int *)0x00000100;

// Execution mode: 0 for testing, 1 for benchmarking
int run_mode = 0;
 

// These dont neeed to be functions
#define RLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define RRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))


/** charToHex
 *  Convert a single character to the 4-bit value it represents.
 *  
 *  Input: a character c (e.g. 'A')
 *  Output: converted 4-bit value (e.g. 0xA)
 */
char charToHex(char c)
{
	char hex = c;

	if (hex >= '0' && hex <= '9')
		hex -= '0';
	else if (hex >= 'A' && hex <= 'F')
	{
		hex -= 'A';
		hex += 10;
	}
	else if (hex >= 'a' && hex <= 'f')
	{
		hex -= 'a';
		hex += 10;
	}
	return hex;
}

/** charsToHex
 *  Convert two characters to byte value it represents.
 *  Inputs must be 0-9, A-F, or a-f.
 *  
 *  Input: two characters c1 and c2 (e.g. 'A' and '7')
 *  Output: converted byte value (e.g. 0xA7)
 */
char charsToHex(char c1, char c2)
{
	char hex1 = charToHex(c1);
	char hex2 = charToHex(c2);
	return (hex1 << 4) + hex2;
}

/*
begin with the original message of length L bits
append a single '1' bit
append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
such that the bits in the message are L 1 00..<K 0's>..00 <L as 64 bit integer> = k*512 total bits
*/

void PadInput(unsigned char *msg_ascii, unsigned char *output){

}



/** hash
 *  Perform SHA256 hash in software.
 *
 *  Input:  msg_ascii - Pointer to 32x 8-bit char array that contains the input message in ASCII format
 *  Output: msg_hash - Pointer to 8x 32-bit int array that contains the SHA256 hash message
 */
void software_hash(unsigned char *msg_ascii, unsigned int *msg_hash)
{
  unsigned char space[64];

  PadInput(msg_ascii, space);

  unsigned char processed[64] = {
   0b01101000, 0b01100101, 0b01101100, 0b01101100, 0b01101111, 0b00100000, 0b01110111, 0b01101111,
   0b01110010, 0b01101100, 0b01100100, 0b10000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
   0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
   0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
   0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
   0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
   0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
   0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b01011000};


  // For each 512 bit chunk
  for(int i=0; i<1; i++){
    // Schedule array
    unsigned int W[64] = {0};

    // copy chunk into first 16 words w[0..15] of the message schedule array
    for(int j=0; j<16; j++){
      W[j] =  (processed[4*j] << 24) +
              (processed[4*j + 1] << 16) +
					    (processed[4*j + 2] << 8) +
					    (processed[4*j + 3]);
    }

    for (i = 0; i < 16; i++)
    {
      printf("%08x\n", W[i]);
    }
    
    for(int k=16; k<17; k++){
      
      printf("What\n");
      printf("%08x\n", W[k-16]);
      printf("%08x\n", RRIGHT(W[k-15],7) );
      printf("%08x\n", RRIGHT(W[k-15],18) );
      printf("%08x\n", RRIGHT(W[k-15],3) );
      printf("%08x\n", RRIGHT(W[k-15],7)^RRIGHT(W[k-15],18)^ W[k-15] >> 3);

      printf("%08x\n", W[k-7]);
      printf("%08x\n", RRIGHT(W[k-2],17)^RRIGHT(W[k-2],19)^W[k-2]>>10);


      W[k] = W[k-16] + 
            RRIGHT(W[k-15],7)^RRIGHT(W[k-15],18)^RRIGHT(W[k-15],3) + 
            W[k-7] +
            RRIGHT(W[k-2],17)^RRIGHT(W[k-2],19)^RRIGHT(W[k-2],10);
    }

    printf("\n");
    printf("%08x\n", W[15]);
    printf("%08x\n", W[16]);



  }

  for (int i = 0; i < 8; i++)
	{
		msg_hash[i] = 2*i;
	}
}

/** decrypt
 *  Perform SHA 256 hash in hardware.
 *
 *  Input:  msg_ascii - Pointer to 32x 8-bit char array that contains the input message in ASCII format
 *  Output: msg_hash - Pointer to 8x 32-bit int array that contains the SHA256 hash message
 */
void hardware_hash(unsigned char *msg_ascii, unsigned int *msg_hash)
{
	SHA_PTR[0] = msg_ascii[0];
	SHA_PTR[1] = msg_ascii[1];
	SHA_PTR[2] = msg_ascii[2];
	SHA_PTR[3] = msg_ascii[3];
	SHA_PTR[14] = 1;

	while (SHA_PTR[15] == 0);

	msg_hash[0] = SHA_PTR[4]; //Twice to make sure we really get it
	msg_hash[0] = SHA_PTR[4];
	msg_hash[1] = SHA_PTR[5];
	msg_hash[2] = SHA_PTR[6];
	msg_hash[3] = SHA_PTR[7];
  msg_hash[4] = SHA_PTR[8];
	msg_hash[5] = SHA_PTR[9];
	msg_hash[6] = SHA_PTR[10];
	msg_hash[7] = SHA_PTR[11];

	SHA_PTR[14] = 0;
	SHA_PTR[15] = 0;
}

/** main
 *  Allows the user to enter the message, key, and select execution mode
 *
 */
int main()
{
	// Input Message as 32x 8-bit ASCII Characters ([33] is for NULL terminator)
	unsigned char msg_ascii[33];
	// Software Hash, and Hardware Hash Message in 8x 32-bit Format to facilitate Read/Write to Hardware
	unsigned int soft_hash[8];
	unsigned int hard_hash[8];

	printf("Select execution mode: 0 for testing, 1 for benchmarking: ");
	scanf("%d", &run_mode);

	if (run_mode == 0)
	{
		// Continuously Perform Encryption and Decryption
		while (1)
		{
			int i = 0;
			printf("\nEnter Message:\n");
			scanf("%s", msg_ascii);
			printf("\n");

      // Calculate hash in software
			software_hash(msg_ascii, soft_hash);
			printf("\nSoftware Hash is: \n");
			for (i = 0; i < 8; i++)
			{
				printf("%08x", soft_hash[i]);
			}
			printf("\n");

      return 0;
      // Now do it in hardware
			hardware_hash(msg_ascii, soft_hash);
			printf("\nHardware Hash is: \n");
			for (i = 0; i < 8; i++)
			{
				printf("%08x", hard_hash[i]);
			}
			printf("\n");
		}
	}
	else
	{
		// Run the Benchmark
		int i = 0;
		int size_KB = 2;
		// Choose a random Plaintext and Key
		for (i = 0; i < 32; i++)
		{
			msg_ascii[i] = 'a';
		}
		// Run Encryption
		clock_t begin = clock();
		for (i = 0; i < size_KB * 64; i++)
		  software_hash(msg_ascii, soft_hash);
		clock_t end = clock();
		double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		double speed = size_KB / time_spent;
		printf("Software Encryption Speed: %f KB/s \n", speed);
		// Run Decryption
		begin = clock();
		for (i = 0; i < size_KB * 64; i++)
			hardware_hash(msg_ascii, soft_hash);
		end = clock();
		time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		speed = size_KB / time_spent;
		printf("Hardware Encryption Speed: %f KB/s \n", speed);
	}
	return 0;
}
