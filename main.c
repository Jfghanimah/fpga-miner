/************************************************************************
Final Project Nios Software

Joseph Fares Ghanimah - jfg4
Madhavan Nair - mgnair2

************************************************************************/

#include <stdio.h>
#include <time.h>
#include "sha.h"

// Pointer to base address of AES module, make sure it matches Qsys
volatile unsigned int *SHA_PTR = (unsigned int *)0x00000200;

// Execution mode: 0 for testing, 1 for benchmarking
int run_mode = 0;
 

// These dont neeed to be functions
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

void pad_input(unsigned char *msg_ascii, unsigned int msg_length, unsigned int *msg_hash){
 /*
  // Pad Input
  unsigned char *processed_msg;
  unsigned int chunks = (msg_length + 1 + 8 + 63)/64;
  printf("chunk count: %d \n", chunks);
  processed_msg = (unsigned char*) malloc(64*chunks); //64 bytes or 512 bits per chunk

  // Fill msg over
  for (int i = 0; i < msg_length; i++)
	{
	  processed_msg[i] = msg_ascii[i];
	}

  processed_msg[msg_length] = 0x80; // fill the 1 byte

  // Add K zeros
  int K = (448 - 8*msg_length - 1) % 512;
  if (K < 0)
      K += 512;

  K-= 7; // 7 zeros in 0x80

  for (int i = 0; i < (K / 8); i++)
  {
    processed_msg[i + len + 1] = 0; // The zero bytes...
  }
    // Append the big-endian length of the message as a 64 bit big endian integer
  for (int i = 0; i < 8; i++)
  {
    processed_msg[blocks * 64 - 1 - i] = (unsigned char)(((uint64_t)size & (uint64_t)(0xff << i * 8)) >> 8 * i);
  }
  */
}


/** hash
 *  Perform SHA256 hash in software.
 *
 *  Input:  msg_ascii - Pointer to 32x 8-bit char array that contains the input message in ASCII format
 *  Output: msg_hash - Pointer to 8x 32-bit int array that contains the SHA256 hash message
 */
void software_hash(unsigned char *processed, unsigned int *msg_hash)
{
  
  int chunk_length = 2;

  //Initialize hash values:
  unsigned int H_t[8];
  for(int i=0; i<8; i++){
    H_t[i] = root_primes[i];
  }


  // For each 512 bit chunk
  for(int i=0; i < chunk_length; i++){
    // Schedule array
    unsigned int W[64] = {0};

    // copy chunk into first 16 words w[0..15] of the message schedule array
    for(int j=0; j<16; j++){
      W[j] =  (processed[4*j + 64*i] << 24) +
              (processed[4*j + 1 + 64*i] << 16) +
					    (processed[4*j + 2 + 64*i] << 8) +
					    (processed[4*j + 3 + 64*i]);
    }
    
    // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    for(int j=16; j<64; j++){
            W[j] = W[j-16] + 
            (RRIGHT(W[j-15],7)^RRIGHT(W[j-15],18)^(W[j-15]>>3)) + 
            W[j-7] +
            (RRIGHT(W[j-2],17)^RRIGHT(W[j-2],19)^(W[j-2]>>10));
    }

    // Initialize working variables to current hash value:
    unsigned int A, B, C, D, E, F, G, H, temp1, temp2;
    A = H_t[0];
    B = H_t[1];
    C = H_t[2];
    D = H_t[3];
    E = H_t[4];
    F = H_t[5];
    G = H_t[6];
    H = H_t[7];


    // Compression function main loop:
    for(int j=0; j<64; j++){
      temp1 = H + 
              (RRIGHT(E,6)^RRIGHT(E,11)^RRIGHT(E,25)) + 
              ((E&F)^(~E&G)) + 
              K_t[j] + W[j];

      temp2 = (RRIGHT(A,2)^RRIGHT(A,13)^RRIGHT(A,22)) + 
              ((A&B)^(A&C)^(B&C));

      H = G;
      G = F;
      F = E;
      E = D + temp1;
      D = C;
      C = B;
      B = A;
      A = temp1 + temp2;

    }

    // Add the compressed chunk to the current hash value:
    H_t[0] += A;
    H_t[1] += B;
    H_t[2] += C;
    H_t[3] += D;
    H_t[4] += E;
    H_t[5] += F;
    H_t[6] += G;
    H_t[7] += H;   

  }

  for (int i = 0; i < 8; i++)
	{
		msg_hash[i] = H_t[i];
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
  int x = 100;
  software_hash(msg_ascii, msg_hash);
  if (x>1)
    return;

  for(int i=0; i<32; i++){
	SHA_PTR[i] = msg_ascii[i];
  }

	SHA_PTR[63] = 1;

	while (SHA_PTR[64] == 0);

	msg_hash[0] = SHA_PTR[4]; //Twice to make sure we really get it
  for(int i=0; i<8; i++){
	  msg_hash[0] = SHA_PTR[32+i];
  }

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

	printf("Select execution mode: 0 for testing, 1 for benchmarking, 2 for demo: ");
	scanf("%d", &run_mode);

	if (run_mode == 0)
	{
		// Continuously Perform Hashes
		while (1)
		{
			printf("\nEnter Message:\n");
			scanf("%s", msg_ascii);
			printf("\n");

      // Calculate hash in software
			software_hash(msg_ascii, soft_hash);
			printf("\nSoftware Hash is: \n");
			for (int i = 0; i < 8; i++)
			{
				printf("%08X", soft_hash[i]);
			}
			printf("\n");

      // Now do it in hardware
			hardware_hash(msg_ascii, hard_hash);
			printf("\nHardware Hash is: \n");
			for (int i = 0; i < 8; i++)
			{
				printf("%08X", hard_hash[i]);
			}
			printf("\n");
		}
	}
	else if(run_mode == 1)
	{
		// Run the Benchmark
		int i = 0;
		int loops = 10;
		// Choose a random Plaintext and Key
		for (i = 0; i < 32; i++)
		{
			msg_ascii[i] = 'a';
		}
		// Run Soft
		clock_t begin = clock();
		for (i = 0; i < loops*100; i++)
		  software_hash(msg_ascii, soft_hash);
		clock_t end = clock();
		double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		double speed = loops / time_spent;
		printf("Software Hash Speed: %f H/s \n", speed);
		// Run Hard
		begin = clock();
		for (i = 0; i < loops ; i++)
			hardware_hash(msg_ascii, soft_hash);
		end = clock();
		time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		speed = loops / time_spent;
		printf("Hardware Hash Speed: %f H/s \n", speed);
	}
  else
  {
    //128 byte block = 1024 bits
    unsigned char block_header[128] = {
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b11100101, 0b11110101, 0b00100000, 0b01000100, 0b11111111, 0b10010010, 0b11011000, 0b10001000,
      0b00111101, 0b10111001, 0b00100111, 0b10110000, 0b01110010, 0b11110010, 0b01000101, 0b10011001,
      0b01101000, 0b10011101, 0b11110110, 0b11011111, 0b11110000, 0b11011101, 0b00011101, 0b00011110,
      0b11011110, 0b00000011, 0b10010110, 0b11111100, 0b00111010, 0b00110100, 0b11001100, 0b01101110,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b10000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000010, 0b00100000};


    unsigned char block_header2[128] = {
      0b00000000, 0b00000111, 0b01101100, 0b10100010, 0b00001000, 0b10011101, 0b01100100, 0b00001110,
      0b01011001, 0b01010001, 0b01001110, 0b10011011, 0b10011000, 0b11000011, 0b01011001, 0b00011001,
      0b01111011, 0b00011011, 0b01110010, 0b00110111, 0b01000100, 0b01110101, 0b11000010, 0b11010011,
      0b01010111, 0b01101011, 0b11000010, 0b11001100, 0b01011001, 0b11100000, 0b00000111, 0b11111000,
      0b10111000, 0b01011001, 0b11100111, 0b01011001, 0b01101001, 0b11011001, 0b00010011, 0b10100101,
      0b01100011, 0b10100000, 0b11101001, 0b10111100, 0b00011000, 0b10011000, 0b10110100, 0b01101010,
      0b11111110, 0b10101001, 0b01111000, 0b00110111, 0b10001100, 0b00011110, 0b11100101, 0b01010111,
      0b10111011, 0b10110110, 0b00111111, 0b00001001, 0b11100100, 0b00101011, 0b01010001, 0b01101011,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b10000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000,
      0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000000, 0b00000010, 0b00100000};

    unsigned int msg_hash[8]; //256 Bit hash
    unsigned int min_hash = 0xffffffff;
    unsigned int nonce = 0;
    unsigned int difficulty = 0x0000000f;


    printf("\n");
    printf("----------------------------------------------------------------\n");
    printf("Block #1 Header: \n");
    printf("PrevHash:");
    for (int i = 0; i < 32; i++)
				printf("%02x", block_header[i]);
     printf("\nMerkleRoot:");
    for (int i = 32; i < 64; i++)
				printf("%02x", block_header[i]);
    printf("\n");  printf("\n");
    printf("Current Mining Difficulty: %08x\n", difficulty);
    printf("Printing results every 100 Nonces\n");
    

    while(1){
      // Load the nonce into the block header
      block_header[64] = (nonce >> 24) & 0xFF;
      block_header[65] = (nonce >> 16) & 0xFF;
      block_header[66] = (nonce >> 8) & 0xFF;
      block_header[67] = nonce & 0xFF;
	  
      software_hash(block_header, msg_hash);
      //hardware_hash(block_header, msg_hash);

      if(msg_hash[0] < min_hash)
        min_hash = msg_hash[0];

      if(msg_hash[0] < difficulty){
        min_hash = msg_hash[0];
        break;
      }
      
      if(nonce % 100000 == 0)
	    	printf("    Nonce: %d Hash: %08x Progress: %08x\n", nonce,  msg_hash[0], min_hash);

      nonce++;
    }
		printf("Hash found using Nonce: %d Hex: %08x\n", nonce, nonce);
		for (int i = 0; i < 8; i++)
				printf("%08x", msg_hash[i]);
    printf("\n");

    printf("----------------------------------------------------------------\n");

    printf("\n");
    printf("Final Bitcoin Header Data For TA: \n");
    for (int i = 0; i < 68; i++)
				printf("%02x", block_header[i]);
    printf("\n");



    printf("\n");
    int block_2 = 0;
    printf("Calculate hash for Block #2 using next 8 transactions (0-No, 1-Yes)\n");
    scanf("%d", &block_2);

    if(block_2==0)
      return 0;

    min_hash = 0xffffffff;
    nonce = 0;

    printf("\n");
    printf("----------------------------------------------------------------\n");
    printf("Block #2 Header: \n");
    printf("PrevHash:");
    for (int i = 0; i < 32; i++)
				printf("%02x", block_header2[i]);
     printf("\nMerkleRoot:");
    for (int i = 32; i < 64; i++)
				printf("%02x", block_header2[i]);
    printf("\n");  printf("\n");
    printf("Current Mining Difficulty: %08x\n", difficulty);
    printf("Printing results every 100 Nonces\n");


    while(1){
      // Load the nonce into the block header
      block_header2[64] = (nonce >> 24) & 0xFF;
      block_header2[65] = (nonce >> 16) & 0xFF;
      block_header2[66] = (nonce >> 8) & 0xFF;
      block_header2[67] = nonce & 0xFF;
      software_hash(block_header2, msg_hash);

      if(msg_hash[0] < min_hash)
        min_hash = msg_hash[0];

      if(msg_hash[0] < difficulty){
        min_hash = msg_hash[0];
        break;
      }

      if(nonce % 100 == 0)
	    	printf("    Nonce: %d Hash: %08x Progress: %08x\n", nonce,  msg_hash[0], min_hash);
      nonce++;           
    }

		printf("Hash found using Nonce: %d Hex: %08x\n", nonce, nonce);
		for (int i = 0; i < 8; i++)
				printf("%08x", msg_hash[i]);
    printf("\n");

    printf("----------------------------------------------------------------\n");
    printf("\n");
    printf("Final Bitcoin Header Data For TA: \n");
    for (int i = 0; i < 68; i++)
				printf("%02x", block_header2[i]);
    printf("\n");


    printf("\n");
    printf("Calculate hash for Block #3 using next 8 transactions? (0-No, 1-Yes)\n");
    scanf("%d", &block_2);

  }
	return 0;
}
