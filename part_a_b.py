import os
import math

class AES(object):

	# Structure of supported modes of operation
	modes = dict(CFB=0, CBC=1, OFB=2)

	# S-box
	sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
			0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
			0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
			0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
			0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
			0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
			0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
			0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
			0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
			0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
			0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
			0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
			0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
			0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
			0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
			0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
			0xb0, 0x54, 0xbb, 0x16]

	# Inverted S-box
	inv_sbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
				0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
				0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
				0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
				0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68,
				0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
				0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8,
				0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
				0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
				0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
				0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
				0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
				0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
				0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33,
				0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
				0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
				0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
				0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
				0x55, 0x21, 0x0c, 0x7d]

	# RCON
	rcon = [0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
			0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
			0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
			0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
			0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
			0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
			0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
			0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
			0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
			0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
			0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
			0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
			0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
			0xe8, 0xcb]

	# Retrieves a gIVectoren S-Box Value
	def getSBox(self, num):
		return self.sbox[num]

	# Retrieves a gIVectoren Inverted S-Box Value
	def getInvSbox(self, num):
		return self.inv_sbox[num]

	# XOR operation left and right side
	def xor(self, left, right):
		return left ^ right

	# Key schedule core
	def core(self, word, iteration):
		# Rotate the 32-bit word 8 bits to the left
		# Key schedule rotate operation.
		# Rotate a word eight bits to the left
		word = word[1:] + word[:1]

		# Apply S-Box substitution on all 4 parts of the 32-bit word
		for i in range(4):
		    word[i] = self.getSBox(word[i])

		# XOR the output of the rcon operation with i to the first part (leftmost) only
		# Retrieves a gIVectoren rcon Value
		word[0] = self.xor(word[0], self.rcon[iteration])

		return word

	# Key expansion.
	def keyExpand(self, key, expandedkeySize):
		size = 16
		currentSize = 0
		iterationRcon = 1
		expandedKey = expandedkeySize * [0]

		# Set the 16 bytes of the expanded key to the input key
		for j in range(size):
			expandedKey[j] = key[j]

		currentSize += size

		while(currentSize < expandedkeySize):
			# Assign the previous 4 bytes to the temporary value temp
			temp = expandedKey[currentSize-4 : currentSize]

			# Every 16 bytes we apply the core schedule to temp and increment iterationRcon afterwards
			if(currentSize % size == 0):
				temp = self.core(temp, iterationRcon)
				iterationRcon += 1

			# We XOR temp with the four-byte block 16 bytes before the new expanded key.  This becomes the next four bytes in the expanded key.
			for m in range(4):
				expandedKey[currentSize] = self.xor(expandedKey[currentSize - size], temp[m])
				currentSize += 1

		return expandedKey

	# Substitute all the values from the st with the value in the SBox using the st value as index for the SBox
	def bytesSubst(self, st, isInv):
		if (isInv == True):
			getter = self.getInvSbox

		else:
			getter = self.getSBox

		for i in range(16):
			st[i] = getter(st[i])

		return st

	# Iterate over the 4 rows and call shiftRow() with that row
	def shiftRows(self, st, isInv):
		for i in range(4):
			stPointer = i * 4
			nbr = i

			# Each iteration shifts the row to the left by 1
			for i in range(nbr):
				if(isInv == True):
					st[stPointer:stPointer+4] = st[stPointer+3:stPointer+4] + st[stPointer:stPointer+3]
				else:
					st[stPointer:stPointer+4] = st[stPointer+1:stPointer+4] + st[stPointer:stPointer+1]

		return st

	# Multiplication of 8 bit characters left and right.
	def multiple(self, left, right):
		p = 0

		for counter in range(8):

			if(right & 1):
				p = self.xor(p, left)

			hi_bit_set = left & 0x80
			left = left << 1

			# keep a 8 bit
			left = left & 0xFF

			if hi_bit_set:
				left = self.xor(left, 0x1b)

			right = right >> 1

		return p


	# Multiplication of the 4x4 matrix
	def mixColumns(self, st, isInv):
		# Iterate over the 4 columns
		for i in range(4):
			# Construct one column by slicing over the 4 rows
			column = st[i : i+16 : 4]

			# Apply the mixColumn on one column
			# Multiplication of 1 column of the 4x4 matrix
			if(isInv == True):
				mult = [14, 9, 13, 11]
			else:
				mult = [2, 1, 1, 3]

			cpy = list(column)
			g = self.multiple

			column[0] = g(cpy[0], mult[0]) ^ g(cpy[3], mult[1]) ^ g(cpy[2], mult[2]) ^ g(cpy[1], mult[3])
			column[1] = g(cpy[1], mult[0]) ^ g(cpy[0], mult[1]) ^ g(cpy[3], mult[2]) ^ g(cpy[2], mult[3])
			column[2] = g(cpy[2], mult[0]) ^ g(cpy[1], mult[1]) ^ g(cpy[0], mult[2]) ^ g(cpy[3], mult[3])
			column[3] = g(cpy[3], mult[0]) ^ g(cpy[2], mult[1]) ^ g(cpy[1], mult[2]) ^ g(cpy[0], mult[3])

			# Put the values back into the st
			st[i : i+16 : 4] = column

		return st

	 # Adds the round key to the st.
	def roundKey(self, st, roundKey):
		for i in range(16):
			st[i] = self.xor(st[i], roundKey[i])

		return st

	# Create a round key.
	def createRoundKey(self, expandedKey, roundKeyPointer):
		# Creates a round key from the gIVectoren expanded key and the position within the expanded key.
		roundKey = 16 * [0]

		for i in range(4):
			for j in range(4):
				roundKey[j*4+i] = expandedKey[roundKeyPointer + i*4 + j]

		return roundKey

	# Applies the 4 operations of the forward round in sequence
	def AESround(self, st, roundKey):
		st = self.bytesSubst(st, False)
		st = self.shiftRows(st, False)
		st = self.mixColumns(st, False)
		st = self.roundKey(st, roundKey)

		return st

	# Applies the 4 operations of the inverse round in sequence
	def AESInvround(self, st, roundKey):
		st = self.shiftRows(st, True)
		st = self.bytesSubst(st, True)
		st = self.roundKey(st, roundKey)
		st = self.mixColumns(st, True)

		return st

	# Perform the initial operations, the standard round, and the final operations of the forward aes, creating a round key for each round
	def AES(self, st, expandedKey, nbrRounds):
		st = self.roundKey(st, self.createRoundKey(expandedKey, 0))
		i = 1

		while(i < nbrRounds):
			st = self.AESround(st, self.createRoundKey(expandedKey, 16*i))
			i += 1

		st = self.bytesSubst(st, False)
		st = self.shiftRows(st, False)
		st = self.roundKey(st, self.createRoundKey(expandedKey, 16*nbrRounds))

		return st

	# Perform the initial operations, the standard round, and the final operations of the inverse aes, creating a round key for each round
	def AES_Inv(self, st, expandedKey, nbrRounds):
		st = self.roundKey(st, self.createRoundKey(expandedKey, 16*nbrRounds))
		i = nbrRounds - 1

		while(i > 0):
			st = self.AESInvround(st, self.createRoundKey(expandedKey, 16*i))
			i -= 1

		st = self.shiftRows(st, True)
		st = self.bytesSubst(st, True)
		st = self.roundKey(st, self.createRoundKey(expandedKey, 0))

		return st

	# Encrypts a 128 bit input block against the gIVectoren key of size specified
	def encryptn(self, input, key):
		size = 16
		output = [0] * 16
		# The number of rounds
		nbrRounds = 0
		# The 128 bit block to encode
		block = [0] * 16
		# Set the number of rounds
		nbrRounds = 10

		# The expanded keySize
		expandedkeySize = 16*(nbrRounds+1)

		for i in range(4):
			# Iterate over the rows
			for j in range(4):
				block[(i+(j*4))] = input[(i*4)+j]

		# Expand the key into an 176, 208, 240 bytes key the expanded key
		expandedKey = self.keyExpand(key, expandedkeySize)

		# Encrypt the block using the expandedKey
		block = self.AES(block, expandedKey, nbrRounds)

		# Unmap the block again into the output
		for k in range(4):
			# Iterate over the rows
			for l in range(4):
				output[(k*4)+l] = block[(k+(l*4))]

		return output

	# Decrypts a 128 bit input block against the gIVectoren key of size specified
	def decryptn(self, input, key):
		output = [0] * 16
		# The number of rounds
		nbrRounds = 0
		# The 128 bit block to decode
		block = [0] * 16
		# Set the number of rounds
		nbrRounds = 10
		# The expanded keySize
		expandedkeySize = 16*(nbrRounds+1)

		for i in range(4):
			# Iterate over the rows
			for j in range(4):
				block[(i+(j*4))] = input[(i*4)+j]
		# Expand the key into an 176, 208, 240 bytes key
		expandedKey = self.keyExpand(key, expandedkeySize)
		# Decrypt the block using the expandedKey
		block = self.AES_Inv(block, expandedKey, nbrRounds)

		# Unmap the block again into the output
		for k in range(4):
			# Iterate over the rows
			for l in range(4):
				output[(k*4)+l] = block[(k+(l*4))]
		return output

# Handles AES with plainText consistingof multiple blocks. Choice of block encoding modes:  CFB, CBC, OFB

	# Converts a 16 character string into a number array
	def convertString(self, string, start, end, mode):
		if(end - start > 16):
			end = start + 16

		if(mode == self.modes["CBC"]):
			ar = [0] * 16
		else:
			ar = []

		i = start
		j = 0

		while(len(ar) < end - start):
			ar.append(0)

		while(i < end):
			ar[j] = ord(string[i])
			j += 1
			i += 1

		return ar

	# Mode of Operation Encryption
	# stringIn - Input String
	# mode - mode of type modes
	# hexKey - a hex key of the bit length size
	# hexIVector - the 128 bit hex Initilization Vector
	def encrypt(self, stringIn, mode, key, IVector):
		aes = AES()
		size = 16
		if(len(key) % size):
			return None

		if(len(IVector) % 16):
			return None
		# The AES input/output
		plainText = []
		input = [0] * 16
		output = []
		cipherText = [0] * 16
		# The output cipher string
		cipherOut = []
		# Char firstRound
		firstRound = True
		if(stringIn != None):
			for j in range(int(math.ceil(float(len(stringIn))/16))):
				start = j*16
				end = j*16+16

				if(end > len(stringIn)):
					end = len(stringIn)

				plainText = self.convertString(stringIn, start, end, mode)

				if(mode == self.modes["CFB"]):
					if(firstRound == True):
						output = self.encryptn(IVector, key)
						firstRound = False
					else:
						output = self.encryptn(input, key)

					for i in range(16):
						if(len(plainText)-1 < i):
							cipherText[i] = self.xor(0, output[i])
						elif(len(output)-1 < i):
							cipherText[i] = self.xor(plainText[i], 0)
						elif(len(plainText)-1 < i and len(output) < i):
							cipherText[i] = self.xor(0, 0)
						else:
							cipherText[i] = self.xor(plainText[i], output[i])

					for k in range(end-start):
						cipherOut.append(cipherText[k])
					input = cipherText

				elif mode == self.modes["OFB"]:
					if firstRound:
						output = self.encryptn(IVector, key)
						firstRound = False
					else:
						output = self.encryptn(input, key)

					for i in range(16):
						if(len(plainText)-1 < i):
							cipherText[i] = self.xor(0, output[i])
						elif(len(output)-1 < i):
							cipherText[i] = self.xor(plainText[i], 0)
						elif(len(plainText)-1 < i and len(output) < i):
							cipherText[i] = self.xor(0, 0)
						else:
							cipherText[i] = self.xor(plainText[i], output[i])

					for k in range(end-start):
						cipherOut.append(cipherText[k])
					input = output

				elif mode == self.modes["CBC"]:
					for i in range(16):
						if(firstRound == True):
							input[i] =  self.xor(plainText[i], IVector[i])
						else:
							input[i] =  self.xor(plainText[i], cipherText[i])

					firstRound = False
					cipherText = self.encryptn(input, key)

					# Always 16 bytes because of the padding for CBC
					for k in range(16):
						cipherOut.append(cipherText[k])

		return mode, len(stringIn), cipherOut

	# Mode of Operation Decryption
	# cipherIn - Encrypted String
	# originalsize - The unencrypted string length - required for CBC
	# mode - mode of type modes
	# key - a number array of the bit length size
	# IVector - the 128 bit number array Initilization Vector
	def decrypt(self, cipherIn, originalsize, mode, key, IVector):
		size = 16

		if(len(key) % size):
			return None

		if(len(IVector) % 16):
			return None
		# The AES input/output
		cipherText = []
		input = []
		output = []
		plainText = [0] * 16
		# The output plain text character list
		charList = []
		# Char firstRound
		firstRound = True
		if(cipherIn != None):
			for j in range(int(math.ceil(float(len(cipherIn))/16))):
				start = j*16
				end = j*16+16

				if(j*16+16 > len(cipherIn)):
					end = len(cipherIn)
				cipherText = cipherIn[start : end]

				if(mode == self.modes["CFB"]):
					if(firstRound == True):
						output = self.encryptn(IVector, key)
						firstRound = False
					else:
						output = self.encryptn(input, key)

					for i in range(16):
						if(len(output)-1 < i):
							plainText[i] = self.xor(0, cipherText[i])
						elif(len(cipherText)-1 < i):
							plainText[i] = self.xor(output[i], 0)
						elif(len(output)-1 < i and len(cipherText) < i):
							plainText[i] = self.xor(0, 0)
						else:
							plainText[i] = self.xor(output[i], cipherText[i])

					for k in range(end-start):
						charList.append(chr(plainText[k]))
					input = cipherText

				elif mode == self.modes["OFB"]:
					if firstRound:
						output = self.encryptn(IVector, key)
						firstRound = False
					else:
						output = self.encryptn(input, key)

					for i in range(16):
						if(len(output)-1 < i):
							plainText[i] = self.xor(0, cipherText[i])
						elif(len(cipherText)-1 < i):
							plainText[i] = self.xor(output[i], 0)
						elif(len(output)-1 < i and len(cipherText) < i):
							plainText[i] = self.xor(0, 0)
						else:
							plainText[i] = self.xor(output[i], cipherText[i])

					for k in range(end-start):
						charList.append(chr(plainText[k]))
					input = output

				elif(mode == self.modes["CBC"]):
					output = self.decryptn(cipherText, key)

					for i in range(16):
						if(firstRound == True):
							plainText[i] = self.xor(IVector[i], output[i])
						else:
							plainText[i] = self.xor(input[i], output[i])

					firstRound = False
					if(originalsize is not None and originalsize < end):
						for k in range(originalsize-start):
							charList.append(chr(plainText[k]))
					else:
						for k in range(end-start):
							charList.append(chr(plainText[k]))

					input = cipherText
		return "".join(charList)

# Generates a key from random input of length `keySize`. The returned key is a string of bytes.  
def generateRandomKey():

	return os.urandom(16)

# Encrypt `input` using `key` AND `key` should be a string of bytes. Returned cipher is a string of bytes prepended with the initialization vector.
def encryptMessage(key, input, mode):
	key = map(ord, key)

	# Return s padded to a multiple of 16-bytes by PKCS7 padding
	if(mode == AES.modes["CBC"]):
		numpads = 16 - (len(input)%16)
		input += numpads*chr(numpads)

	keySize = len(key)
	# Create a new IVector using random input
	IVector = [ord(i) for i in os.urandom(16)]
	AESmode = AES()
	(mode, length, ciph) = AESmode.encrypt(input, mode, key, IVector)

	# With padding, the original length does not need to be known. It's a bad idea to store the original message length. prepend the IVector.
	return ''.join(map(chr, IVector)) + ''.join(map(chr, ciph))

# Decrypt `input` using `key` AND `key` should be a string of bytes. `input` should have the initialization vector prepended as a string of ordinal values.
def decryptMessage(key, input, mode):

	key = map(ord, key)
	keySize = len(key)
	# IVector is first 16 bytes
	IVector = map(ord, input[:16])
	input = map(ord, input[16:])
	AESmode = AES()
	decr = AESmode.decrypt(input, None, mode, key, IVector)

	# Return s stripped of PKCS7 padding
	if(mode == AES.modes["CBC"]):
		numpads = ord(decr[-1])
		decr = decr[ : -numpads]

	return decr

if __name__ == "__main__":
	print "---------- PART A: AES Sifreleme / Desifreleme ----------\n"
	modeName = "CFB"
	cleartext = "Bu bir acik metin test mesajidir. Merhaba Dunya!"
	print "Acik Metin: \"" + cleartext + "\"\n"

	key = generateRandomKey()
	print "Anahtar:", [ord(x) for x in key], "\n"

	mode = AES.modes[modeName]
	cipher = encryptMessage(key, cleartext, mode)
	print "Sifreli Metin:", [ord(x) for x in cipher], "\n"

	decr = decryptMessage(key, cipher, mode)
	print "Desifrelenmis Metin:", decr, "\n"

	print "---------- PART B: AES Sifreleme / Desifreleme (CBC ve OFB Modlari) ----------\n"
	modeName = "CBC"
	print "----- 1. Mod: " + modeName + " -----\n"
	cleartext = "Bu bir CBC modu acik metin test mesajidir. Merhaba Dunya!"
	print "Acik Metin: \"" + cleartext + "\"\n"

	key = generateRandomKey()
	print "Anahtar:", [ord(x) for x in key], "\n"

	mode = AES.modes[modeName]
	cipher = encryptMessage(key, cleartext, mode)
	print "Sifreli Metin:", [ord(x) for x in cipher], "\n"

	decr = decryptMessage(key, cipher, mode)
	print "Desifrelenmis Metin:", decr, "\n"

	modeName = "OFB"
	print "----- 2. Mod: " + modeName + " -----\n"
	cleartext = "Bu bir OFB modu acik metin test mesajidir. Merhaba Dunya!"
	print "Acik Metin: \"" + cleartext + "\"\n"

	key = generateRandomKey()
	print "Anahtar:", [ord(x) for x in key], "\n"

	mode = AES.modes[modeName]
	cipher = encryptMessage(key, cleartext, mode)
	print "Sifreli Metin:", [ord(x) for x in cipher], "\n"

	decr = decryptMessage(key, cipher, mode)
	print "Desifrelenmis Metin:", decr, "\n"