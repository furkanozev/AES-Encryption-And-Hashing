#! /usr/bin/env python
# -*- coding: UTF-8 -*-

import part_a_b as aesmodule
import sys

mode = aesmodule.AES.modes["CFB"]

# Hash message
# First expand to the nearest multiplies of 16
# XOR Left and Rİght sides
# Continiue, until 16 values remains.
def hash(message):
	while(len(message) != 16):
		size = len(message)
		expsize = 16 - (size % 16)

		i = 0
		char = 'a'
		while i < expsize:
			message += char
			char = chr(ord(char) + 1)
			i += 1

		newSize = len(message)
		messageLeft = message[ : newSize//2]
		messageRight = message[newSize//2 : ]
		message = [chr(ord(a) ^ ord(b)) for a,b in zip(messageLeft,messageRight)]
		message = listToString(message)

	return message

# Convert a list to string
def listToString(lst):
	# Initialize an empty string
	str1 = ""
	# Traverse in the string
	for elem in lst:
		str1 += elem

	# Return string
	return str1

# Hash clear text, then encrypt it.
def hash_and_encrypt(cleartext, key):
	hashvalue = hash(cleartext)
	print "Ozet Degeri:", [ord(x) for x in hashvalue], "\n"

	print "Anahtar:", [ord(x) for x in key], "\n"

	cipher = aesmodule.encryptMessage(key, listToString(hashvalue), mode)
	print "Ozetlenmis ve Sifrelenmis Metin:", [ord(x) for x in cipher], "\n"

	return cipher

# In project, Part C
def partC(file, key):
	print "---------- PART C: Ozet Alma / Sifreleme ve Dosyanin Sonuna Ekleme ----------\n"
	cleartext = file.read()
	file.close()

	print "Acik Metin:\n\"" + cleartext + "\"\n"

	cipher = hash_and_encrypt(cleartext, key)

	content = cleartext + cipher
	encryptFilename = "hash_encrypt_" + filename
	encryptFile = open(encryptFilename, "w+")
	encryptFile.write(content)
	encryptFile.close()

	print "Ozet alinidiktan sonra sifrelenen ozet degeri dosyanin sonuna eklenmistir."
	print encryptFilename + " isimli dosya olusturuldu. Son durumu bu dosya icerir"

# In project prd D
def partD(file, key):
	print "\n---------- PART D: Dosyanin Butunlugunu Dogrulama ----------\n"
	decryptFilename = open(encryptFilename, "r+")
	text = decryptFilename.read()
	decryptFilename.close()


	cleartext = text[:-32]
	print "Gelen Acik Metin:\n\"" + cleartext + "\"\n"

	hashvalue = hash(cleartext)
	print "Gelen Acik Metnin Ozet Degeri:", [ord(x) for x in hashvalue], "\n"

	ency_hash = list(text[-32:])
	print "Gelen Ozeti Alınıp Sifrelenmis Mesaj:", [ord(x) for x in ency_hash], "\n"

	print "Anahtar:", [ord(x) for x in key], "\n"

	decr = aesmodule.decryptMessage(key, ency_hash, mode)
	print 'Gelen Sifrelenmis Ozet Degerin Desifrelenmesi (Cozumlenen Ozet Deger):', [ord(x) for x in decr], "\n"

	print "Gelen Acik Metinin Ozet Degeri ile Gelen Sifrelenmis Ozet Deger Kiyaslandi"

	if(hashvalue == decr):
		print "\n*** Dosya butunlugunun korundugu teyit edilmistir."
	else:
		print "\n*** Dosya butunlugunun korunmadigi tespit edilmistir. Dosyada bir degisiklik meydana gelmistir. "


if __name__ == "__main__":
	if(len(sys.argv) != 2):
		print "Please give input file as argument.\nRun typle like that: python part_c_d.py inputfile.txt\n"
		exit()

	filename = sys.argv[-1]
	try:
		file = open(filename, "r+")
	except IOError:
		print filename + " is not exist.\n"

	key = aesmodule.generateRandomKey()

	print "--------------------- TEST 1: DOSYA BUTUNLUGU KORUNUR ---------------------"
	partC(file, key)
	encryptFilename = "hash_encrypt_" + filename
	partD(encryptFilename, key)

	print "\n\n--------------------- TEST 2: DOSYA BUTUNLUGU KORUNMAZ ---------------------"
	file = open(filename, "r+")
	partC(file, key)
	encryptFilename = "hash_encrypt_" + filename
	wrong = open(encryptFilename, "r+")
	wrong.write("change file content ")
	wrong.close()
	partD(encryptFilename, key)