"""
    Basic implementation of XOR encryption and decryption
    Author: Daniel Tan
    Date: 7/04/2022
"""


def main():
    while True:
        # get user input of string to be encrypted
        plaintext = input('Enter string to be encrypted: ')
        # get initialisation vector to encrypt string
        initvector = input('Enter Initialisation Vector in binary: ')
        # convert plaintext to binary
        plaintextbinary = ' '.join(format(ord(x), 'b') for x in plaintext) + ' '
        print('String in binary: {}'.format(plaintextbinary))

        # if binary is less than 8 bits IV length, pad with 0s
        plaintextarr = []
        binary = ''
        for i in plaintextbinary:
            if i != ' ':
                binary += i
            else:
                binary = '0'*(8-len(binary)) + binary
                plaintextarr.append(binary)
                binary = ''

        print('Binary after padding with 0s: {}'.format(plaintextarr))
        # call encryption function
        encryptedstringarr = encryptString(plaintextarr, initvector)
        print('Encrypted string in binary: {}'.format(encryptedstringarr))

        # convert encrypted binary to characters
        encryptedstring = ''
        for x in encryptedstringarr:
            encryptedstring += chr(int(x, 2))
        print('Encrypted string: {}'.format(encryptedstring))

        # decryption of encrypted string
        # call decryption function
        decryptedstringarr = decryptString(encryptedstringarr, initvector)
        decryptedstring = ''
        for x in decryptedstringarr:
            decryptedstring += chr(int(x, 2))
        print('Decrypted string: {}'.format(decryptedstring))


def encryptString(plaintextarr, initvector):
    encryptedstringarr = []
    encryptedstringbinary = ''

    # loop through plain text array and XOR bits with IV
    for binary in plaintextarr:
        index = 0
        for bit in binary:
            encryptedstringbinary += xor(bit, index, initvector)
            index += 1
        encryptedstringarr.append(encryptedstringbinary)
        encryptedstringbinary = ''
    return encryptedstringarr


def decryptString(encryptedstringarr, initvector):
    decryptedstringarr = []
    decryptedstringbinary = ''

    # loop through encrypted string arr and XOR bits with IV
    for binary in encryptedstringarr:
        index = 0
        for bit in binary:
            decryptedstringbinary += xor(bit, index, initvector)
            index += 1
        decryptedstringarr.append(decryptedstringbinary)
        decryptedstringbinary = ''
    return decryptedstringarr


def xor(bit, index, initvector):
    if bit == initvector[index]:
        return '0'
    else:
        return '1'


if __name__ == '__main__':
    main()
