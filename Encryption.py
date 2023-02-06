
from hashlib import sha256
import base64
from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: bytes(s + (BS - len(s) % BS) * chr(BS - len(s) % BS), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]

class AESCipher:

    def __init__( self, key ):
        self.key = bytes(key, 'utf-8')

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] )).decode('utf8')


#encrypted = cipher.encrypt('Secret')
#decrypted = cipher.decrypt(encrypted)

def encrypt_file(cipher, filename):
    try:
        with open(filename,'r') as fi:
            plaintext = fi.read()
        encrypted = cipher.encrypt(plaintext)
        with open(filename+".enc",'wb') as fo:
            fo.write(encrypted)
    except Exception as e:
        print("Error occured while encrypting:",e)


def decrypt_file(cipher, filename):
    try:
        with open(filename,'rb') as fi:
            plaintext = fi.read()
        decrypted = cipher.decrypt(plaintext)
        with open(filename[0:-4]+".orig",'w') as fo:
            fo.write(decrypted)
    except Exception as e:
        print("Error occured while decrypting:",e)


def main():
    while True:
        choice = int(input(
            "1. Press '1' to encrypt file.\n2. Press '2' to decrypt file.\n3. Press '3' to exit.\n"))
        cipher_obj = AESCipher('mysecretpassword')
        if choice == 1:
            encrypt_file(cipher_obj, str(input("Enter name of file to encrypt: ")))
        elif choice == 2:
            decrypt_file(cipher_obj, str(input("Enter name of file to decrypt: ")))
        elif choice == 3:
            exit()
        else:
            print("Please select a valid option!")


if __name__=="__main__":
    main()
