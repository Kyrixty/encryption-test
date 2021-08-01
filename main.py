'''
Testing basic encryption protocol.
Asymmetric encryption, client+server share public keys (encrypt) but not their private keys (decrypt).
'''

import hashlib
import random
import string

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Cipher    import PKCS1_OAEP
    from Crypto           import Hash
except Exception:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Signature import pkcs1_15
    from Cryptodome.Cipher    import PKCS1_OAEP
    from Cryptodome           import Hash

def h256(msg):
    return hashlib.sha256(bytes(msg, "utf-8"))

def genRandomString(size=10, chars=string.ascii_letters + string.digits):
    '''
    Returns a random string with a default size of 10, using the string module.

    Usage: genRandomString() --> Will return a random string with a size of (size, default is 10).
    '''

    return ''.join(random.choices(chars, k=size))

class Person:
    '''
    A participant in the handshake (exchange of public keys between 2 participants.)
    '''
    def __init__(self, name: str):
        self.name = name
        self.key = self.gen_RSA_key(1024) #Just doing 1024 for speed, normally 2048.
        self.partnerKey = None
        self.pubKey = self.key.public_key()#.export_key("PEM").decode("utf-8") 
        self.prvKey = self.key#.export_key("PEM").decode("utf-8")
        self.sigScheme = PKCS1_OAEP.new(self.key, Hash.SHA256)
    
    def gen_RSA_key(self, bits=2048):
        '''
        Generates an RSA keypair of size ``bits``.
        '''
        
        return RSA.generate(bits)
    
    def encrypt_msg(self, msg: str, key: RSA.RsaKey):
        return self.sigScheme.encrypt(bytes(msg, "utf-8"))
    
    def decrypt_msg(self, ciphertext):
        return self.sigScheme.decrypt(ciphertext)
    
    def sign_msg(self, msg: str):
        '''
        Signs a message using the sender's private key.
        '''

        signature = pkcs1_15.new(self.prvKey)
        h = Hash.SHA256.new(bytes(msg, "utf-8"))
        return signature.sign(h)
    
    def verify_signature(self, signature: bytes, pubKey: RSA.RsaKey, msg: str) -> bool:
        '''
        Verifies a signature given a public key and a signed message.
        '''
        try:
            h = Hash.SHA256.new(bytes(msg, "utf-8"))
            signature = pkcs1_15.new(pubKey).verify(h, signature)
            return True

        except (ValueError, TypeError):
            return False

alice = Person("Alice")
bob = Person("Bob")

alice_encrypt = alice.encrypt_msg("hello", alice.key)
alice_decrypt = alice.decrypt_msg(alice_encrypt)
bob_encrypt = bob.encrypt_msg("hello", bob.key)
bob_decrypt = bob.decrypt_msg(bob_encrypt)

print(alice_encrypt, alice_decrypt)
print(bob_encrypt, bob_decrypt)

aliceTestKey = PKCS1_OAEP.new(bob.pubKey, Hash.SHA256)
bobTestKey = PKCS1_OAEP.new(alice.pubKey, Hash.SHA256)

aliceWithBobKey = aliceTestKey.encrypt(b"hello")
bobWithAliceKey = bobTestKey.encrypt(b"hello")

#print("\n------------------------------------------------------")
#print("ALICE (using bob's public key): ")
#print(aliceWithBobKey)
#print("\nBOB (with alice's public key): ")
#print(bobWithAliceKey)

print("\n------------------------------------------------------")
print("ALICE DECRYPTING 'BOB (with alice's public key)': ")
print(alice.decrypt_msg(bobWithAliceKey))
print("BOB DECRYPTING 'ALICE (using bob's public key)': ")
print(bob.decrypt_msg(aliceWithBobKey))

msg = "hello"
aliceSignature = alice.sign_msg(msg)
bobSignature = bob.sign_msg(msg)

bobVerification = alice.verify_signature(bobSignature, bob.pubKey, msg)
aliceVerification = bob.verify_signature(aliceSignature, alice.pubKey, msg)

print("\nALICE SIGNATURE")
print(aliceSignature)
print("\nBOB SIGNATURE")
print(bobSignature)

print("\nALICE VERIFICATION?")
print(aliceVerification) #True
print("\nBOB VERIFICATION")
print(bobVerification) #True