# -*- coding: utf-8 -*-
"""
Created on Tue Jun 15 16:31:02 2021

@author: varad
"""
from sympy import randprime
from math import gcd
def gcd(a,b):
    while b != 0:
        c = a % b
        a = b
        b = c
    return a

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:    # gcd * k % mod phi = 1
            return x
    return None
keysize=int(input("Please Enter the desired key size "))
p1=0
p2=0
while p1==p2 or (p1*p2)>2**keysize:
    p1=randprime(3,2**keysize)
    p2=randprime(3,2**keysize)
    
print("1st Prime Number is " + str(p1))
print("2nd Prime Number is " + str(p2))

rsa_modulus=p1*p2
totient=(p1-1)*(p2-1)

e=0
for i in range(3,totient-1):
    if gcd(i,totient)==1:
        e=i
        break

print("  Public-Key exponent, e -----> " + str(i))
print("  Public Key -----> (" + str(i) + ", " + str(rsa_modulus) + ")")

d = modinv(e,totient)
#Display the private-key exponent d
print("  Private-Key exponent, d -----> " + str(d))

#Display the private key
print("  Private Key -----> (" + str(d) + ", " + str(rsa_modulus) + ")")


def mod(x,y): # get modulus for 2 number
    if(x<y):
        return y
    else:
        c=x%y
        return c

def encryptString(plainText):
    cipher=""
    for x in list(plainText):
        c = mod(ord(x)**e,rsa_modulus)
        cipher+=(chr(c))
    return cipher
def decryptString(plainText):
    plain=""
    for x in list(plainText):
        c = mod(ord(x)**d,rsa_modulus)
        plain+=(chr(c))
    return plain
s = input("Enter a text to encrypt: ")
print("\nPlain message: " + s + "\n")
   
enc = encryptString(s)
print("Encrypted message: " + str(enc) + "\n")
    
dec = decryptString(enc)
print("Decrypted message: " + dec + "\n")
        