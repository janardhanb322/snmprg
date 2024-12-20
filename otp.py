import random
def genotp():
    otp=''
    for i in range(2):
        otp=otp+random.choice([chr(i) for i in range(ord('A'),ord('Z')+1)]) #otp=' '+'B' -----> 'B'
        otp=otp+random.choice([chr(i) for i in range(ord('a'),ord('z')+1)]) #otp='B'+'a' -----> 'Ba'
        otp=otp+str(random.randint(0,9)) #otp='Ba'+'7' ----> 'Ba7'
    return otp

print(genotp())