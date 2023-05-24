from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions  import InvalidSignature
def generate_keys():
  private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
  )
  public = private.public() #inbuilt function
  return private,public

def sign(message,private_key):
 message = bytes(str(message),'utf-8') # convert message to bytes
 signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
 return signature


def verification(message_,signature_,public_key):
    message = bytes(str(message),'utf-8') # convert message to bytes
    try:
        public_key.verify(
            signature_,
            message_,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    
    return True
   except InvalidSignature:
        return False
   except:
       print("Error Executing public key")
       return False



if __name__ == '__main__':
  getPrivate,getPublic = generate_keys()
  print(getPrivate)
  print(getPublic)
  message = "Hello,World"
  getSign = sign(message,getPrivate)
  print(getSign)
  correct = verification(message,getSign,getPublic)
  if correct:
      print("successfull")
  else:
      print("unsuccessfull")
      
  #for unsuccessfull event get the another private public key bind signature with 1st one and tries to open with other one we will get an error
