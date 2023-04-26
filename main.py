import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def DeriveKey(passwordParam):
    if type(passwordParam) == str:
        passwordParam = passwordParam.encode("utf-8")
    keyDerivationFunction = Scrypt(
        salt=b'ABCDEFGHIJKLMNOP',
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    deriveKey = keyDerivationFunction.derive(passwordParam)
    key = base64.urlsafe_b64encode(deriveKey)
    return key


def Encrypt(chunkParam, passwordParam: str):
    convertChunkToString = False
    if type(chunkParam) == str:
        chunkParam = chunkParam.encode("utf-8")
        convertChunkToString = True
    key = DeriveKey(passwordParam)
    fernet = Fernet(key)
    encryptedChunk = fernet.encrypt(chunkParam)
    if convertChunkToString == True:
        encryptedChunk = encryptedChunk.decode("utf-8")
    return encryptedChunk


def Decrypt(chunkParam, passwordParam: int):
    convertChunkToString = False
    if type(chunkParam) == str:
        chunkParam = chunkParam.encode("utf-8")
        convertChunkToString = True
    key = DeriveKey(passwordParam)
    fernet = Fernet(key)
    try:
        decryptedChunk = fernet.decrypt(chunkParam)
    except Exception:
        return None
    if convertChunkToString == True:
        decryptedChunk = decryptedChunk.decode("utf-8")
    return decryptedChunk


def EncryptFile(fileNameParam: str, passwordParam: str) -> None:
    with open(fileNameParam, "rb") as fileObject:
        fileContent = fileObject.read()
        encrypteFileContent = Encrypt(fileContent, passwordParam)
    with open(f"{fileNameParam}.enc", "wb") as fileObject:
        fileObject.write(encrypteFileContent)


def DecryptFile(fileNameParam: str, passwordParam: str) -> None:
    with open(fileNameParam, "rb") as fileObject:
        fileContent = fileObject.read()
        decryptedFileContent = Decrypt(fileContent, passwordParam)

    if decryptedFileContent == None:
        print("Şifre Hatalı")
    else:
        with open(f"{fileNameParam}.dec", "wb") as fileObject:
            fileObject.write(decryptedFileContent)


while True:
    command = input("İşlem türünü giriniz (E/D): ").upper()
    if command == "E" or command == "D":
        break
    else:
        print("İşlem türünü E veya D olarak giriniz.")

password = input("Şifre giriniz: ")
fileName = input("İşlem yapmak istediğiniz dosya ismini giriniz: ")

if command == "E":
    EncryptFile(fileName, password)
elif command == "D":
    DecryptFile(fileName, password)

