# This simple script allows encryption/decryption of a string, using a Caesar Cipher
# The user may choose the number of characters he wishes to rotate

def encrypt(input_text, rotation):
    encrypted = ""
    for character in input_text:
        encrypted = encrypted + \
            chr((ord(character) - ord('a') + rotation) % 26 + ord('a'))

    print("Encrypted text: " + encrypted)


def decrypt(input_text, rotation):
    decrypted = ""
    for character in input_text:
        decrypted = decrypted + \
            chr((ord(character) - ord('a') - rotation) % 26 + ord('a'))
    print("Decrypted text: " + decrypted)


def get_user_input():

    text = input("Please enter the text to encrypt/decrypt: ")
    if text.isalpha() == False:
        print("You must use alphabetic characters only! Bye!")
        exit()

    rotation = input("Enter the number of characters to rotate: ")
    if rotation.isnumeric() == False:
        print("You must use numbers only! Bye!")
        exit()

    choice = input("Press d to decrypt or e to encrypt: ")
    match choice:
        case "d":
            decrypt(text, int(rotation))
        case "e":
            encrypt(text, int(rotation))
        case _:
            print("That's not a valid option. Bye!")


get_user_input()
