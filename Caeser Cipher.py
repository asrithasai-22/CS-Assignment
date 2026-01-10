def caesar(text, shift):
    result = ""

    for ch in text:
        if ch.isalpha():
            result += chr(ord(ch) + shift)
        else:
            result += ch

    return result

choice = input("Enter choice (encrypt / decrypt): ")
text = input("Enter text: ")
shift = int(input("Enter shift value: "))

if choice == "encrypt":
    print("Encrypted text:", caesar(text, shift))

elif choice == "decrypt":
    print("Decrypted text:", caesar(text, -shift))

else:
    print("Invalid choice! Enter encrypt or decrypt.")
