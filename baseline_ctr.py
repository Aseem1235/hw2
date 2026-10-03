import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def ctr(key, iv, data):
    context = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return context.update(data) + context.finalize()


def relay(ciphertext):
    # Attacker knows the fixed format, but receives no encryption key.
    original = b"READ"
    replacement = b"LIST"
    offset = len(b'{"action":"')

    modified = bytearray(ciphertext)
    delta = bytes(a ^ b for a, b in zip(original, replacement))

    for i, value in enumerate(delta):
        modified[offset + i] ^= value

    print("Original action bytes:", original.hex())
    print("Replacement bytes:   ", replacement.hex())
    print("XOR difference:      ", delta.hex())
    print("Original ciphertext: ", ciphertext.hex())
    print("Modified ciphertext: ", bytes(modified).hex())
    return bytes(modified)


def main():
    key = os.urandom(32)
    iv = os.urandom(16)
    plaintext = b'{"action":"READ","path":"notes.txt"}'
    ciphertext = ctr(key, iv, plaintext)

    def receive(record):
        recovered = ctr(key, iv, record)
        command = json.loads(recovered)
        print("Receiver processes:", command)
        return recovered

    print("Original message:")
    assert receive(ciphertext) == plaintext

    print("\nAttacker modifies READ to LIST:")
    modified = relay(ciphertext)
    expected = b'{"action":"LIST","path":"notes.txt"}'
    assert receive(modified) == expected

    print("\nReplay the same modified ciphertext:")
    assert receive(modified) == expected
    print("The LIST command was processed twice.")


if __name__ == "__main__":
    main()
