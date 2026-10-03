import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from handshake import establish_session, mac, new_signing_key


HEADER = struct.Struct(">BBQBI")
VERSION = 1
G2N = 0
N2G = 1
MAX_SEQUENCE = (1 << 64) - 1
MAX_PLAINTEXT = 16


class RecordError(Exception):
    pass


def crypt(key, iv, data):
    context = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
    ).encryptor()

    return context.update(data) + context.finalize()


class RecordLayer:
    def __init__(self, keys, role):
        if role not in ("gateway", "node"):
            raise ValueError("unknown role")

        self.session_id = keys["session_id"]

        if len(self.session_id) != 8:
            raise ValueError("invalid session ID")

        self.send_direction = G2N if role == "gateway" else N2G
        self.receive_direction = N2G if role == "gateway" else G2N

        send_prefix = "g2n" if role == "gateway" else "n2g"
        receive_prefix = "n2g" if role == "gateway" else "g2n"

        self.send_enc = keys[send_prefix + "_enc"]
        self.send_mac = keys[send_prefix + "_mac"]
        self.receive_enc = keys[receive_prefix + "_enc"]
        self.receive_mac = keys[receive_prefix + "_mac"]

        self.send_sequence = 0
        self.receive_sequence = 0

    def seal(self, plaintext, message_type=1):
        if not isinstance(plaintext, bytes):
            raise RecordError("plaintext must be bytes")

        if len(plaintext) > MAX_PLAINTEXT:
            raise RecordError("record exceeds 16 bytes")

        if not 0 <= message_type <= 255:
            raise RecordError("invalid message type")

        if self.send_sequence > MAX_SEQUENCE:
            raise RecordError("sequence exhausted")

        sequence = self.send_sequence
        iv = self.session_id + sequence.to_bytes(8, "big")
        ciphertext = crypt(self.send_enc, iv, plaintext)

        header = HEADER.pack(
            VERSION,
            self.send_direction,
            sequence,
            message_type,
            len(ciphertext),
        )

        tag = mac(self.send_mac, header + iv + ciphertext)

        self.send_sequence += 1
        return header + iv + ciphertext + tag

    def open_record(self, record):
        minimum = HEADER.size + 16 + 32

        if len(record) < minimum:
            raise RecordError("malformed record")

        header = record[:HEADER.size]

        version, direction, sequence, message_type, length = (
            HEADER.unpack(header)
        )

        if length > MAX_PLAINTEXT or len(record) != minimum + length:
            raise RecordError("malformed record")

        iv = record[HEADER.size:HEADER.size + 16]
        ciphertext = record[HEADER.size + 16:-32]
        tag = record[-32:]

        # Verify the MAC before any decryption.
        context = hmac.HMAC(self.receive_mac, hashes.SHA256())
        context.update(header + iv + ciphertext)

        try:
            context.verify(tag)
        except InvalidSignature as error:
            raise RecordError("invalid MAC") from error

        if version != VERSION:
            raise RecordError("wrong version")

        if direction != self.receive_direction:
            raise RecordError("wrong direction")

        if self.receive_sequence > MAX_SEQUENCE:
            raise RecordError("sequence exhausted")

        if sequence != self.receive_sequence:
            raise RecordError("unexpected sequence")

        expected_iv = self.session_id + sequence.to_bytes(8, "big")

        if iv != expected_iv:
            raise RecordError("unexpected IV")

        plaintext = crypt(self.receive_enc, iv, ciphertext)
        self.receive_sequence += 1

        return message_type, plaintext


if __name__ == "__main__":
    gateway_keys, node_keys = establish_session(
        new_signing_key(),
        new_signing_key(),
    )

    gateway = RecordLayer(gateway_keys, "gateway")
    node = RecordLayer(node_keys, "node")

    record = gateway.seal(b"READ notes.txt")
    print("Gateway -> node:", node.open_record(record))

    reply = node.seal(b"OK")
    print("Node -> gateway:", gateway.open_record(reply))

    second = gateway.seal(b"LIST")
    print("Next gateway record:", node.open_record(second))

    try:
        node.open_record(record)
    except RecordError as error:
        print("Replay rejected:", error)
