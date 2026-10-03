import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa


LABEL = b"CSCE465-HS-v2"
GROUP = b"ffdhe3072"
IDENTITIES = (b"gateway", b"node")

PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


class HandshakeError(Exception):
    pass


def sha256(data):
    context = hashes.Hash(hashes.SHA256())
    context.update(data)
    return context.finalize()


def mac(key, data):
    context = hmac.HMAC(key, hashes.SHA256())
    context.update(data)
    return context.finalize()


def encode_fields(fields):
    return b"".join(
        len(field).to_bytes(4, "big") + field
        for field in fields
    )


def decode_transcript(data):
    fields = []
    position = 0

    for _ in range(8):
        if position + 4 > len(data):
            raise HandshakeError("malformed transcript")

        length = int.from_bytes(data[position:position + 4], "big")
        position += 4

        if position + length > len(data):
            raise HandshakeError("malformed transcript")

        fields.append(data[position:position + length])
        position += length

    if position != len(data):
        raise HandshakeError("malformed transcript")

    if fields[0] != LABEL or fields[1] != GROUP:
        raise HandshakeError("unexpected protocol or group")

    if tuple(fields[2:4]) != IDENTITIES:
        raise HandshakeError("unexpected identity")

    if any(len(field) != 384 for field in fields[4:6]):
        raise HandshakeError("invalid public-value width")

    if any(len(field) != 16 for field in fields[6:8]):
        raise HandshakeError("invalid nonce width")

    return fields


def load_group():
    path = Path(__file__).with_name("ffdhe3072.pem")
    parameters = serialization.load_pem_parameters(path.read_bytes())

    if not isinstance(parameters, dh.DHParameters):
        raise HandshakeError("not DH parameters")

    numbers = parameters.parameter_numbers()
    if numbers.p.bit_length() != 3072 or numbers.g != 2:
        raise HandshakeError("unexpected DH parameters")

    # Trust the local standard-group file generated with OpenSSL.
    return parameters


def new_signing_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


def derive_keys(shared_secret, transcript_hash):
    z = shared_secret.rjust(384, b"\x00")

    if len(z) != 384:
        raise HandshakeError("invalid shared-secret width")

    master = sha256(b"CSCE465-KDF-v1" + z + transcript_hash)

    labels = {
        "g2n_enc": b"gateway-to-node encryption",
        "g2n_mac": b"gateway-to-node MAC",
        "n2g_enc": b"node-to-gateway encryption",
        "n2g_mac": b"node-to-gateway MAC",
        "session_id": b"session identifier",
    }

    keys = {
        name: mac(master, label + transcript_hash)
        for name, label in labels.items()
    }

    keys["session_id"] = keys["session_id"][:8]
    return keys


class Party:
    def __init__(self, role, signing_key, trusted_peer_key, parameters):
        if role not in IDENTITIES:
            raise HandshakeError("unexpected identity")

        self.role = role
        self.peer_role = b"node" if role == b"gateway" else b"gateway"
        self.signing_key = signing_key
        self.trusted_peer_key = trusted_peer_key
        self.parameters = parameters

        # Fresh ephemeral DH key and nonce for this session.
        self.private = parameters.generate_private_key()
        public_value = self.private.public_key().public_numbers().y
        self.public = public_value.to_bytes(384, "big")
        self.nonce = os.urandom(16)
        self.accepted = False

    def validate_local_fields(self, fields):
        index = 0 if self.role == b"gateway" else 1

        if fields[4 + index] != self.public:
            raise HandshakeError("local public value mismatch")

        if fields[6 + index] != self.nonce:
            raise HandshakeError("local nonce mismatch")

    def sign(self, transcript):
        fields = decode_transcript(transcript)
        self.validate_local_fields(fields)

        message = self.role + sha256(transcript)

        return self.signing_key.sign(
            message,
            PSS,
            hashes.SHA256(),
        )

    def accept(self, transcript, peer_signature):
        if self.accepted:
            raise HandshakeError("handshake already accepted")

        # Validate the transcript before hashing it.
        fields = decode_transcript(transcript)
        self.validate_local_fields(fields)
        th = sha256(transcript)

        try:
            self.trusted_peer_key.verify(
                peer_signature,
                self.peer_role + th,
                PSS,
                hashes.SHA256(),
            )
        except InvalidSignature as error:
            raise HandshakeError("invalid peer signature") from error

        peer_index = 1 if self.role == b"gateway" else 0
        peer_value = int.from_bytes(fields[4 + peer_index], "big")

        try:
            peer_public = dh.DHPublicNumbers(
                peer_value,
                self.parameters.parameter_numbers(),
            ).public_key()

            shared_secret = self.private.exchange(peer_public)
        except ValueError as error:
            raise HandshakeError("invalid DH public value") from error

        keys = derive_keys(shared_secret, th)
        self.accepted = True
        return keys


def prepare_handshake(gateway_key, node_key):
    parameters = load_group()

    gateway = Party(
        b"gateway",
        gateway_key,
        node_key.public_key(),
        parameters,
    )

    node = Party(
        b"node",
        node_key,
        gateway_key.public_key(),
        parameters,
    )

    transcript = encode_fields([
        LABEL,
        GROUP,
        b"gateway",
        b"node",
        gateway.public,
        node.public,
        gateway.nonce,
        node.nonce,
    ])

    gateway_signature = gateway.sign(transcript)
    node_signature = node.sign(transcript)

    return (
        gateway,
        node,
        transcript,
        gateway_signature,
        node_signature,
    )


def establish_session(gateway_key, node_key):
    gateway, node, transcript, gs, ns = prepare_handshake(
        gateway_key,
        node_key,
    )

    gateway_keys = gateway.accept(transcript, ns)
    node_keys = node.accept(transcript, gs)

    return gateway_keys, node_keys


if __name__ == "__main__":
    # Reuse long-term RSA keys across two fresh sessions.
    gateway_key = new_signing_key()
    node_key = new_signing_key()

    first_g, first_n = establish_session(gateway_key, node_key)
    second_g, second_n = establish_session(gateway_key, node_key)

    assert first_g == first_n
    assert second_g == second_n
    assert first_g != second_g

    print("Gateway and node derived matching keys.")
    print("Fresh session derived different keys.")
    print("Session 1 ID:", first_g["session_id"].hex())
    print("Session 2 ID:", second_g["session_id"].hex())
