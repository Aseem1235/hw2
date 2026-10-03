import pytest

from handshake import (
    HandshakeError,
    decode_transcript,
    encode_fields,
    establish_session,
    new_signing_key,
    prepare_handshake,
)
from secure_record import HEADER, RecordError, RecordLayer


@pytest.fixture(scope="module")
def signing_keys():
    return new_signing_key(), new_signing_key()


@pytest.fixture
def layers(signing_keys):
    gateway_keys, node_keys = establish_session(*signing_keys)
    assert gateway_keys == node_keys

    return (
        RecordLayer(gateway_keys, "gateway"),
        RecordLayer(node_keys, "node"),
    )


def flip(data, position):
    changed = bytearray(data)
    changed[position] ^= 1
    return bytes(changed)


def test_valid_bidirectional_messages(layers):
    gateway, node = layers

    assert node.open_record(gateway.seal(b"READ notes.txt")) == (
        1, b"READ notes.txt"
    )

    assert gateway.open_record(node.seal(b"OK")) == (1, b"OK")
    assert node.open_record(gateway.seal(b"LIST")) == (1, b"LIST")

    assert gateway.send_sequence == 2
    assert node.receive_sequence == 2


@pytest.mark.parametrize(
    "position",
    [
        HEADER.size + 16,
        10,
        HEADER.size,
        -1,
    ],
    ids=["ciphertext", "header", "iv", "tag"],
)
def test_modified_record(layers, position):
    gateway, node = layers
    valid = gateway.seal(b"hello")

    with pytest.raises(RecordError, match="invalid MAC"):
        node.open_record(flip(valid, position))

    assert node.receive_sequence == 0
    assert node.open_record(valid) == (1, b"hello")


def test_replay(layers):
    gateway, node = layers
    record = gateway.seal(b"hello")
    node.open_record(record)

    with pytest.raises(RecordError, match="unexpected sequence"):
        node.open_record(record)

    assert node.receive_sequence == 1


def test_record_reflection(layers):
    gateway, node = layers
    record = gateway.seal(b"hello")

    with pytest.raises(RecordError, match="invalid MAC"):
        gateway.open_record(record)

    assert gateway.receive_sequence == 0


def test_out_of_order(layers):
    gateway, node = layers
    first = gateway.seal(b"first")
    second = gateway.seal(b"second")

    with pytest.raises(RecordError, match="unexpected sequence"):
        node.open_record(second)

    assert node.receive_sequence == 0
    assert node.open_record(first) == (1, b"first")
    assert node.open_record(second) == (1, b"second")


def test_truncated_record(layers):
    gateway, node = layers
    record = gateway.seal(b"hello")

    with pytest.raises(RecordError, match="malformed record"):
        node.open_record(record[:-1])

    assert node.receive_sequence == 0


def test_long_record_rejected(layers):
    gateway, node = layers

    with pytest.raises(RecordError, match="record exceeds 16 bytes"):
        gateway.seal(b"x" * 17)

    assert gateway.send_sequence == 0


def test_sequence_exhaustion(layers):
    gateway, node = layers
    gateway.send_sequence = 1 << 64

    with pytest.raises(RecordError, match="sequence exhausted"):
        gateway.seal(b"hello")


def test_invalid_signature(signing_keys):
    gateway, node, transcript, gs, ns = prepare_handshake(*signing_keys)

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(transcript, flip(ns, 0))

    assert not gateway.accepted


def test_incorrect_public_key(signing_keys):
    gateway, node, transcript, gs, ns = prepare_handshake(*signing_keys)
    gateway.trusted_peer_key = signing_keys[0].public_key()

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(transcript, ns)

    assert not gateway.accepted


def test_handshake_reflection(signing_keys):
    gateway, node, transcript, gs, ns = prepare_handshake(*signing_keys)

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(transcript, gs)

    assert not gateway.accepted


@pytest.mark.parametrize(
    "index",
    [5, 7],
    ids=["peer_public", "peer_nonce"],
)
def test_changed_handshake_fields(signing_keys, index):
    gateway, node, transcript, gs, ns = prepare_handshake(*signing_keys)

    fields = decode_transcript(transcript)
    fields[index] = flip(fields[index], -1)

    with pytest.raises(HandshakeError, match="invalid peer signature"):
        gateway.accept(encode_fields(fields), ns)

    assert not gateway.accepted


def test_unexpected_identity(signing_keys):
    gateway, node, transcript, gs, ns = prepare_handshake(*signing_keys)

    fields = decode_transcript(transcript)
    fields[3] = b"stranger"

    with pytest.raises(HandshakeError, match="unexpected identity"):
        gateway.accept(encode_fields(fields), ns)

    assert not gateway.accepted


def test_malformed_transcript(signing_keys):
    gateway, node, transcript, gs, ns = prepare_handshake(*signing_keys)

    changed = bytearray(transcript)
    changed[:4] = (999999).to_bytes(4, "big")

    with pytest.raises(HandshakeError, match="malformed transcript"):
        gateway.accept(bytes(changed), ns)

    assert not gateway.accepted


def test_handshake_replay(signing_keys):
    gateway, node, transcript, gs, ns = prepare_handshake(*signing_keys)
    gateway.accept(transcript, ns)

    with pytest.raises(HandshakeError, match="handshake already accepted"):
        gateway.accept(transcript, ns)


def test_old_handshake_in_new_session(signing_keys):
    old_g, old_n, old_t, old_gs, old_ns = prepare_handshake(*signing_keys)
    new_g, new_n, new_t, new_gs, new_ns = prepare_handshake(*signing_keys)

    with pytest.raises(HandshakeError, match="local public value mismatch"):
        new_g.accept(old_t, old_ns)

    assert not new_g.accepted


def test_fresh_sessions(signing_keys):
    first_g, first_n = establish_session(*signing_keys)
    second_g, second_n = establish_session(*signing_keys)

    assert first_g == first_n
    assert second_g == second_n
    assert first_g != second_g
