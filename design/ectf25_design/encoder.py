"""
Author: TrustLab Team
Date: 2025

This source file is part of a secure satellite TV transmission system for MITRE's 2025
Embedded System CTF (eCTF). This code implements the secure encoder for the satellite
TV system.

Copyright: Copyright (c) 2025
"""

import argparse
import struct
import json
import base64
import time
from Crypto.Random import get_random_bytes

from .utils import (
    aes_ctr_encrypt,
    derive_key_from_master,
    create_nonce_from_seq_channel,
    bytes_to_hex
)


class Encoder:
    def __init__(self, secrets: bytes):
        """
        Initialize the encoder with system secrets.

        :param secrets: Contents of the secrets file generated by
            ectf25_design.gen_secrets
        """
        # Parse the secrets JSON
        secrets_json = json.loads(secrets)

        # Extract and decode the cryptographic material
        self.master_key = base64.b64decode(secrets_json["master_key"])
        self.encoder_id = base64.b64decode(secrets_json["encoder_id"])

        # Ensure master_key and encoder_id are in bytes format
        if isinstance(self.master_key, bytearray):
            self.master_key = bytes(self.master_key)
        if isinstance(self.encoder_id, bytearray):
            self.encoder_id = bytes(self.encoder_id)

        self.current_seq_num = secrets_json.get("initial_seq_num", 1)

        # Keep track of valid channels
        self.valid_channels = [0] + secrets_json["channels"]  # Channel 0 is always valid

        # Create a dictionary to store derived keys for each channel
        self.channel_keys = {}

        # Pre-derive keys for each channel to improve performance
        for channel in self.valid_channels:
            channel_key = derive_key_from_master(
                self.master_key,
                f"CHANNEL_{channel}"
            )
            # Ensure channel key is in bytes format
            if isinstance(channel_key, bytearray):
                channel_key = bytes(channel_key)
            self.channel_keys[channel] = channel_key


def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
    """El frame encoder modificado para NO cifrar canal 0."""
    # Validar que el canal es válido
    if channel not in self.valid_channels:
        raise ValueError(f"Channel {channel} is not valid")

    # Incrementar el sequence number
    seq_num = self.current_seq_num
    self.current_seq_num += 1

    # Crear el header (seq_num + channel + encoder_id)
    encoder_id_bytes = self.encoder_id
    header = struct.pack("<II", seq_num, channel) + encoder_id_bytes

    # Crear la parte de datos: frame + timestamp + sequence number
    plaintext = frame + struct.pack("<QI", timestamp, seq_num)

    if channel == 0:
        # Para canal 0 (emergencia), NO ciframos, enviamos el plaintext directamente
        final_payload = header + plaintext
    else:
        # Para otros canales, ciframos como antes
        channel_key = self.channel_keys[channel]
        nonce = create_nonce_from_seq_channel(seq_num, channel)
        ciphertext, _ = aes_ctr_encrypt(channel_key, plaintext, nonce)
        final_payload = header + ciphertext

    return final_payload


def main():
    """A test main to one-shot encode a frame

    This function is only for your convenience and will not be used in the final design.

    After pip-installing, you should be able to call this with:
        python3 -m ectf25_design.encoder path/to/test.secrets 1 "frame to encode" 100
    """
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file"
    )
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    encoded_frame = encoder.encode(args.channel, args.frame.encode(), args.timestamp)
    print(f"Encoded frame: {bytes_to_hex(encoded_frame)}")
    print(f"Length: {len(encoded_frame)} bytes")


if __name__ == "__main__":
    main()
