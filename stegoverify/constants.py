"""Sample messages required by the assignment (short / large / custom)."""

APP_NAME = "StegoVerify"
APP_VERSION = "1.0"

SHORT_MESSAGE = ("LO3: Use digital signatures to verify that a payload or file record was issued "
                 "by a legitimate signer and has not been altered.")

LARGE_MESSAGE = (
    "This undergraduate project requires student teams to design, implement and demonstrate a "
    "GUI-based LSB Replacement steganography program (window-based or web-based) that protects and "
    "verifies both image and audio cover objects using steganography, hashing and digital signatures. "
    "The project focuses on practical cybersecurity concepts: hiding a verification payload inside an "
    "image and an audio file, signing relevant verification data, extracting the hidden payload, "
    "checking the digital signature, and demonstrating positive and negative verification cases. "
    "Video as a cover object is not required for the main assignment, but may be attempted as an "
    "optional challenge.")

CUSTOM_MESSAGE = (
    "CONFIDENTIAL RELEASE RECORD\n"
    "asset: press_kit_hero_v3\n"
    "approved_by: media-verification-team\n"
    "licence: internal-use-only\n"
    "contact: release-desk@example.org\n"
    "note: this record is AES-256-GCM encrypted inside the signed payload, so only holders of the "
    "release passphrase can read it, and any modification is detected by both the GCM tag and the "
    "Ed25519 signature.")
