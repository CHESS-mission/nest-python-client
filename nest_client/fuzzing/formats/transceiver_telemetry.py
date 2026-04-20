"""
Transceiver — outbound UART telemetry format.
Reverse-engineered from: CHESS/Components/Transceiver/Transceiver.cpp

Fixed 9-byte packet sent periodically by F' to the OBC.
"""

from nest_client.fuzzing.message_format import Enum, Float, MessageFormat, Sync

TRANSCEIVER_TELEMETRY = MessageFormat(
    name        = "Transceiver / Telemetry packet",
    transport   = "uart",
    source      = "CHESS/Components/Transceiver/Transceiver.cpp",
    description = (
        "9-byte periodic telemetry: [0xDEADBEEF][type=0x01][F32 temperature]. "
        "Temperature = temperatureValues[0] from OBCSensorsManager (first PCT2075)."
    ),
    sections    = [
        Sync("start_word",
             value=b"\xDE\xAD\xBE\xEF",
             description="4-byte magic start-word 0xDEADBEEF."),

        Enum("pkt_type",
             bits=8,
             values={"TEMPERATURE": 0x01},
             description="Packet type/version. Currently always 0x01."),

        Float("temperature",
              bits=32, endian="big",
              description=(
                  "Current temperature in °C as IEEE-754 F32. "
                  "Sourced from temperatureValues[0] (PCT2075_0). "
                  "Fuzz: NaN/Inf test receiver parsing; large negatives test "
                  "display/threshold logic."
              )),
    ],
)

FORMATS = [TRANSCEIVER_TELEMETRY]
