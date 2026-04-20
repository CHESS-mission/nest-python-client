"""
I2C sensor format descriptions.
Reverse-engineered from: CHESS/Components/OBCSensorsManager/OBCSensorsManager.cpp

Each MessageFormat describes one I2C transaction (write or read response).
The mutation engine handles all mutation logic; this file only describes structure.

Implementation bugs preserved as structural notes in descriptions:
  BUG-1  PCT2075 sign-extension mismatch between poller and command handler
  BUG-2  MMC5983MA: poller reads 6 bytes (drops 2 LSBs); cmd handler reads 7
  BUG-3  isSensorDataValid() rejects all-0x00 and all-0xFF responses
"""

from nest_client.fuzzing.message_format import (
    BitField, Flags, Integer, MessageFormat, RawBytes
)

_SOURCE = "CHESS/Components/OBCSensorsManager/OBCSensorsManager.cpp"


# ===========================================================================
# PCT2075 — Temperature sensor  (addresses 0x48-0x4F)
# ===========================================================================
#
# Poll sequence:
#   write [0x00]        → set register pointer to Temp register
#   read  2 bytes       → raw temperature
#
# Config write (on entering NOMINAL or CONFIG state):
#   write [0x01, 0x00]  → Config register = normal mode

PCT2075_CONFIG_WRITE = MessageFormat(
    name        = "PCT2075 / Config register write",
    transport   = "i2c_write",
    source      = _SOURCE,
    description = "Write [0x01, 0x00] to set Config register to normal mode.",
    sections    = [
        Integer("reg_addr",
                bits=8,
                description="Register address. 0x01 = Config. Other values redirect the write."),

        Flags("config",
              bits=8,
              fields=[
                  BitField("SHUTDOWN",    0, 1, "1=stop conversions, 0=normal"),
                  BitField("OS_F_QUE",    1, 2, "fault queue: 00→1, 01→2, 10→4, 11→6 faults"),
                  BitField("OS_POL",      3, 1, "OS polarity: 0=active-low, 1=active-high"),
                  BitField("OS_COMP_INT", 4, 1, "OS mode: 0=comparator, 1=interrupt"),
                  # bits [7:5] reserved (not listed → engine will flag them as FLAG_RESERVED)
              ],
              description="PCT2075 configuration byte. F' writes 0x00 = normal mode."),
    ],
)

PCT2075_TEMP_READ = MessageFormat(
    name        = "PCT2075 / Temperature register read (2 bytes)",
    transport   = "i2c_read",
    source      = _SOURCE,
    description = (
        "2-byte response from register 0x00. "
        "raw16[15:5] = 11-bit signed temperature × 0.125 °C. raw16[4:0] = 0 (reserved). "
        "BUG-3: all-0x00 or all-0xFF rejected by isSensorDataValid(). "
        "BUG-1: OBC_REQUEST_TEMP_DATA checks raw16 bit-10 as sign bit (WRONG — "
        "should check bit-15 after shifting). Values raw16 ∈ [0x0400, 0x7BFF] "
        "produce opposite signs between pollTempSensor() and the command handler."
    ),
    sections    = [
        Flags("temp_msb",
              bits=8,
              fields=[
                  BitField("SIGN",    7, 1, "Sign bit of 11-bit temperature (bit 10 of 11-bit value)"),
                  BitField("TEMP_HI", 0, 7, "Temperature bits [9:3]"),
              ],
              description=(
                  "High byte. Bit 7 = sign of 11-bit value. "
                  "0xC9=−55°C, 0x00=0°C, 0x19=+25°C, 0x7D=+125°C. "
                  "BUG-1 window: 0x04–0x7B (bit10=1, bit15=0 → sign mismatch)."
              )),

        Flags("temp_lsb",
              bits=8,
              fields=[
                  BitField("TEMP_LO",   3, 5, "Temperature bits [2:0] padded to 5 bits"),
                  BitField("RESERVED",  0, 3, "Reserved bits [2:0], must be 0. F' ignores them."),
              ],
              description="Low byte. Bits [7:3] extend the temperature value. Bits [2:0] reserved."),
    ],
)

PCT2075_FORMATS = [PCT2075_CONFIG_WRITE, PCT2075_TEMP_READ]


# ===========================================================================
# IIM-42652 — 6-axis IMU  (address 0x68)
# ===========================================================================
#
# Config write (configSensors):
#   write [0x4E, 0x0F]   → PWR_MGMT0: accel+gyro low-noise mode
#
# Poll sequence:
#   write [0x1F]          → set register pointer to ACCEL_DATA_X1
#   read  14 bytes        → AX AY AZ GX GY GZ + 2 ignored bytes

IIM42652_CONFIG_WRITE = MessageFormat(
    name        = "IIM-42652 / PWR_MGMT0 config write",
    transport   = "i2c_write",
    source      = _SOURCE,
    description = "Write [0x4E, 0x0F] to configure accel+gyro power and mode.",
    sections    = [
        Integer("reg_addr",
                bits=8,
                description="Register address. 0x4E = PWR_MGMT0."),

        Flags("pwr_mgmt0",
              bits=8,
              fields=[
                  BitField("ACCEL_MODE", 0, 2, "00=off, 10=low-power, 11=low-noise"),
                  BitField("GYRO_MODE",  2, 2, "00=off, 01=standby, 11=low-noise"),
                  BitField("IDLE",       4, 1, "1=keep RC oscillator on when both off"),
                  BitField("TEMP_DIS",   5, 1, "1=disable temperature sensor"),
                  # bits [7:6] reserved
              ],
              description="F' writes 0x0F = accel+gyro both in low-noise mode."),
    ],
)

IIM42652_DATA_READ = MessageFormat(
    name        = "IIM-42652 / Accel+Gyro burst read (14 bytes from 0x1F)",
    transport   = "i2c_read",
    source      = _SOURCE,
    description = (
        "14-byte burst starting at register 0x1F. "
        "Bytes [0-5]: ACCEL XYZ, big-endian I16, ÷2048 → g (±16g FSR). "
        "Bytes [6-11]: GYRO XYZ, big-endian I16, ×(250/16.4) → °/s. "
        "Bytes [12-13]: ignored by F' (could be temperature). "
        "BUG-3: all-0x00 or all-0xFF rejected by isSensorDataValid()."
    ),
    sections    = [
        Integer("accel_x", bits=16, signed=True, endian="big",
                description="Accelerometer X. 1g=0x0800, −1g=0xF800, ±16g FSR."),
        Integer("accel_y", bits=16, signed=True, endian="big",
                description="Accelerometer Y."),
        Integer("accel_z", bits=16, signed=True, endian="big",
                description="Accelerometer Z. ~0x0800 at rest (1g downward)."),
        Integer("gyro_x",  bits=16, signed=True, endian="big",
                description="Gyroscope X. 250°/s ≈ 0x0FA0. ±250°/s FSR."),
        Integer("gyro_y",  bits=16, signed=True, endian="big",
                description="Gyroscope Y."),
        Integer("gyro_z",  bits=16, signed=True, endian="big",
                description="Gyroscope Z."),
        RawBytes("unused_bytes_12_13", length=2,
                 description="Bytes [12-13] ignored by F'. May contain IMU temperature."),
    ],
)

IIM42652_FORMATS = [IIM42652_CONFIG_WRITE, IIM42652_DATA_READ]


# ===========================================================================
# MMC5983MA — Magnetometer  (address 0x30)
# ===========================================================================
#
# Config write (configSensors):
#   write [0x0B, 0x04]   → CTRL2: frequency/mode configuration
#
# Poll sequence (pollMagnetometer — Path A):
#   write [0x09, 0x01]   → CTRL0: trigger one-shot measurement
#   write [0x00]          → set register pointer
#   read  6 bytes         → Xout[17:2], Yout[17:2], Zout[17:2]
#                           (2 LSBs of each axis DISCARDED — BUG-2)
#
# Command handler (OBC_REQUEST_MAG_DATA — Path B):
#   write [0x00]          → set register pointer
#   read  7 bytes         → same 6 bytes + byte6 packed 2-LSB triplet
#                           (full 18-bit precision — byte 6 invisible to Path A)

MMC5983MA_CTRL0_TRIGGER = MessageFormat(
    name        = "MMC5983MA / CTRL0 trigger write (Path A only)",
    transport   = "i2c_write",
    source      = _SOURCE,
    description = "Trigger one-shot measurement. Used only by pollMagnetometer(), not by command handler.",
    sections    = [
        Integer("reg_addr", bits=8,
                description="0x09 = CTRL0 register."),

        Flags("ctrl0",
              bits=8,
              fields=[
                  BitField("TM_M",       0, 1, "Trigger magnetic measurement (self-clearing)"),
                  BitField("TM_T",       1, 1, "Trigger temperature measurement"),
                  BitField("START_MDT",  2, 1, "Start motion detection timer"),
                  BitField("DO_RESET",   3, 1, "Execute RESET pulse (demagnetise)"),
                  BitField("DO_SET",     4, 1, "Execute SET pulse (re-magnetise)"),
                  BitField("AUTO_SR_EN", 5, 1, "Enable automatic SET/RESET"),
                  BitField("OTP_READ",   6, 1, "Reload shadow registers from OTP"),
                  # bit 7 reserved
              ],
              description="F' writes 0x01 = TM_M only."),
    ],
)

MMC5983MA_CTRL2_CONFIG = MessageFormat(
    name        = "MMC5983MA / CTRL2 config write",
    transport   = "i2c_write",
    source      = _SOURCE,
    description = "Write [0x0B, 0x04] to configure measurement mode. Sent during configSensors().",
    sections    = [
        Integer("reg_addr", bits=8,
                description="0x0B = CTRL2 register."),

        Flags("ctrl2",
              bits=8,
              fields=[
                  BitField("CMM_FREQ_EN",     0, 1, "Enable CMM frequency selection"),
                  BitField("PRD_SET",         1, 3, "Periodic SET interval: 000→1, 001→25, 010→75 samples, …"),
                  BitField("EN_PRD_SET",      4, 1, "Enable periodic SET in CMM"),
                  BitField("CMM_EN",          5, 1, "Enable continuous measurement mode"),
                  BitField("INT_MEAS_DONE_EN",6, 1, "Interrupt on measurement completion"),
                  BitField("HPOWER",          7, 1, "High-power mode"),
              ],
              description="F' writes 0x04 = PRD_SET=010 (75-sample interval)."),
    ],
)

MMC5983MA_DATA_READ_6B = MessageFormat(
    name        = "MMC5983MA / Output burst read, 6 bytes (Path A — poller)",
    transport   = "i2c_read",
    source      = _SOURCE,
    description = (
        "6-byte response from register 0x00. "
        "axis_raw = (hi_byte << 10) | (lo_byte << 2) — bits [1:0] always 0. "
        "physical = (raw − 131072) / 16384. "
        "BUG-2: byte 6 (2-LSB triplet) NOT read → 2 LSBs of each axis discarded. "
        "BUG-3: all-0x00 or all-0xFF rejected."
    ),
    sections    = [
        Integer("x_hi", bits=8,
                description="Xout[17:10]. 0x20=null-field MSB, 0x00=min, 0x3F=max."),
        Integer("x_lo", bits=8,
                description="Xout[9:2]. Parsed as (byte << 2) → bits [9:2]."),
        Integer("y_hi", bits=8,
                description="Yout[17:10]."),
        Integer("y_lo", bits=8,
                description="Yout[9:2]."),
        Integer("z_hi", bits=8,
                description="Zout[17:10]."),
        Integer("z_lo", bits=8,
                description="Zout[9:2]."),
    ],
)

MMC5983MA_DATA_READ_7B = MessageFormat(
    name        = "MMC5983MA / Output burst read, 7 bytes (Path B — command handler)",
    transport   = "i2c_read",
    source      = _SOURCE,
    description = (
        "7-byte response. Full 18-bit precision. "
        "mx_raw = (b0<<10)|(b1<<2)|((b6&0xC0)>>6). "
        "my_raw = (b2<<10)|(b3<<2)|((b6&0x30)>>4). "
        "mz_raw = (b4<<10)|(b5<<2)|((b6&0x0C)>>2). "
        "BUG-2: byte 6 INVISIBLE to the poller — only this path uses it. "
        "BUG-2 (also): this path does NOT trigger a new measurement first."
    ),
    sections    = [
        Integer("x_hi", bits=8, description="Xout[17:10]."),
        Integer("x_lo", bits=8, description="Xout[9:2]."),
        Integer("y_hi", bits=8, description="Yout[17:10]."),
        Integer("y_lo", bits=8, description="Yout[9:2]."),
        Integer("z_hi", bits=8, description="Zout[17:10]."),
        Integer("z_lo", bits=8, description="Zout[9:2]."),
        Flags("xyz_lsb_packed",
              bits=8,
              fields=[
                  BitField("X_LSB", 6, 2, "Xout[1:0]"),
                  BitField("Y_LSB", 4, 2, "Yout[1:0]"),
                  BitField("Z_LSB", 2, 2, "Zout[1:0]"),
                  # bits [1:0] unused
              ],
              description=(
                  "2-LSB triplet for X, Y, Z. "
                  "INVISIBLE to pollMagnetometer (Path A). "
                  "Bits [1:0] unused by F'."
              )),
    ],
)

MMC5983MA_FORMATS = [
    MMC5983MA_CTRL0_TRIGGER,
    MMC5983MA_CTRL2_CONFIG,
    MMC5983MA_DATA_READ_6B,
    MMC5983MA_DATA_READ_7B,
]


# ===========================================================================
# Registry
# ===========================================================================

ALL_FORMATS = PCT2075_FORMATS + IIM42652_FORMATS + MMC5983MA_FORMATS
