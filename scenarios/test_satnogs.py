import base64
from nest_client import *


#Uplink 

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_send_packet():
    """send_packet queues packets correctly."""
    payload = base64.b64encode(b"hello from ground").decode()

    with timeline() as t:
        t[1 * s] = command("Satnogs", "send_packet", payload)
        t[2 * s] = command("Satnogs", "send_packet", base64.b64encode(b"second packet").decode())


#  Ping

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_ping():
    """COMMS_PING is acknowledged with no error."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_PING", "")


#  Status

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_status_off():
    """Status is 'off' before UHF is enabled."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[1 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "off") \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_status_idle():
    """Status is 'idle' after UHF is enabled but before RX starts."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[2 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "idle") \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_status_rx():
    """Status is 'rx' after UHF is enabled and RX started."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_START_UHF_RX", "")
        t[3 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[3 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "rx") \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_status_safe():
    """Status is 'safe' after entering safe mode."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_ENTER_SAFE_MODE", "")
        t[3 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[3 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "safe") \
            .expect(within=2 * s)


#  UHF enable / disable 

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_uhf_enable_disable():
    """Disabling UHF also stops RX."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_START_UHF_RX", "")
        t[3 * s] = command("Satnogs", "COMMS_DISABLE_UHF", "")
        t[4 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[4 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "off") \
            .expect(within=2 * s)


#  RX control 

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_stop_rx():
    """COMMS_STOP_UHF_RX returns to idle."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_START_UHF_RX", "")
        t[3 * s] = command("Satnogs", "COMMS_STOP_UHF_RX", "")
        t[4 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[4 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "idle") \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_stop_rf():
    """COMMS_STOP_RF stops reception."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_START_UHF_RX", "")
        t[3 * s] = command("Satnogs", "COMMS_STOP_RF", "")
        t[4 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[4 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "idle") \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_reset_radio():
    """COMMS_RESET_UHF_RADIO returns to off."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_START_UHF_RX", "")
        t[3 * s] = command("Satnogs", "COMMS_RESET_UHF_RADIO", "")
        t[4 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[4 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "off") \
            .expect(within=2 * s)


#  RX queue 

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_queue_available():
    """Queue reports available after send_packet."""
    payload = base64.b64encode(b"test").decode()
    with timeline() as t:
        t[1 * s] = command("Satnogs", "send_packet", payload)
        t[2 * s] = command("Satnogs", "COMMS_CHECK_RX_FRAME_AVAILABLE", "")
        t[2 * s] = event("Satnogs", "rx_frame_available") \
            .where(lambda d: d["available"] == True and d["queue_depth"] == 1) \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_queue_status():
    """Queue status depth matches number of queued packets."""
    payload = base64.b64encode(b"packet").decode()
    with timeline() as t:
        t[1 * s] = command("Satnogs", "send_packet", payload)
        t[2 * s] = command("Satnogs", "send_packet", payload)
        t[3 * s] = command("Satnogs", "COMMS_GET_RX_QUEUE_STATUS", "")
        t[3 * s] = event("Satnogs", "rx_queue_status") \
            .where(lambda d: d["queue_depth"] == 2) \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_flush_queue():
    """COMMS_FLUSH_RX_QUEUE empties the queue."""
    payload = base64.b64encode(b"packet").decode()
    with timeline() as t:
        t[1 * s] = command("Satnogs", "send_packet", payload)
        t[2 * s] = command("Satnogs", "send_packet", payload)
        t[3 * s] = command("Satnogs", "COMMS_FLUSH_RX_QUEUE", "")
        t[4 * s] = command("Satnogs", "COMMS_CHECK_RX_FRAME_AVAILABLE", "")
        t[4 * s] = event("Satnogs", "rx_frame_available") \
            .where(lambda d: d["available"] == False and d["queue_depth"] == 0) \
            .expect(within=2 * s)


#  UHF status and stats

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_uhf_status():
    """COMMS_GET_UHF_STATUS reflects current radio flags."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_START_UHF_RX", "")
        t[3 * s] = command("Satnogs", "COMMS_GET_UHF_STATUS", "")
        t[3 * s] = event("Satnogs", "uhf_status") \
            .where(lambda d: d["enabled"] == True and d["receiving"] == True) \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_link_stats():
    """COMMS_GET_UHF_LINK_STATS and COMMS_CLEAR_UHF_LINK_STATS work correctly."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_UHF_LINK_STATS", "")
        t[1 * s] = event("Satnogs", "uhf_link_stats") \
            .where(lambda d: d["rx_count"] == 0 and d["tx_count"] == 0) \
            .expect(within=2 * s)
        t[3 * s] = command("Satnogs", "COMMS_CLEAR_UHF_LINK_STATS", "")
        t[4 * s] = command("Satnogs", "COMMS_GET_UHF_LINK_STATS", "")
        t[4 * s] = event("Satnogs", "uhf_link_stats") \
            .where(lambda d: d["rx_count"] == 0 and d["tx_count"] == 0) \
            .expect(within=2 * s)


#  Version and capabilities

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_version():
    """COMMS_GET_VERSION emits a version event."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_VERSION", "")
        t[1 * s] = event("Satnogs", "version") \
            .where(lambda d: "firmware" in d) \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_capabilities():
    """COMMS_GET_CAPABILITIES reports UHF band."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_CAPABILITIES", "")
        t[1 * s] = event("Satnogs", "capabilities") \
            .where(lambda d: "uhf" in d["bands"]) \
            .expect(within=2 * s)


#  TX queries 
@scenario(topology_file="./satnogs.yaml")
def test_satnogs_tx_status_idle():
    """TX status is idle since COMMS_TRANSMIT_UHF_FRAME is not yet implemented."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_TX_STATUS", "")
        t[1 * s] = event("Satnogs", "tx_status") \
            .where(lambda d: d["status"] == "idle") \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_abort_tx():
    """COMMS_ABORT_TX returns idle when no transmission is active."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ABORT_TX", "")
        t[1 * s] = event("Satnogs", "abort_tx_result") \
            .where(lambda d: d["status"] == "idle") \
            .expect(within=2 * s)


#  Safe mode 
@scenario(topology_file="./satnogs.yaml")
def test_satnogs_safe_mode_stops_rx():
    """Entering safe mode stops active RX."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_START_UHF_RX", "")
        t[3 * s] = command("Satnogs", "COMMS_ENTER_SAFE_MODE", "")
        t[4 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[4 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "safe") \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_exit_safe_mode():
    """Exiting safe mode returns to idle."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_ENTER_SAFE_MODE", "")
        t[3 * s] = command("Satnogs", "COMMS_EXIT_SAFE_MODE", "")
        t[4 * s] = command("Satnogs", "COMMS_GET_STATUS", "")
        t[4 * s] = event("Satnogs", "status") \
            .where(lambda d: d["state"] == "idle") \
            .expect(within=2 * s)


#  Beacon

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_beacon():
    """Beacon enable/disable and transmit work correctly."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_BEACON", "")
        t[2 * s] = command("Satnogs", "COMMS_SET_BEACON_CONFIG", "period=30")
        t[3 * s] = command("Satnogs", "COMMS_TRANSMIT_BEACON", "beacon_payload")
        t[3 * s] = event("Satnogs", "beacon_transmitted") \
            .expect(within=2 * s)
        t[5 * s] = command("Satnogs", "COMMS_DISABLE_BEACON", "")


# Faults / diagnostics 

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_no_faults():
    """Twin reports no faults by default."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_FAULT_STATUS", "")
        t[1 * s] = event("Satnogs", "fault_status") \
            .where(lambda d: d["active_faults"] == False) \
            .expect(within=2 * s)
        t[3 * s] = command("Satnogs", "COMMS_GET_FAULTS", "")
        t[3 * s] = event("Satnogs", "faults") \
            .where(lambda d: d["flags"] == []) \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_self_test():
    """Self-test always passes in the twin."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_SELF_TEST", "")
        t[2 * s] = command("Satnogs", "COMMS_GET_SELF_TEST_RESULT", "")
        t[2 * s] = event("Satnogs", "self_test_result") \
            .where(lambda d: d["passed"] == True) \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_reset_reason():
    """Reset reason is always power_on in the twin."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_RESET_REASON", "")
        t[1 * s] = event("Satnogs", "reset_reason") \
            .where(lambda d: d["reason"] == "power_on") \
            .expect(within=2 * s)


#  State change tracking

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_state_change_status():
    """State change status tracks previous and current state."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_ENABLE_UHF", "")
        t[2 * s] = command("Satnogs", "COMMS_GET_STATE_CHANGE_STATUS", "")
        t[2 * s] = event("Satnogs", "state_change_status") \
            .where(lambda d: d["previous_state"] == "off" and d["current_state"] == "idle") \
            .expect(within=2 * s)


# Contact window

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_contact_window():
    """Contact window can be set and cleared."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_SET_CONTACT_WINDOW", "2026-06-01T12:00:00/PT10M")
        t[2 * s] = command("Satnogs", "COMMS_CLEAR_CONTACT_WINDOW", "")


# Fault injection
@scenario(topology_file="./satnogs.yaml")
def test_satnogs_simulate_fault():
    """simulate_fault causes fault commands to report an active fault."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_GET_FAULT_STATUS", "")
        t[1 * s] = event("Satnogs", "fault_status") \
            .where(lambda d: d["active_faults"] == False) \
            .expect(within=2 * s)
        t[3 * s] = command("Satnogs", "simulate_fault", "pa_overheat")
        t[4 * s] = command("Satnogs", "COMMS_GET_FAULT_STATUS", "")
        t[4 * s] = event("Satnogs", "fault_status") \
            .where(lambda d: d["active_faults"] == True) \
            .expect(within=2 * s)
        t[6 * s] = command("Satnogs", "COMMS_GET_FAULTS", "")
        t[6 * s] = event("Satnogs", "faults") \
            .where(lambda d: "pa_overheat" in d["flags"]) \
            .expect(within=2 * s)


@scenario(topology_file="./satnogs.yaml")
def test_satnogs_clear_fault():
    """COMMS_CLEAR_FAULTS removes the injected fault."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "simulate_fault", "spi_error")
        t[2 * s] = command("Satnogs", "COMMS_CLEAR_FAULTS", "")
        t[3 * s] = command("Satnogs", "COMMS_GET_FAULT_STATUS", "")
        t[3 * s] = event("Satnogs", "fault_status") \
            .where(lambda d: d["active_faults"] == False) \
            .expect(within=2 * s)


#  Unknown command 

@scenario(topology_file="./satnogs.yaml")
def test_satnogs_unknown_command():
    """Unknown commands are rejected without crashing."""
    with timeline() as t:
        t[1 * s] = command("Satnogs", "COMMS_NONEXISTENT_COMMAND", "")
