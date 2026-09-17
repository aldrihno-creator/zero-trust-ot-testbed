import asyncio
import json
import logging
import sys

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

with open("/app/policy.json") as f:
    POLICY = json.load(f)

FUNCTION_CODE_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}

TARGET_HOST = POLICY["resource_host"]
TARGET_PORT = POLICY["resource_port"]
LISTEN_PORT = POLICY["listen_port"]
RULE = POLICY["rules"][0]

BASELINE_CFG = POLICY.get("baseline", {"learning_samples": 5, "tolerance_absolute": 50})
LEARNING_SAMPLES = BASELINE_CFG["learning_samples"]
TOLERANCE = BASELINE_CFG["tolerance_absolute"]

# In-memory historical baseline store: {register_address: [observed values]}
# Once len(values) >= LEARNING_SAMPLES, the mean of the learning window is
# frozen as the baseline for that register, and further deviation is judged
# against it rather than continuing to update forever.
_baseline_store = {}


def evaluate_register_value(address, value):
    """
    Returns a tuple (verdict, detail) where verdict is one of:
    'LEARNING'  - still building the baseline, response passed through
    'BASELINE-OK' - value consistent with the learned baseline, passed through
    'ANOMALY'   - value deviates from the learned baseline, response blocked
    """
    history = _baseline_store.setdefault(address, {"samples": [], "baseline": None})

    if history["baseline"] is None:
        history["samples"].append(value)
        if len(history["samples"]) >= LEARNING_SAMPLES:
            history["baseline"] = sum(history["samples"]) / len(history["samples"])
            return (
                "LEARNING",
                f"sample {len(history['samples'])}/{LEARNING_SAMPLES} "
                f"(baseline now established at {history['baseline']:.1f})",
            )
        return "LEARNING", f"sample {len(history['samples'])}/{LEARNING_SAMPLES}"

    baseline = history["baseline"]
    deviation = abs(value - baseline)
    if deviation <= TOLERANCE:
        return "BASELINE-OK", f"value={value}, baseline={baseline:.1f}, deviation={deviation:.1f} (within tolerance {TOLERANCE})"
    else:
        return "ANOMALY", f"value={value}, baseline={baseline:.1f}, deviation={deviation:.1f} (exceeds tolerance {TOLERANCE})"


def build_exception_response(mbap_bytes, unit_id, function_code):
    """Builds a Modbus exception response (function code | 0x80, exception code 0x04
    'Server Device Failure') so the client receives a clean protocol-level error
    rather than the anomalous data, and rather than just silently hanging."""
    transaction_id = mbap_bytes[0:2]
    protocol_id = mbap_bytes[2:4]
    length = (3).to_bytes(2, "big")  # unit id + function code + exception code
    return transaction_id + protocol_id + length + bytes([unit_id, function_code | 0x80, 0x04])


async def pump_request(reader, writer, peer, state):
    """Client -> Resource direction: enforce the function-code allow-list, and
    record the requested register address/quantity for the response pass to use."""
    while True:
        data = await reader.read(4096)
        if not data:
            break
        if len(data) >= 12:
            unit_id = data[6]
            function_code = data[7]
            fc_name = FUNCTION_CODE_NAMES.get(function_code, f"FC {function_code}")
            allowed = function_code in RULE["allowed_function_codes"]

            if function_code in (3, 4):
                address = int.from_bytes(data[8:10], "big")
                quantity = int.from_bytes(data[10:12], "big")
                state["last_addr"] = address
                state["last_qty"] = quantity
                state["last_unit"] = unit_id
                state["last_fc"] = function_code

            if allowed:
                logging.info(
                    f"ALLOW  {peer} -> {TARGET_HOST}:{TARGET_PORT} | {fc_name} (0x{function_code:02x})"
                )
            else:
                logging.warning(
                    f"DENY   {peer} -> {TARGET_HOST}:{TARGET_PORT} | {fc_name} (0x{function_code:02x}) "
                    f"| policy: {RULE['description']}"
                )
                continue  # drop — do not forward to the resource
        writer.write(data)
        await writer.drain()


async def pump_response(reader, writer, peer, state):
    """Resource -> Client direction: for holding/input register reads, inspect
    the returned value(s) against the historical baseline before forwarding."""
    while True:
        data = await reader.read(4096)
        if not data:
            break

        function_code = data[7] if len(data) >= 8 else None
        is_register_read = state.get("last_fc") in (3, 4) and function_code == state.get("last_fc")

        if is_register_read and len(data) >= 9:
            byte_count = data[8]
            address = state["last_addr"]
            values = []
            for i in range(0, byte_count, 2):
                offset = 9 + i
                if offset + 2 <= len(data):
                    values.append(int.from_bytes(data[offset:offset + 2], "big"))

            blocked = False
            for i, value in enumerate(values):
                reg_addr = address + i
                verdict, detail = evaluate_register_value(reg_addr, value)
                if verdict == "ANOMALY":
                    logging.warning(
                        f"ANOMALY {TARGET_HOST}:{TARGET_PORT} -> {peer} | register {reg_addr} | {detail} "
                        f"| response BLOCKED, exception returned to client"
                    )
                    blocked = True
                else:
                    logging.info(
                        f"{verdict:<11} {TARGET_HOST}:{TARGET_PORT} -> {peer} | register {reg_addr} | {detail}"
                    )

            if blocked:
                exception_resp = build_exception_response(data[0:4], state.get("last_unit", 0), state.get("last_fc", 3))
                writer.write(exception_resp)
                await writer.drain()
                continue

        writer.write(data)
        await writer.drain()


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            TARGET_HOST, TARGET_PORT
        )
    except Exception as e:
        logging.error(f"PEP: cannot reach resource {TARGET_HOST}:{TARGET_PORT} - {e}")
        writer.close()
        return

    state = {"last_addr": None, "last_qty": None, "last_unit": None, "last_fc": None}

    await asyncio.gather(
        pump_request(reader, upstream_writer, peer, state),
        pump_response(upstream_reader, writer, peer, state),
    )
    writer.close()
    upstream_writer.close()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    logging.info(
        f"Modbus PEP (with baseline anomaly detection) listening on 0.0.0.0:{LISTEN_PORT}, "
        f"forwarding permitted traffic to {TARGET_HOST}:{TARGET_PORT} | "
        f"learning_samples={LEARNING_SAMPLES}, tolerance={TOLERANCE}"
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
