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
RULE = POLICY["rules"][0]  # single subject-resource pair for this testbed


async def pump_request(reader, writer, peer):
    """Client -> Resource direction: inspect and enforce policy."""
    while True:
        data = await reader.read(4096)
        if not data:
            break
        if len(data) >= 8:
            function_code = data[7]
            fc_name = FUNCTION_CODE_NAMES.get(function_code, f"FC {function_code}")
            allowed = function_code in RULE["allowed_function_codes"]
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


async def pump_response(reader, writer):
    """Resource -> Client direction: pass responses straight through."""
    while True:
        data = await reader.read(4096)
        if not data:
            break
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

    await asyncio.gather(
        pump_request(reader, upstream_writer, peer),
        pump_response(upstream_reader, writer),
    )
    writer.close()
    upstream_writer.close()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    logging.info(
        f"Modbus PEP listening on 0.0.0.0:{LISTEN_PORT}, forwarding permitted "
        f"traffic to {TARGET_HOST}:{TARGET_PORT}"
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
