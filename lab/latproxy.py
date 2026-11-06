#!/usr/bin/env python3
"""Latency-injecting TCP relay for benchmarks (loopback only; this kernel has no netem).

Listens on 127.0.20.k:<port> and relays to 127.0.10.k:<port>, delaying every chunk by D ms in each
direction, so a request/response costs 2*D and each TLS flight costs a round trip. The TCP handshake
itself is not delayed (it completes in the kernel before accept), so connect RTT is NOT emulated.
usage: latproxy.py <one-way-ms> <hosts> <port> [<port> ...]
"""
import asyncio, sys, time

D = float(sys.argv[1]) / 1000.0
N = int(sys.argv[2])
PORTS = [int(p) for p in sys.argv[3:]]


async def pump(reader, writer):
    q = asyncio.Queue()

    async def sender():
        while True:
            due, data = await q.get()
            wait = due - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            if data is None:
                try:
                    writer.write_eof()
                except Exception:
                    pass
                return
            writer.write(data)
            await writer.drain()
    t = asyncio.ensure_future(sender())
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            q.put_nowait((time.monotonic() + D, data))
    except Exception:
        pass
    q.put_nowait((time.monotonic() + D, None))
    try:
        await t
    except Exception:
        pass


def handler(dst_ip, port):
    async def handle(creader, cwriter):
        try:
            sreader, swriter = await asyncio.open_connection(dst_ip, port)
        except Exception:
            cwriter.close(); return
        try:
            await asyncio.gather(pump(creader, swriter), pump(sreader, cwriter))
        except Exception:
            pass
        finally:
            for w in (cwriter, swriter):
                try:
                    w.close()
                except Exception:
                    pass
    return handle


async def main():
    asyncio.get_running_loop().set_exception_handler(lambda l, c: None)
    for k in range(1, N + 1):
        for p in PORTS:
            await asyncio.start_server(handler("127.0.10.%d" % k, p), "127.0.20.%d" % k, p, backlog=256)
    print("latproxy up: %d hosts x %s, one-way %.0f ms" % (N, PORTS, D * 1000), flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
