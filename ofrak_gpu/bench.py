import asyncio
import sys
import time

from ofrak import *


async def main():
    start = time.time()
    o = OFRAK(logging_level="INFO")
    c = await o.create_ofrak_context()
    r = await c.create_root_resource_from_file(sys.argv[1])
    print("File loaded in", time.time() - start, "seconds")
    start = time.time()
    if False:
        import numpy
        from ofrak_gpu.entropy import entropy

        data = numpy.frombuffer(await r.get_data(), dtype=numpy.uint8)
        print("numpy array created in", time.time() - start, "seconds")
        start = time.time()
        entropy(device_pref="AMD").chunked_entropy(1024, data)
    else:
        from ofrak.core.entropy.entropy import DataSummaryAnalyzer

        await r.run(DataSummaryAnalyzer)
    print("Analysis completed in", time.time() - start, "seconds")


if __name__ == "__main__":
    asyncio.run(main())
