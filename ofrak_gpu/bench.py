import asyncio
import sys
import time
from ofrak import *
from ofrak.core.entropy.entropy import DataSummaryAnalyzer
import numpy
from ofrak.core.entropy.entropy import DataSummary
from ofrak_gpu.entropy import entropy
import statistics

kill_thread = False


def print_progress(e):
    last_logged_progress = None
    global kill_thread
    while not kill_thread:
        if hasattr(e, "test_progress"):
            if e.test_progress != last_logged_progress:
                print(f"Progress: {e.test_progress}")
                last_logged_progress = e.test_progress


async def main():
    global kill_thread

    start = time.time()
    o = OFRAK(logging_level="WARN")
    c = await o.create_ofrak_context()
    r = await c.create_root_resource_from_file(sys.argv[1])
    print("File loaded in", time.time() - start, "seconds")

    start = time.time()
    data = numpy.frombuffer(await r.get_data(), dtype=numpy.uint8)
    e = entropy(device_pref="AMD")
    # progress_thread = threading.Thread(target=print_progress, args=(e,))
    # progress_thread.start()

    print("numpy array created in", time.time() - start, "seconds")

    times = []

    for _ in range(50):
        start = time.time()
        # print(e.queue.get_info(cl.command_queue_info.DEVICE))
        results = e.chunked_entropy(256, data)
        GPU_time = time.time() - start
        times.append(GPU_time)
        # print("Results len:", len(results))
        # print("Results type:", type(results))
        # print("Get:", results.get(), type(results.get()))
        # print(results.get())

        # print("GPU Analysis completed in", GPU_time, "seconds")

    print(f"Average time: {statistics.fmean(times)} seconds")
    return
    start = time.time()
    await r.run(DataSummaryAnalyzer)
    Current_time = time.time() - start
    print("Current analysis completed in", Current_time, "seconds")
    # Calculate speedup percentage
    speedup_percentage = ((Current_time - GPU_time) / Current_time) * 100

    results = r.get_attributes(DataSummary)
    print("DataSummaryAnalyzer results:", len(results.entropy_samples))
    # print([results.entropy_samples[x] for x in range(0, len(results.entropy_samples), 256)])
    # print(results.entropy_samples[len(results.entropy_samples) - 1])

    print(f"Speedup: {speedup_percentage:.2f}%")
    kill_thread = True
    progress_thread.join()


if __name__ == "__main__":
    asyncio.run(main())
