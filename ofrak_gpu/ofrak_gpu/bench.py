import asyncio
import time

# from ofrak.core.entropy.entropy import DataSummaryAnalyzer
import numpy

# from ofrak.core.entropy.entropy import DataSummary

kill_thread = False

from guppy import hpy


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
    # o = OFRAK(logging_level="WARN")
    # c = await o.create_ofrak_context()
    # r = await c.create_root_resource_from_file(sys.argv[1])
    # print("File loaded in", time.time() - start, "seconds")

    # chosen_platform, chosen_device = pick_pyopencl_device()

    # e = entropy(platform_pref=chosen_platform, device_pref=chosen_device, interactive=False)
    import random

    for i in range(10):
        random_data = numpy.random.bytes(random.randint(1, 750) * 1024 * 1024)
        start = time.time()
        # data = numpy.frombuffer(await r.get_data(), dtype=numpy.uint8)
        np_data = numpy.frombuffer(random_data, dtype=numpy.uint8)
        numpy_time = time.time() - start
        print("numpy array created in", numpy_time, "seconds")

        size_1 = hpy().heap().size
        del np_data

        start = time.time()
        data = numpy.asanyarray(memoryview(random_data).cast("B"))
        memview_time = time.time() - start

        size_2 = hpy().heap().size

        # raw_data = await r.get_data()
        # data = cl.array.Array(cq=e.ctx, data=memoryview(raw_data).cast('B') , shape=len(raw_data), dtype=numpy.uint8)
        print("memoryview array created in", memview_time, "seconds")
        print(f"Size of ndarray: {data.nbytes/(1024 ** 2):.2f} MB")
        print(f"Speedup: {((numpy_time - memview_time) / numpy_time) * 100:.2f}%")
        print(f"Smaller by {size_2 - size_1} B")
    return
    # data = await r.get_data()
    # cl.array.Array(cq=e.ctx, data=data)

    # times = []

    # for _ in range(50):
    #     start = time.time()
    #     # print(e.queue.get_info(cl.command_queue_info.DEVICE))
    #     results = e.chunked_entropy(256, data)
    #     GPU_time = time.time() - start
    #     times.append(GPU_time)
    #     # print("Results len:", len(results))
    #     # print("Results type:", type(results))
    #     # print("Get:", results.get(), type(results.get()))
    #     # print(results.get())

    #     # print("GPU Analysis completed in", GPU_time, "seconds")

    # print(f"Average time: {statistics.fmean(times)} seconds")
    # return

    start = time.time()
    results = e.chunked_entropy(256, data)
    GPU_time = time.time() - start
    print("GPU Analysis completed in", GPU_time, "seconds")

    print("Results len:", len(results))
    print("Results type:", type(results))
    # print("Get:", results.get(), type(results.get()))
    # print(results.get().tobytes())
    return

    # start = time.time()
    # await r.run(DataSummaryAnalyzer)
    # Current_time = time.time() - start
    # print("Current analysis completed in", Current_time, "seconds")
    # # Calculate speedup percentage
    # speedup_percentage = ((Current_time - GPU_time) / Current_time) * 100

    # results = r.get_attributes(DataSummary)
    # print("DataSummaryAnalyzer results:", len(results.entropy_samples))
    # print([results.entropy_samples[x] for x in range(0, len(results.entropy_samples), 256)])
    # print(results.entropy_samples[len(results.entropy_samples) - 1])

    # print(f"Speedup: {speedup_percentage:.2f}%")
    # kill_thread = True
    # progress_thread.join()


if __name__ == "__main__":
    asyncio.run(main())
