import numpy

from ofrak_gpu.entropy_gpu import pick_pyopencl_device
from ofrak_gpu.entropy import entropy


def parse_args():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    return parser.parse_args()


def main(args):
    with open(args.file, "rb") as f:
        data = numpy.fromfile(f, dtype="uint8")

    chosen_platform, chosen_device = pick_pyopencl_device()
    e = entropy(platform_pref=chosen_platform, device_pref=chosen_device, interactive=False)

    print(e.chunked_entropy(1024, data))


if __name__ == "__main__":
    main(parse_args())
