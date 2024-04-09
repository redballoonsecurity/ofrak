import numpy

from ofrak_gpu.entropy import entropy


def parse_args():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    return parser.parse_args()


def main(args):
    with open(args.file, "rb") as f:
        data = numpy.fromfile(f, dtype="uint8")
    calculate = entropy(device_pref="AMD").chunked_entropy
    print(calculate(1024, data))


if __name__ == "__main__":
    main(parse_args())
