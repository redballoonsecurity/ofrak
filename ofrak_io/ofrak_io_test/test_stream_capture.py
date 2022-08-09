import sys

from ofrak_io.stream_capture import StreamCapture


def test_stream_capture(capsys):
    """
    Test StreamCapture.
    """
    # pytest captures standard in and out by default. Disable this for our test
    with capsys.disabled():
        with StreamCapture(sys.stdout) as stream_capture:
            sys.stdout.write("hello\n")
        captured_stream = stream_capture.get_captured_stream()
        assert captured_stream == "hello\n"


def test_stream_capture_stop_called_before_start(capsys):
    with capsys.disabled():
        stream = StreamCapture(sys.stdout)
        result = stream.stop()
        assert result is None
