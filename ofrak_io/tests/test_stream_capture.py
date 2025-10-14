"""
This module tests StreamCapture.
"""
import os
import sys

from ofrak_io.stream_capture import StreamCapture


def test_stream_capture(capsys):
    """
    Test StreamCapture.

    This test verifies that:
    - StreamCapture properly captures output written to a stream
    - The captured output matches the expected content including line endings
    """
    # pytest captures standard in and out by default. Disable this for our test
    with capsys.disabled():
        with StreamCapture(sys.stdout) as stream_capture:
            sys.stdout.write("hello\n")
        captured_stream = stream_capture.get_captured_stream()
        # On Windows, "\n" gets converted to "\r\n" (linesep)
        assert captured_stream == f"hello{os.linesep}"


def test_stream_capture_stop_called_before_start(capsys):
    """
    Test calling stop() on StreamCapture before start().

    This test verifies that:
    - Calling stop() before start() returns None
    """
    with capsys.disabled():
        stream = StreamCapture(sys.stdout)
        result = stream.stop()
        assert result is None
