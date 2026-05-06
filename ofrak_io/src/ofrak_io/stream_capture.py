"""
StreamCapture is useful utility for capturing standard output of C processes called from python.

**Usage:**
```python
with StreamCapture(sys.stdout) as stream_capture:
    sys.stdout.write("hello\\n")
assert stream_capture.get_captured_stream() == "hello\\n"
```
"""

from types import TracebackType
from typing import IO, Optional, Type

import os


class StreamCapture:
    """
    Capture a stream from a filelike object.
    """

    escape_char = b"\b"

    def __init__(self, stream: IO):
        self.stream = stream
        self.stream_file_descriptor = self.stream.fileno()
        self.pipe_out, self.pipe_in = os.pipe()
        self.stream_captured = ""
        self.stream_file_descriptor_copy = None  # type: Optional[int]

    def __enter__(self):
        self.start()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[BaseException]],
        exception_value: Optional[BaseException],
        exception_traceback: Optional[TracebackType],
    ) -> None:
        self.stop()

    def start(self) -> None:
        """
        Start capturing the stream.
        """
        self.stream_file_descriptor_copy = os.dup(self.stream_file_descriptor)
        os.dup2(self.pipe_in, self.stream_file_descriptor)

    def stop(self) -> None:
        """
        Stop capturing the stream and read what was captured.
        """
        if self.stream_file_descriptor_copy is None:
            # Capture was not started
            return

        # Fix for ofrak_tutorial ARM support so Jupyter notebook doesn't hang:
        # Flush any Python-level buffered content so it reaches the pipe before the sentinel.
        self.stream.flush()
        # Write the escape sentinel directly to the pipe fd rather than through the Python
        # stream object. In environments like Jupyter where sys.stderr is a Python-level
        # wrapper (e.g. ZMQ OutStream) rather than a direct fd, self.stream.write() does
        # not reach the pipe and _read_stream() would block forever waiting for the sentinel.
        os.write(self.pipe_in, self.escape_char)
        self._read_stream()

        # Reset the file
        os.close(self.pipe_in)
        os.close(self.pipe_out)
        os.dup2(self.stream_file_descriptor_copy, self.stream_file_descriptor)
        os.close(self.stream_file_descriptor_copy)

        # Write the captured stream to the file. This way, anything that may have been captured
        # by accident still gets where it needs to go
        self.stream.write(self.stream_captured)

    def get_captured_stream(self) -> str:
        """
        Get the captured stream.
        """
        return self.stream_captured

    def _read_stream(self) -> None:
        """
        Read the stream data (one byte at a time)
        and save the text in `capturedtext`.
        """
        while True:
            char = os.read(self.pipe_out, 1)
            if not char or self.escape_char in char:
                break
            self.stream_captured += char.decode()
