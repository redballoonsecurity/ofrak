from unittest.mock import MagicMock


entropy_gpu = MagicMock(side_effect=ImportError("ofrak_gpu has not been installed!"))
np = MagicMock(side_effect=ImportError("NumPy has not been installed!"))
