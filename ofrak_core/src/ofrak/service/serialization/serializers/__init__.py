# Suppress all BeartypeDecorHintPep585DeprecationWarning warnings pending resolution of
# https://github.com/redballoonsecurity/ofrak/issues/92.
# This is nice for OFRAK users, who don't want to see these warnings.
from beartype.roar import BeartypeDecorHintPep585DeprecationWarning
from warnings import filterwarnings

filterwarnings("ignore", category=BeartypeDecorHintPep585DeprecationWarning)
