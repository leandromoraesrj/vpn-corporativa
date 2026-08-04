"""Compatibilidade para consumidores não privilegiados da validação."""

from .privileged_validation import *  # noqa: F401,F403
from .privileged_validation import main


if __name__ == "__main__":
    main()
