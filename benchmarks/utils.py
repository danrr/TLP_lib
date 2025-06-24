import functools
import os
import timeit
import warnings
from collections.abc import Callable

from consts import NUMBER


def timer[R, **P](f: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> float:
    return timeit.Timer(functools.partial(f, *args, **kwargs)).timeit(number=NUMBER)


# make the process not share the CPU with other processes
def try_make_process_rude():
    try:
        os.nice(-20)
    except PermissionError:
        warnings.warn(
            "Could not make process rude to prevent sharing the CPU with other processes",
            RuntimeWarning,
            stacklevel=2,
        )


def timer_with_output[R, **P](
    f: Callable[P, R], *args: P.args, **kwargs: P.kwargs
) -> tuple[float, R]:
    output: R | None = None

    def func():
        nonlocal output
        output = f(*args, **kwargs)

    times = timeit.Timer(func).timeit(number=NUMBER)

    assert output is not None

    return times, output
