# ruff: noqa PLC0415  # disable imports at top-level so unused dependencies are not always imported
import time

from consts import KEYSIZE, SEED, SQUARINGS_PER_SEC
from utils import timer

from tlp_lib import TLP


def now():
    return time.perf_counter_ns()


INTERVAL = 10
MILI_TO_S = 10**9
INTERVAL_NS = INTERVAL * MILI_TO_S


def count_squarings_in_fixed_time():
    tlp = TLP(seed=SEED)
    pk, _ = tlp.setup(1, 1, keysize=KEYSIZE)
    n, _, r = pk

    counter = 0
    start = now()
    stop = start + INTERVAL_NS
    s = SQUARINGS_PER_SEC[KEYSIZE] * INTERVAL
    # use previous value to refine; avoid making more calls to now()
    for _ in range(s - s // 20):
        r = (r**2) % n
        counter += 1
    while stop > now():
        for _ in range(10_000):
            r = (r**2) % n
            # r = pow(r, 2, n)  # slower
            counter += 1
    print(counter)
    print("per sec:", counter / INTERVAL)
    # print("per hour", counter / INTERVAL * 3600)


def time_fixed_squarings(squarings: int):
    tlp = TLP(seed=SEED)
    pk, _ = tlp.setup(1, 1, keysize=KEYSIZE)
    n, _, r = pk
    start = now()
    for _ in range(squarings):
        r = (r**2) % n
    stop = now()
    seconds = (stop - start) / MILI_TO_S
    print(squarings / seconds)


def compare_gmpy_sage(squarings: int):
    import gmpy2
    from sage.all import IntegerModRing, power  # type: ignore

    n = 6229205250449008408488810372435917442525505743598603566286880180064596734952053099221673849147518748692399578515831628412259027551369804282958904058809630420264031318325689626489250260020546212671383371411496565970115779226866501484729684350420421387107574180358960901752985144624550632252158672377981406168119986502705837004760655589162121670420147891606761984406546807870016164278720930862084677050553472632350920774838421622484403139811587663843084714602900714142650839197152586147630427406796612595096204464380274595090350217936191025805017452851931370665127804116777356024822439098514655521996611422252932038961
    r_0 = 1743724424099666811431147607616692728826896443514242207251022167360334231794188502189239727905681649520198367880849093018870101376967446659325924877661130735527461957163130540894138745900941923700245232830214433940492810834306971987060530021931099050876151469281045398509726082192914920014136006891577804647901082138191447261475413873009694783720641377347310893325563523104910130150196172994236840850382206150539461295079402510124994605171161856343241143526252650336130173751940408292960684250460120602910899431931616599866508397641635456344269448841436759323323914976248980825239042395258981917924022550563782923632

    Zn = IntegerModRing(n)
    r = Zn(r_0)
    start = now()
    for _ in range(squarings):
        r = power(r, 2)
    stop = now()
    seconds = (stop - start) / MILI_TO_S
    print("r = power(r, 2)")
    print(squarings / seconds)
    print(seconds)

    r = Zn(r_0)
    start = now()
    for _ in range(squarings):
        r = r**2
    stop = now()
    seconds = (stop - start) / MILI_TO_S
    print("r = r ** 2")
    print(squarings / seconds)
    print(seconds)

    n = gmpy2.mpz(n)
    r = gmpy2.mpz(r_0)
    start = now()
    for _ in range(squarings):
        r = (r**2) % n
    stop = now()
    seconds = (stop - start) / MILI_TO_S
    print("r = (r ** 2) % n")
    print(squarings / seconds)
    print(seconds)


if __name__ == "__main__":
    print(timer(count_squarings_in_fixed_time))
    # print(timer(time_fixed_squarings, 100_000_000))
