import reedsolo as rs
from ofrak.core.ecc.abstract import EccAlgorithm, EccError


class ReedSolomon(EccAlgorithm):
    def __init__(
        self,
        nsym: int = 10,
        nsize: int = 255,
        fcr: int = 0,
        prim: int = 0x11D,
        generator: int = 2,
        c_exp: int = 8,
        single_gen: bool = True,
    ):
        self.RSC = rs.RSCodec(
            nsym=nsym,
            nsize=nsize,
            fcr=fcr,
            prim=prim,
            generator=generator,
            c_exp=c_exp,
            single_gen=single_gen,
        )

    def encode(self, payload: bytes) -> bytes:
        return self.RSC.encode(
            data=payload,
        )[len(payload) :]

    def decode(self, payload: bytes) -> bytes:
        try:
            return self.RSC.decode(data=payload)[0]
        except rs.ReedSolomonError:
            raise EccError()
