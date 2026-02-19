from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class Time:
    """A simple, comparable duration stored in microseconds."""
    us: int

    def as_unit(self, unit: Time) -> float:
        return self.us / unit.us

    def __post_init__(self) -> None:
        if not isinstance(self.us, int):
            raise TypeError("Duration(ns=...) must be an int")

    def __add__(self, other: Time) -> Time:
        return Time(self.us + other.us)

    def __sub__(self, other: Time) -> Time:
        return Time(self.us - other.us)

    def __mul__(self, k: int | float) -> Time:
        return Time(int(self.us * float(k)))

    def __rmul__(self, k: int | float) -> Time:
        return self.__mul__(k)

    def __truediv__(self, k: int | float) -> Time:
        return Time(int(self.us / float(k)))

    def __repr__(self) -> str:
        return f"Duration({self.us}ns)"

    def __str__(self) -> str:
        """Pretty-format duration for logs (stable formatting)."""
        if self.us % s.us == 0:
            return f"{self.us // s.us}s"
        if self.us % ms.us == 0:
            return f"{self.us // ms.us}ms"
        return f"{self.us}us"

# Time units
us = Time(1)
ms = Time(1_000)
s = Time(1_000_000)
m = 60 * s

