from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, List, Tuple
from itertools import count
import json

from nest_client.time import Time, s
from nest_client.types import EnvVarType, EnvVarValueType

# ---------------------------------------------------------------------
# Schedulable base
# ---------------------------------------------------------------------

class Schedulable:
    def flatten(self) -> List[SequenceOp]:
        return [SequenceOp(self, Time(0), [])]

    def duration(self) -> Time:
        raise NotImplementedError


# ---------------------------------------------------------------------
# Events, Commands and Environment variables
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class EventBuilder:
    component: str
    name: str
    predicate: Callable[[dict], bool] | None = None

    def where(self, predicate: Callable[[dict], bool]) -> EventBuilder:
        return EventBuilder(self.component, self.name, predicate)

    def expect(self, within: Time | None = None) -> Event:
        return Event(self.component, self.name, self.predicate, True, within)

    def forbid(self, within: Time | None = None) -> Event:
        return Event(self.component, self.name, self.predicate, False, within)


@dataclass(frozen=True)
class Event(Schedulable):
    component: str
    name: str
    predicate: Callable[[Any], bool] | None = None
    expect: bool = True
    within: Time | None = None

    def duration(self) -> Time:
        return self.within or Time(0)

    def __repr__(self):
        expect = "expect" if self.expect else "forbid"
        within = self.within or "current scope"
        return f"Event({expect} {self.component}.{self.name} within {within})"


@dataclass(frozen=True)
class Command(Schedulable):
    component: str
    name: str
    args_json: str

    def duration(self) -> Time:
        return Time(0)

    def __repr__(self):
        return f"Command({self.component}.{self.name}, args={self.args_json})"

@dataclass(frozen=True)
class SetEnv(Schedulable):
    var: str
    type: EnvVarType
    value: EnvVarValueType
    lerp_over: Time | None

    def duration(self) -> Time:
        return self.lerp_over or Time(0)

    def __repr__(self):
        lerp = f", lerp_over={self.lerp_over}" if self.lerp_over else ""
        return f"SetEnv({self.var}, type={self.type}, value={self.value}{lerp})"


def event(component: str, name: str) -> EventBuilder:
    return EventBuilder(component, name)


def command(component: str, name: str, args) -> Command:
    return Command(component, name, json.dumps(args))


def set_env(var: str, type: EnvVarType, value: EnvVarValueType, lerp_over: Time | None=None) -> SetEnv:
    return SetEnv(var, type, value, lerp_over)


# ---------------------------------------------------------------------
# Sequence
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class Scope:
    start: Time
    end: Time
    label: str | None=None

    def with_offset(self, offset: Time) -> Scope:
        return Scope(self.start + offset, self.end + offset, self.label)


@dataclass(frozen=True)
class SequenceOp:
    item: Schedulable
    offset: Time
    scope_stack: List[Scope]

    def __repr__(self) -> str:
        scope = " / ".join([s.label or '<anonymous>' for s in self.scope_stack if s.label])
        return f"[{str(self.offset):>8}] ({scope}) {self.item}"


@dataclass
class Sequence(Schedulable):
    entries: List[Tuple[Schedulable, Time]] = field(default_factory=list)
    label: str | None = None

    def add(self, item: Schedulable, offset: Time=Time(0)):
        self.entries.append((item, offset))

    def flatten(self) -> List[SequenceOp]:
        flattened: List[Tuple[SequenceOp, int]] = []
        scope = Scope(0*s, self.duration(), self.label)
        order_generator = count()
        for (item, offset) in self.entries:
            flattened += [
                (
                    SequenceOp(
                        op.item,
                        offset + op.offset,
                        [scope] + [scope.with_offset(offset) for scope in op.scope_stack]
                    ),
                    next(order_generator)
                )
                for op in item.flatten()
            ]

        return list(
            map(
                lambda e: e[0],
                sorted(flattened, key=lambda e: (e[0].offset, e[1]))
        ))

    def duration(self) -> Time:
        if not self.entries:
            return Time(0)
        return max(offset + item.duration() for (item, offset) in self.entries)

    # --- Composition operators ---

    def __rshift__(self, other: Sequence) -> Sequence:
        seq = Sequence()
        seq.add(self)
        seq.add(other, self.duration())
        return seq

    def __or__(self, other: Sequence) -> Sequence:
        seq = Sequence()
        seq.add(self)
        seq.add(other)
        return seq

    # --- Timeline builder ---

    def timeline(self) -> TimelineBuilder:
        return TimelineBuilder(self)


# ---------------------------------------------------------------------
# Timeline Builder
# ---------------------------------------------------------------------

class TimelineBuilder:
    def __init__(self, seq: Sequence):
        self.seq = seq

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def __setitem__(self, time: Time, item: Schedulable):
        self.seq.add(item, time)

    @contextmanager
    def offset(self, delta: Time, label: str | None=None):
        parent_seq = self.seq
        self.seq = Sequence(label=label)
        yield
        parent_seq.add(self.seq, delta)
        self.seq = parent_seq


# ---------------------------------------------------------------------
# @sequence decorator
# ---------------------------------------------------------------------

def sequence[**P](fn: Callable[P, None]) -> Callable[P, Sequence]:
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Sequence:
        seq = Sequence(label=fn.__name__)
        _timeline_stack.append(seq)
        try:
            fn(*args, **kwargs)
        finally:
            _timeline_stack.pop()
        return seq
    return wrapper


# Global stack for implicit timeline()
_timeline_stack: List[Sequence] = []


def timeline() -> TimelineBuilder:
    if not _timeline_stack:
        raise RuntimeError("timeline() used outside of @sequence")
    return _timeline_stack[-1].timeline()

