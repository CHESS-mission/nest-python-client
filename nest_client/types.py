from enum import Enum, auto
import numpy as np


class EnvVarType(Enum):
    INT = auto()
    FLOAT = auto()
    BOOL = auto()
    VEC2 = auto()
    VEC3 = auto()
    QUATERNION = auto()
    TENSOR = auto()

EnvVarValueType = int | float | bool | np.ndarray

