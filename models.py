from dataclasses import dataclass


@dataclass
class Task:
    id:         int
    timestamp:  int
    name:       str
    status:     str
    tokens:     int = 0
    flag:       str = ""
    error:      str = ""
