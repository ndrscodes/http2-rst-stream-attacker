from runnerutils import Params

FRAME_AMOUNT = 1000
TIMEOUT = 100

servers = [
    ("nginx_legacy", "a759a235a408"), 
    ("nginx_current", "1fb35dd77e42"), 
    ("apache_legacy", "4cf54c915818"),
    ("apache_current", "b740464d6b16")
]

paths = [
    ("index", "/"), 
    ("index_file", "/index.html"),
    ("small_file", "/small-file"),
    ("medium_file", "/med-file"),
    ("large_file", "/large-file"),
]

args = [
    ["single_connection_single_routine", Params(connections=1, routines=1, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["single_connection_five_routines", Params(connections=1, routines=5, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["five_connections_single_routine", Params(connections=5, routines=1, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["ten_connections_single_routine", Params(connections=10, routines=1, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["single_connection_single_routine_consecutive", Params(connections=1, routines=1, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["single_connection_five_routines_consecutive", Params(connections=1, routines=5, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["five_connections_single_routine_consecutive", Params(connections=5, routines=1, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["ten_connections_single_routine_consecutive", Params(connections=10, routines=1, delay=0, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["single_connection_single_routine_delay", Params(connections=1, routines=1, delay=5, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["single_connection_five_routines_delay", Params(connections=1, routines=5, delay=5, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["five_connections_single_routine_delay", Params(connections=5, routines=1, delay=5, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["ten_connections_single_routine_delay", Params(connections=10, routines=1, delay=5, frames=FRAME_AMOUNT, attempts=100, timeout=TIMEOUT)],
    ["single_connection_single_routine_delay_consecutive", Params(connections=1, routines=1, delay=5, frames=FRAME_AMOUNT, attempts=100, consecutive=10, timeout=TIMEOUT)],
    ["single_connection_five_routines_delay_consecutive", Params(connections=1, routines=5, delay=5, frames=FRAME_AMOUNT, attempts=100, consecutive=10, timeout=TIMEOUT)],
    ["five_connections_single_routine_delay_consecutive", Params(connections=5, routines=1, delay=5, frames=FRAME_AMOUNT, attempts=100, consecutive=10, timeout=TIMEOUT)],
    ["ten_connections_single_routine_delay_consecutive", Params(connections=10, routines=1, delay=5, frames=FRAME_AMOUNT, attempts=100, consecutive=10, timeout=TIMEOUT)],
]
