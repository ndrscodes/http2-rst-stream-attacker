from config import paths
import os
import runnerutils

def is_valid_path(path: str, allow_final=False) -> bool:
    return (not path.startswith("FINAL") or allow_final) and not path.find(".DS_Store") > -1

def find_option_stats(server_name: str, final = False) -> list[tuple[str, runnerutils.Stats]]:
    base = os.path.dirname(__file__) + "/" + server_name
    flist = filter(lambda f: is_valid_path(f, final), os.listdir(base))
    scores = [(f, runnerutils.stats_from_file(base + "/" + f + "/Latency.txt")) for f in flist]
    return scores

def order_options(server_name: str, final = True) -> list[tuple[str, runnerutils.Stats]]:
    return sorted(find_option_stats(server_name, final), key=lambda s: s[1].score(), reverse=True)

def find_best_option(server_name: str):
    scores = order_options(server_name)
    return scores[0]

print("\n".join([o[0] for o in order_options("nginx_current", final=True)]))
