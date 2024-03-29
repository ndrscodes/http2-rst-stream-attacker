from datetime import datetime
import subprocess
import httpx
from timeit import default_timer as timer
import time
from matplotlib import pyplot
import statistics
import os
import concurrent.futures
from config import *
import runnerutils
import copy

pyplot.ioff()

def create_stats(path: str, name: str, data: list[tuple[int | float, datetime]]):
    x_values = []
    y_values = []
    for i in data:
        y, x = i
        x_values.append(x)
        y_values.append(y)

    mean = statistics.fmean(y_values)
    median = statistics.median(y_values)
    stdev = statistics.stdev(y_values)
    max_val = max(y_values)
    min_val = min(y_values)

    pyplot.plot(x_values, y_values)
    pyplot.title(name)
    pyplot.axhline(mean, color="red")
    pyplot.axhline(median, color="green")
    pyplot.axhline(max_val, color="orange")
    pyplot.axhline(min_val, color="blue")
    pyplot.axhspan(mean - stdev, mean + stdev, color="red", alpha=0.2)
    pyplot.savefig(f"{path}/{name}_plot.png", format="png")
    pyplot.close()

    stats = runnerutils.Stats(median, mean, stdev, min_val, max_val, name)

    with open(f"{path}/{name}.txt", "a") as stat_file:
        stat_file.write(str(stats))

    return stats

def take_memory_measurements(cancel_token: runnerutils.CancellationToken) -> list[tuple[int, datetime]]:
    global CONTAINER_ID

    result = []
    while not cancel_token.cancelled: 
        proc_response = subprocess.run(("docker", "exec", CONTAINER_ID, "cat", "/proc/meminfo"), capture_output=True)
        data = proc_response.stdout.decode().splitlines()[2].replace(" ", "").split(":")[1].replace("kB", "")
        result.append((int(data), datetime.now()))
        time.sleep(1)
    return result

def take_cpu_measurements(cancel_token: runnerutils.CancellationToken) -> list[tuple[float, datetime]]:
    global CONTAINER_ID

    result = []
    while not cancel_token.cancelled:
        proc_response = subprocess.run(("docker", "exec", CONTAINER_ID, "cat", "/proc/loadavg"), capture_output=True)
        data = proc_response.stdout.decode().split(" ")[0]
        result.append((float(data), datetime.now()))
        time.sleep(1)
    return result 

def take_latency_measurement(client: httpx.Client, url: str) -> tuple[int, datetime]:
    start = timer()
    response = client.head(url)
    if response.status_code != 200:
        print("STATUS ERROR", response.status_code)
        raise Exception()
    end = timer()
    return ((end - start) * 1000., datetime.now())

def measure_baseline(client: httpx.Client, url: str, path: str):
    times = [] 
    client.head(url)
    c_token = runnerutils.CancellationToken()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        cpu_future = ex.submit(take_cpu_measurements, c_token)
        mem_future = ex.submit(take_memory_measurements, c_token)

        for i in range(1000):
            try:
                times.append(take_latency_measurement(client, url))
            except Exception as e:
                print(f"WARNING: unable to send request: {e}")

            time.sleep(0.1)
        
        c_token.cancel()

        cpu_data = cpu_future.result()
        mem_data = mem_future.result()

        stats = [
            create_stats(path, "CPU", cpu_data),
            create_stats(path, "Memory", mem_data),
            create_stats(path, "Latency", times),
        ]

        return stats

def cooldown(timeout: int=120):
    print(f"now cooling down for {timeout} seconds")
    try:
        time.sleep(timeout)
    except KeyboardInterrupt:
        pass

def measure_attack(client: httpx.Client, args: runnerutils.Params, path: str):
    times = []
    print("execute with params", args[1].to_params())

    with httpx.Client(http2=True, verify=False) as client, open(path + "/log.txt", "a") as log, concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        url = a[1].url
        client.head(url)
        p = subprocess.Popen(["go", "run", "../main.go", *(args[1].to_params())], stdout=log)

        c_token = runnerutils.CancellationToken()
        cpu_future = ex.submit(take_cpu_measurements, c_token)
        mem_future = ex.submit(take_memory_measurements, c_token)


        while p.poll() is None:
            try:
                times.append(take_latency_measurement(client, url))
            except Exception as e:
                print(f"WARNING: unable to send request: {e}")

            time.sleep(0.1)

        c_token.cancel()

        cpu_data = cpu_future.result()
        mem_data = mem_future.result()

        stats = [
            create_stats(path, "CPU", cpu_data),
            create_stats(path, "Memory", mem_data),
            create_stats(path, "Latency", times),
        ]

        return stats

def stats_to_str(stats: list[runnerutils.Stats]):
    stats = [s.__str__() for s in stats]
    return "\n".join(stats)

def stop_running_containers():
    print("stopping ALL running docker containers...")
    container_response = subprocess.run(("docker", "ps", "-q"), capture_output=True)
    containers = container_response.stdout.splitlines()
    print(f"found running docker containers: {containers}")
    subprocess.run(("docker", "stop", *containers))
    print("all containers stopped")

def is_valid(path: str):
   return not os.path.exists(path + "/Latency.txt") 

def find_best_option(server_name: str):
    base = os.path.dirname(__file__) + "/" + server_name
    scores = [(f, runnerutils.stats_from_file(base + "/" + f + "/Latency.txt")) for f in os.listdir(base)]
    print("stats generated", scores)
    best = None
    for s in scores:
        if s[0].startswith("FINAL") or s[1] is None:
            continue
        if best is None or best[1].score() < s[1].score():
            best = s

    print("found best option type", best)
    for arg in args:
        if arg[0] == best[0]:
            return arg        

stop_running_containers()

for server in servers:
    SERVER_TYPE, CONTAINER_ID = server
    subprocess.run(("docker", "start", CONTAINER_ID))
    print("started container.")

    path = os.path.dirname(__file__) + "/" + SERVER_TYPE + "/baseline"
    should_measure_baseline = is_valid(path)    
    cooldown()

    if should_measure_baseline:
        os.makedirs(path, exist_ok=True)

        with httpx.Client(http2=True, verify=False) as client:
            url = args[0][1].url
            print(f"now measuring baseline for url {url}")
            stats = measure_baseline(client, url, path)
            print(f"finished baseline measurement. Stats:\n{stats_to_str(stats)}")

        cooldown()
    else:
        print("baseline already contains a complete measurement. Skipping.")

    for a in args:
        print(f"collecting arg measurements. now trying args {a[0]}")
        path = os.path.dirname(__file__) + "/" + SERVER_TYPE + "/" + a[0]
        if not is_valid(path):
            print(f"{path} already contains a complete measurement.")
            continue

        os.makedirs(path, exist_ok=True)

        with httpx.Client(http2=True, verify=False) as client:
            stats = measure_attack(client, a, path)
            print(f"finished attack. Stats:\n{stats_to_str(stats)}")

        cooldown() 
    
    best = find_best_option(SERVER_TYPE)

    print("best option:", best)
    
    for p in paths:
        print(f"measuring path {p}")
        name = best[0]
        name = name + "_" + p[0]
        path = os.path.dirname(__file__) + "/" + SERVER_TYPE + "/FINAL_" + name
        if not is_valid(path):
            print(f"{path} already contains a complete measurement.")
            continue

        os.makedirs(path, exist_ok=True)
        with httpx.Client(http2=True, verify=False) as client:
            params: Params = copy.copy(best[1])
            params.path = "/" + p[1].strip("/")
            stats = measure_attack(client, (best[0], params), path)
            print(f"finished attack. Stats:\n{stats_to_str(stats)}")
        
        cooldown()

    print("stopping container.")
    subprocess.run(("docker", "stop", CONTAINER_ID))