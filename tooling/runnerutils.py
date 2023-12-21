class Params:

    def __init__(self, connections: int, routines: int, delay: int, frames: int, attempts: int, url: str = "https://127.0.0.1:443", consecutive: int = 1, timeout: int = 1000, path="/"):
        self.connections = connections
        self.routines = routines
        self.delay = delay
        self.frames = frames
        self.attempts = attempts
        self.url = url
        self.consecutive = consecutive
        self.timeout = timeout
        self.path = path
    
    def to_params(self):
        return ("--url", str(self.url) + str(self.path), "--connections", str(self.connections), "--routines", str(self.routines), "--delay", str(self.delay), "--frames", str(self.frames), "--connectAttempts", str(self.attempts), "--consecutiveSends", str(self.consecutive), "--timeout", str(self.timeout))

class CancellationToken:

    def __init__(self):
        self.cancelled = False
    
    def cancel(self):
        self.cancelled = True

class Stats:
    def __init__(self, median: float, mean: float, stdev: float, minimum: float, maximum: float, name: str=None):
        self.median = median
        self.mean = mean
        self.stdev = stdev
        self.minimum = minimum
        self.maximum = maximum
        self.name = name
    
    def score(self):
        return self.median + self.mean

    def __str__(self):
        return f"Stats type: {self.name}\nmedian: {self.median}\nmean: {self.mean}\nstandard deviation: {self.stdev}\nmin: {self.minimum}\nmax: {self.maximum}\n"

def stats_from_file(path: str) -> Stats:
    with open(path, 'r') as f:
        lines = f.readlines()
        lines = [l.split(":") for l in lines]
        return Stats(float(lines[1][1].strip()), float(lines[2][1].strip()), float(lines[3][1].strip()), float(lines[4][1].strip()), float(lines[5][1].strip()), lines[0][1].strip())