from datetime import timedelta
from datetime import datetime
import re
import matplotlib.pyplot as plt
import csv
from dateutil import parser

rows = []
with open('monitor.log') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=';', quotechar='"')
    for row in spamreader:
        rows.append(row)

y = [float(r[1]) for r in rows]
x = [parser.parse(r[0]) for r in rows]
print(y)
plt.plot(x, y)
plt.axvline(x[0] + timedelta(seconds=3), color='r')
plt.axvline(x[-1] - timedelta(seconds=3), color='r')
plt.yscale("log")
plt.ylabel('some numbers')
plt.show()
