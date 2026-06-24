import csv

import matplotlib.pyplot as plt

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
ZSET_KEY = "simulation:0"

signals = {
    "TIME": 0,
    "PANGLE": 1,
    "AF": 2,
    "CMODE": 3,
}

plt.rcParams.update({"font.size": 16})

CASES = ["3.csv", "4.csv"]
TITLES = ["Normal execution", "Runtime enforcement"]
fig, ax = plt.subplots(figsize=(10, 4))
times = []
pangle = []
af = []
for c, case in enumerate(CASES):
    times.append([])
    pangle.append([])
    af.append([])
    with open(case) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        next(csv_reader)
        for line in csv_reader:
            times[c].append(int(line[0]))
            pangle[c].append(float(line[1]))
            af[c].append(float(line[2]))

ax.plot(
    times[0], pangle[0], label="Pedal angle", linestyle="--", linewidth=3, color="green"
)
ax.set_ylim(0, 65)
ax.set_ylabel("Angle [°]")
twin_g = ax.twinx()
twin_g.plot(times[0], af[0], color="blue", linewidth=3, label="Air-to-fuel")
twin_g.plot(
    times[0],
    af[1],
    color="red",
    linewidth=3,
    label="Air-to-fuel after injection",
    linestyle="dashdot",
)
twin_g.set_ylim(10, 20)
ax.autoscale(axis="x", tight=True)

ax.set_title("Comparison after permanent state change")
ax.text(
    52,
    51,
    "Base opening\nangle altered",
    ha="left",
    va="center",
    fontsize=16,
    color="black",
)
ax.annotate(
    text="",
    xy=(50, 30),
    xytext=(50, 50),
    arrowprops=dict(arrowstyle="->", color="black"),
)
#     axs[0].annotate(text='', xy=(265, 30), xytext=(265,50),
#                     arrowprops=dict(arrowstyle='-', color='black', linestyle=':'))
fig.legend(loc="lower center", bbox_to_anchor=(0.5, -0.17), ncol=3)
fig.savefig("af-exp-p.png", bbox_inches="tight")
