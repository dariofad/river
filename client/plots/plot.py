import matplotlib.pyplot as plt
import matplotlib.patches as patches
import csv

REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
ZSET_KEY = 'simulation:0'

signals = {
    "TIME": 0,
    "DREL": 1,
    "AEGO": 2,
    "VEGO": 3,
    "VREL": 4,
    "DLEAD": 5,
    "APOS": 6,    
}

plt.rcParams.update({'font.size': 16})

CASES = ["normal.csv", "acc.csv", "brk.csv"]
TITLES = ["Normal execution", "Adversarial attack", "Runtime enforcement"]
fig, axs = plt.subplots(1, 3, figsize=(15, 4))
handles, labels = [], []
times = []
real_drel = []
ow_drel = []
phi = []
for c, case in enumerate(CASES):
    times.append([])
    real_drel.append([])
    ow_drel.append([])
    phi.append([])    
    with open(case, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        next(csv_reader)
        for line in csv_reader:
            times[c].append(int(line[0]))
            real_drel[c].append(float(line[1]))
            ow_drel[c].append(float(line[2]))
            phi[c].append(float(line[3]))            

    axs[c].plot(times[c], real_drel[c], label="Real distance", linestyle='--', linewidth=3, color='black')
    if c != 0:
        axs[c].plot(times[c], ow_drel[c], label="Injected distance", linestyle=':', linewidth=3, color='red')
    axs[c].text(220, 2, 'unsafe area', ha='center', va='center', fontsize=16, color='black')
    rect = patches.Rectangle(
        (0,0),
        451,
        4,
        linewidth=0,
        edgecolor='red',
        facecolor='red',
        hatch='//',
        alpha=0.3,
        fill=True
    )
    axs[c].add_patch(rect)
    axs[c].plot(times[c], phi[c], color='blue', linewidth=3, label="CPS safety according to φ")
    axs[c].autoscale(axis='x', tight=True)
    axs[c].set_ylim(0, 90)
    axs[c].set_ylabel("Vehicle distance")
    axs[c].set_xlabel("Loop iteration")
    axs[c].set_title(TITLES[c])
    if c == 0:
        h, l = axs[0].get_legend_handles_labels()
        handles.extend(h)
        labels.extend(l)
    if c == 2:
        axs[2].annotate(text='', xy=(311, 2), xytext=(311,18),
                        arrowprops=dict(arrowstyle='<->', color='black'))
        axs[c].text(317, 10, '+Δ', ha='left', va='center', fontsize=16, color='black')        

fig.legend(handles, labels, loc='lower center', bbox_to_anchor=(0.5, -0.17), ncol=3)
fig.savefig('fig.png', bbox_inches='tight')
