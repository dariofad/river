M ?= 1
C ?= 1
HOST ?= 127.0.0.1

.PHONY: monit fals sign state
ONESHELL: monit fals sign state
.DEFAULT_GOAL := list

list:
	@echo 'MODELS:'
	@echo '1 --- EgoCar'
	@echo '2 --- Signal Addition'
	@echo '3 --- Abstract Fuel Control'
	@echo 'LIST OF DEMOS AVAILABLE:'
	@echo -e 'monit\tM=1 C=1 --- WI: [DREL], RO: [AEGO, VEGO]'
	@echo -e 'monit\tM=2 C=2 --- RI: [X, Y], RO: [X, Y, RES, MOFFSET]'
	@echo -e 'fals\tM=1 C=1 --- WI: [DREL], RO: [AEGO, VEGO]'
	@echo -e 'fals\tM=2 C=1 --- WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]'
	@echo -e 'sign\tM=1 C=2 --- WI: [DREL], RO: [DREL, AEGO, VEGO]'
	@echo -e 'sign\tM=2 C=1 --- WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]'
	@echo -e 'state\tM=2 C=1 --- WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]'

monit:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json && \
		python3 monit.py $(HOST) $(M) $(C)

fals:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	python3 fals.py $(HOST) $(M) $(C)

sign:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	chmod +x ../simulator/_utils/list_signals.py
	../simulator/_utils/list_signals.py < ../simulator/config.json
	python3 sign.py $(HOST) $(M) $(C)

state:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	chmod +x ../simulator/_utils/list_signals.py
	../simulator/_utils/list_signals.py < ../simulator/config.json
	python3 state.py $(HOST) $(M) $(C)
