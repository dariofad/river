M ?= 1
C ?= 1

.PHONY: monit fals sign state
ONESHELL: monit fals sign state
.DEFAULT_GOAL := list

list:
	@echo 'MODELS:'
	@echo '1 --- EgoCar'
	@echo '1 --- Toy Model'
	@echo '3 --- Not yet implemented'
	@echo 'LIST OF DEMOS AVAILABLE:'
	@echo -e 'monit\tM=1 C=1 --- WI: [DREL], RO: [AEGO, VEGO]'
	@echo -e 'monit\tM=2 C=3 --- RI: [X, Y], RO: [X, Y, RES, MOFFSET]'
	@echo -e 'fals\tM=1 C=1 --- WI: [DREL], RO: [AEGO, VEGO]'
	@echo -e 'sign\tM=2 C=1 --- WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]'
	@echo -e 'state\tM=2 C=1 --- WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]'

monit:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json && \
		python3 monit.py 127.0.0.1 $(M) $(C)

fals:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	python3 fals.py 127.0.0.1 $(M) $(C)

sign:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	chmod +x ../simulator/_utils/list_signals.py
	../simulator/_utils/list_signals.py < ../simulator/config.json
	python3 sign.py 127.0.0.1 $(M) $(C)

state:
	cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	chmod +x ../simulator/_utils/list_signals.py
	../simulator/_utils/list_signals.py < ../simulator/config.json
	python3 state.py 127.0.0.1 $(M) $(C)
