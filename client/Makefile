M ?= 1
C ?= 1
HOST ?= 127.0.0.1

MONIT = monit
FALS = fals
SIGN = sign
STATE = state
WIDTH = 5

.PHONY: monit fals sign state
ONESHELL: monit fals sign state
.DEFAULT_GOAL := list

list:
	@echo 'MODELS:'
	@echo '1 --- EgoCar'
	@echo '2 --- Signal Addition'
	@echo '3 --- Abstract Fuel Control'
	@echo 'LIST OF DEMOS AVAILABLE:'
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=1 C=1" "# WI: [DREL], RO: [AEGO, VEGO]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=2 C=2" "# RI: [X, Y], RO: [X, Y, RES, MOFFSET]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=3 C=1" "# WI: [PANGLE], RO: [PANGLE, AF, CMODE]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=1 C=1" "# WI: [DREL], RO: [AEGO, VEGO]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=2 C=1" "# WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=3 C=2" "# WI: [PANGLE, RPM], RO: [PANGLE, AF, CMODE]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=1 C=2" "# WI: [DREL], RO: [DREL, AEGO, VEGO]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=2 C=1" "# WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=3 C=2" "# WI: [PANGLE, RPM], RO: [PANGLE, AF, CMODE]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "M=2 C=1" "# WI: [X, Y], RI: [X, Y], RO: [X, Y, RES, MOFFSET]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "M=3 C=3" "# WI: WI: [PANGLE, RPM], RO: [PANGLE, AF, CMODE, BANGLE]"

clean_cache:
	@ echo "Cleaning the KeyValue cache..."
	@ docker exec redis redis-cli DEL "simulation" "simulation:0"

monit: clean_cache
	@ cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	@ python3 monit.py $(HOST) $(M) $(C)

fals: clean_cache
	@ cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	@ python3 fals.py $(HOST) $(M) $(C)

sign: clean_cache
	@ cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/config.json
	@ python3 sign.py $(HOST) $(M) $(C)

state: clean_cache
	@ cp ../simulator/M$(M)_C$(C)_config.json ../simulator/config.json
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/config.json
	@ python3 state.py $(HOST) $(M) $(C)
