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
	@echo '4 --- Uprobe multi test model'
	@echo 'LIST OF DEMOS AVAILABLE:'
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=1 C=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=2 C=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=3 C=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=4 C=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=1 C=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=2 C=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=3 C=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=1 C=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=2 C=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=3 C=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "M=1 C=3"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "M=2 C=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "M=3 C=3"

clean_cache:
	@ echo "Cleaning the KeyValue cache..."
	@ docker exec redis redis-cli DEL "simulation" "simulation:0"

monit: clean_cache
	@ cp ../simulator/demos/M$(M)_C$(C)_config.json ../simulator/config.json
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/config.json
	@ uv run monit.py $(HOST) $(M) $(C)

fals: clean_cache
	@ cp ../simulator/demos/M$(M)_C$(C)_config.json ../simulator/config.json
	@ uv run fals.py $(HOST) $(M) $(C)

sign: clean_cache
	@ cp ../simulator/demos/M$(M)_C$(C)_config.json ../simulator/config.json
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/config.json
	@ uv run sign.py $(HOST) $(M) $(C)

state: clean_cache
	@ cp ../simulator/demos/M$(M)_C$(C)_config.json ../simulator/config.json
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/config.json
	@ uv run state.py $(HOST) $(M) $(C)
