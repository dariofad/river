m ?= 1
c ?= 1
HOST ?= 127.0.0.1

MONIT = monit
FALS = fals
SIGN = sign
STATE = state
WIDTH = 5

.PHONY: monit fals sign state select_manifest
ONESHELL: monit fals sign state
.DEFAULT_GOAL := list

list:
	@echo 'MODELS:'
	@echo '1 --- EgoCar'
	@echo '2 --- Signal Addition'
	@echo '3 --- Abstract Fuel Control'
	@echo '4 --- Uprobe multi test model'
	@echo 'LIST OF DEMOS AVAILABLE:'
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "m=1 c=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "m=2 c=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "m=3 c=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "m=4 c=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "m=1 c=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "m=2 c=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "m=3 c=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "m=1 c=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "m=2 c=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "m=3 c=2"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "m=1 c=3"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "m=2 c=1"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "m=3 c=3"

clean_cache:
	@ echo "Cleaning the KeyValue cache..."
	@ docker exec redis redis-cli DEL "simulation" "simulation:0"

select_manifest:
	@ tmp=../simulator/.manifest.yaml.tmp; cp ../simulator/demos/m$(m)_c$(c).river.yaml $$tmp; mv $$tmp ../simulator/manifest.yaml

monit: clean_cache select_manifest
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/manifest.yaml
	@ uv run demo_monit.py $(HOST) $(m) $(c)

fals: clean_cache select_manifest
	@ uv run demo_fals.py $(HOST) $(m) $(c)

sign: clean_cache select_manifest
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/manifest.yaml
	@ uv run demo_sign.py $(HOST) $(m) $(c)

state: clean_cache select_manifest
	@ chmod +x ../simulator/_utils/list_signals.py
	@ ../simulator/_utils/list_signals.py < ../simulator/manifest.yaml
	@ uv run demo_state.py $(HOST) $(m) $(c)
