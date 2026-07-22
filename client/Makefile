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
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=1 C=1" "# WI: [d_lead], RO: [d_rel, v_rel, v_ego, a_ego]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=2 C=2" "# RI: [x, y], RO: [x, y, result]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(MONIT)" "M=3 C=1" "# WI: [Pedal Angle], RO: [AFref, AF, controller_mode]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=1 C=1" "# WI: [d_lead], RO: [d_rel, v_rel, v_ego, a_ego]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=2 C=1" "# WI: [x, y], RO: [result]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(FALS)"  "M=3 C=2" "# WI: [Pedal Angle, Engine Speed], RO: [AFref, AF, controller_mode]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=1 C=2" "# WI: [d_lead], RO: [d_rel, v_rel, v_ego, a_ego]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=2 C=1" "# WI: [x, y], RO: [result]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(SIGN)"  "M=3 C=2" "# WI: [Pedal Angle, Engine Speed], RO: [AFref, AF, controller_mode]"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "M=2 C=1" "# No addressable internal state in ToyModel"
	@printf "make %$(WIDTH)s %s\t%s\n" "$(STATE)" "M=3 C=3" "# WI: [Pedal Angle, Engine Speed], state: [Integrator_CSTATE]"

clean_cache:
	@ echo "Cleaning the KeyValue cache..."
	@ docker exec redis redis-cli --scan --pattern "simulation:*" | xargs -r docker exec redis redis-cli DEL

monit: clean_cache
	@ uv run monit.py $(HOST) $(M) $(C)

fals: clean_cache
	@ uv run fals.py $(HOST) $(M) $(C)

sign: clean_cache
	@ uv run sign.py $(HOST) $(M) $(C)

state: clean_cache
	@ uv run state.py $(HOST) $(M) $(C)
