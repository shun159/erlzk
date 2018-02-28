REBAR?=rebar

ERL_FLAGS=ERL_FLAGS="-config test/eunit"

all: build

build:
	$(REBAR) compile

clean:
	$(REBAR) clean

doc:
	$(REBAR) doc

test: build
	$(ERL_FLAGS) $(REBAR) eunit

setup_dialyzer: build
	dialyzer --build_plt --apps erts kernel stdlib compiler runtime_tools crypto tools inets ssl public_key ./ebin

dialyze: build
	dialyzer --add_to_plt --plt ~/.dialyzer_plt --output_plt $(APP_NAME).plt
	dialyzer --plt ${APP_NAME}.plt --src src -Werror_handling -Wrace_conditions -Wunmatched_returns

.PHONY: all build clean doc test setup_dialyzer dialyze
