%%%===================================================================
%% @author Erdem Aksu
%% @copyright 2016 Pundun Labs AB
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
%% implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%% -------------------------------------------------------------------
%% @doc
%% SSH Channel callback module that implements shell and command 
%% executions.
%% @end
%%%===================================================================


-module(gb_cli_server).

-behaviour(ssh_daemon_channel).

%% API functions
-export([exit/0,
	 usage/2,
	 usage_expand/2]).

-export([start_link/1]).

%% ssh_channel callbacks
-export([init/1,
         handle_msg/2,
         handle_ssh_msg/2,
	 terminate/2,
         code_change/3]).

-include_lib("gb_log/include/gb_log.hrl").

-record(state, {id,
		cm,
		history = [],
		future = [],
		bytes = [],
		ris,
		last_ris = [],
		cursor = 0,
		routines = #{},
		welcome = ""}).

-type ssh_connection_ref() :: term().

-type ssh_channel_id() :: integer().

-type ssh_data_type_code() :: 1 | %% stderr
			      0.  %% normal
-type data_events() :: {data, ssh_channel_id(), ssh_data_type_code(),
			Data :: binary()} |
		       {eof, ssh_channel_id()}.

-type status_events() :: {signal, ssh_channel_id(), any()} |
			 {exit_signal, ssh_channel_id(),
			    ExitSignal :: string(),
			    ErrorMsg ::string(),
			    LanguageString :: string()} |
			 {exit_status, ssh_channel_id(),
			    ExitStatus :: integer()} |
			 {closed, ssh_channel_id()}.

-type terminal_events() :: {env, ssh_channel_id(), WantReply :: boolean(),
			    Var ::string(), Value :: string()} |
			   {pty, ssh_channel_id(), WantReply :: boolean(),
			    {Terminal :: string(), CharWidth :: integer(),
				RowHeight :: integer(), PixelWidth :: integer(),
				PixelHeight :: integer(),
				TerminalModes :: [{Opcode :: atom() | integer(),
						   Value :: integer()}]}} |
			   {shell, WantReply :: boolean()} |
			   {window_change, ssh_channel_id(),
			    CharWidth :: integer(), RowHeight :: integer(),
			    PixWidth :: integer(), PixHeight :: integer()} |
			   {exec, ssh_channel_id(), WantReply :: boolean(),
			    Cmd :: string()}.

-type ssh_event_msg() :: data_events() | status_events() | terminal_events().

-type event() :: {ssh_cm, ssh_connection_ref(), ssh_event_msg()}.

%%--------------------------------------------------------------------
%% @doc
%% Starts the server that handles SSH Channel
%% @end
%%--------------------------------------------------------------------
-spec start_link(Mod :: atom()) ->
    {ok, ChannelRef :: pid()} | {error, Reason :: term()}.
start_link(Mod) ->
    Routines = add_base_routines(Mod:routines()),
    CbInitArgs = [{welcome, Mod:welcome_msg()},
		  {routines, Routines}],
    Options = [{system_dir, Mod:system_dir()},
	       {user_dir, Mod:user_dir()},
	       {ssh_cli, {?MODULE, CbInitArgs}}],
    IP = parse_ip_address(Mod:ip()),
    Port = Mod:port(),
    ssh:daemon(IP, Port, Options).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init(Args) ->
    Welcome = proplists:get_value(welcome, Args),
    Routines = proplists:get_value(routines, Args),
    {ok, #state{routines = Routines, welcome = Welcome}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handles SSH Connection Protocol messages that may need 
%% service-specific attention. 
%% @end
%%--------------------------------------------------------------------
-spec handle_ssh_msg(Msg :: event(), State :: #state{}) ->
    {ok, State :: #state{}} |
    {stop, ssh_channel_id(), State :: #state{}}.

handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<3>>}},
	       #state{history = H, future = F, bytes = B} = State) ->
    %%Ctrl+C
    ssh_connection:send(CM, ChannelId, <<"^C\n\r">>),
    prompt(CM, ChannelId, [], 0),
    NH =
	case F of
	    [] ->
		H;
	    [_] ->
		[B|H];
	    _ ->
		[_|FR] = lists:reverse(F),
		FR ++ [B|H]
	end,		    
    {ok, State#state{history = NH, future = [], bytes = [], cursor = 0}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<1>>}},
	       #state{bytes = Bytes} = State) ->
    %%Ctrl+A
    C = length(Bytes),
    prompt(CM, ChannelId, Bytes, C),
    {ok, State#state{cursor = C, ris = undefined}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<5>>}},
	       #state{bytes = Bytes} = State) ->
    %%Ctrl-E
    prompt(CM, ChannelId, Bytes, 0),
    {ok, State#state{cursor = 0, ris = undefined}};
handle_ssh_msg({ssh_cm, _CM, {data, ChannelId, 0, <<4>>}}, State) ->
    ?debug("ssh_cm.. Ctrl+D", []),
    {stop, ChannelId, State};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<18>>}},
	       #state{bytes = B, ris = undefined} = State) ->
    %%Ctrl+R
    prompt(CM, ChannelId, B, 0, {ok, []}),
    {ok, State#state{cursor = 0, ris = []}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<18>>}},
	       #state{history = H, future = F, bytes = B,
		      ris = [], last_ris = LastRis} = State) ->
    %%Ctrl+R
    {S,NH,NB,NF,NC} = reverse_search(LastRis, H, B, F),
    prompt(CM, ChannelId, NB, NC, {S, LastRis}),
    {ok, State#state{history = NH, future = NF,
		     bytes = NB, ris = LastRis, cursor = NC}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<18>>}},
	       #state{history = [], future = F,
		      bytes = B, ris = Ris} = State) ->
    %%Ctrl+R
    prompt(CM, ChannelId, B, 0, {failed, Ris}),
    {ok, State#state{history = [], future = F,
		     bytes = B, cursor = 0}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<18>>}},
	       #state{history = [HH|HR], future = F,
		      bytes = B, ris = Ris} = State) ->
    %%Ctrl+R
    {S,NH,NB,NF,NC} = reverse_search(Ris, HR, HH, [B|F], B),
    prompt(CM, ChannelId, NB, NC, {S, Ris}),
    {ok, State#state{history = NH, future = NF,
		     bytes = NB, cursor = NC}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<27:8,91:8,65:8>>}},
	       #state{history = H, future = F,
		      bytes = B, cursor = C} = State) ->
    %%Up Arrow
    NewState =
    case H of
	[] ->
	    prompt(CM, ChannelId, B, 0),
	    State#state{cursor = 0};
	[HC | HRest] ->
	    prompt(CM, ChannelId, HC, C),
	    State#state{history = HRest,
			future = [B|F],
			bytes = HC}
    end,
    {ok, NewState#state{cursor = 0, ris = undefined}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<27:8,91:8,66:8>>}},
	       #state{history = H, future = F,
		      bytes = B, cursor = C} = State) ->
    %%Down Arrow
    NewState =
    case F of
	[] ->
	    prompt(CM, ChannelId, B, 0),
	    State#state{history = H, bytes = B, cursor = 0};
	[FC | FRest] ->
	    prompt(CM, ChannelId, FC, C),
	    State#state{history = [B|H], future = FRest, bytes = FC}
    end,
    {ok, NewState#state{cursor = 0, ris = undefined}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<27:8,91:8,$C:8>>}},
	       #state{bytes = Bytes,
		      cursor = C} = State) ->
    %%Right Arrow
    NewCursor = cursor_right(C),
    prompt(CM, ChannelId, Bytes, NewCursor),
    {ok, State#state{cursor = NewCursor, ris = undefined}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<27:8,91:8,$D:8>>}},
	       #state{bytes = Bytes,
		      cursor = C} = State) ->
    %%Left Arrow
    NewCursor = cursor_left(C, length(Bytes)),
    prompt(CM, ChannelId, Bytes, NewCursor),
    {ok, State#state{cursor= NewCursor, ris = undefined}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<27:8,$O:8,$H:8>>}},
	       #state{bytes = Bytes} = State) ->
    %%Home
    C = length(Bytes),
    prompt(CM, ChannelId, Bytes, C),
    {ok, State#state{cursor = C, ris = undefined}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<27:8,$O:8,$F:8>>}},
	       #state{bytes = Bytes} = State) ->
    %%End
    prompt(CM, ChannelId, Bytes, 0),
    {ok, State#state{cursor = 0, ris = undefined}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<27:8,$[:8,$3:8,$~:8>>}},
	       #state{bytes = Bytes, cursor = C} = State) ->
    %%Del
    NewState =
	if C > 0 ->
	    NewCursor = C-1,
	    NewBytes = delete_char(NewCursor, Bytes),
	    prompt(CM, ChannelId, NewBytes, NewCursor),
	    State#state{bytes=NewBytes, cursor = NewCursor};
	   true ->
	    State
	end,
    {ok, NewState#state{ris=undefined}};
handle_ssh_msg({ssh_cm, _CM, {data, _ChannelId, 0, <<27:8,_/binary>> = Bin}},
    State) ->
    ?debug("Unhandled Data with esc char: ~p ", [Bin]),
    {ok, State};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<127>>}},
	       State = #state{bytes = Bytes, cursor = C,
			      ris = undefined}) ->
    %%Backspace handling
    NewBytes = delete_char(C, Bytes),
    prompt(CM, ChannelId, NewBytes, C),
    {ok, State#state{bytes=NewBytes}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<127>>}},
	       State = #state{history = H, future = F,
			      bytes = B,
			      ris = Ris, last_ris = LastRis}) ->
    %%Backspace handling
    NewRis =
	case Ris of
	    [] -> [];
	    [_|NR] -> NR
	end,
    NewLastRis =
	case NewRis of
	    [] -> LastRis;
	    _ -> NewRis
	end,
    {S,NH,NB,NF,NC} = reverse_search(NewRis, H, B, F),
    prompt(CM, ChannelId, NB, NC, {S,NewRis}),
    ?debug("NewRis: ~p, NewLastRis: ~p",[NewRis, NewLastRis]),
    {ok, State#state{history = NH, future = NF, bytes = NB,
		     ris = NewRis, last_ris = NewLastRis,
		     cursor = NC}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<"\t">>}},
	       State = #state{bytes = Bytes,
			      routines = Routines,
			      cursor = C,
			      ris = undefined}) ->
    %%Tab handling
    NewBytes = expand(CM, ChannelId, Bytes, Routines),
    prompt(CM, ChannelId, NewBytes, C),
    {ok, State#state{bytes=NewBytes}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<"\t">>}},
	       State = #state{bytes = Bytes,
			      cursor = C}) ->
    %%Tab handling during reverse-i-search
    prompt(CM, ChannelId, Bytes, C),
    {ok, State#state{bytes=Bytes}};
handle_ssh_msg({ssh_cm, CM, {data, ChannelId, 0, <<"\r">>}},
	       State = #state{history = H, future = F,
			      bytes = Bytes,
			      routines = Routines}) ->
    %% Command entered.
    Dmc = strip_trailing_spaces(Bytes), 
    Cmd = lists:reverse(Dmc),
    ?debug("Command: ~p", [Cmd]),
    ssh_connection:send(CM, ChannelId, <<"\n\r">>),
    case execute(Cmd, Routines) of
	{ok, Result} ->
	    ssh_connection:send(CM, ChannelId, Result),
	    prompt(CM, ChannelId, [], 0),
	    FR =
		case lists:reverse(F) of
		    [] -> [];
		    [_] -> [];
		    [_|R] -> R ++ [Dmc]
		end,
	    {ok, State#state{history = add_to_history(Dmc, FR ++ H),
			     future = [],
			     bytes=[],
			     cursor=0,
			     ris = undefined}};
	{stop, Msg} ->
	    ?debug("stopping channel: ~p", [Msg]),
	    {stop,  ChannelId, State}
    end;
handle_ssh_msg({ssh_cm, CM,
	       {data, ChannelId, 0, <<Char:8, _/binary>>}},
	       State = #state{bytes = Bytes, cursor = C, ris = undefined}) ->
    Acc = insert_char(Char, C, Bytes),
    prompt(CM, ChannelId, Acc, C),
    {ok, State#state{bytes = Acc}};
handle_ssh_msg({ssh_cm, CM,
	       {data, ChannelId, 0, <<Char:8, _/binary>>}},
	       State = #state{history = H, future = F,
			      bytes = B, ris = Ris}) ->
    NewRis = insert_char(Char, 0, Ris),
    {S,NH,NB,NF,NC} = reverse_search(NewRis, H, B, F),
    prompt(CM, ChannelId, NB, NC, {S,NewRis}),
    {ok, State#state{history = NH, future = NF, bytes = NB,
		     cursor = NC, ris = NewRis, last_ris = NewRis}};
handle_ssh_msg({ssh_cm, _ConnectionManager,
		{data, _ChannelId, 1, Data}}, State) ->
    ?debug("ssh_cm..standard_error,  ~p", [Data]),
    {ok, State};
handle_ssh_msg({ssh_cm, _ConnectionManager, {eof, _ChannelId}}, State) ->
    ?debug("ssh_cm..eof", []),
    {ok, State};
handle_ssh_msg({ssh_cm, _, {signal, _, _}}, State) ->
    ?debug("ssh_cm..signal", []),
    %% Ignore signals according to RFC 4254 section 6.9.
    {ok, State};
handle_ssh_msg({ssh_cm, _, {exit_signal, ChannelId, _, _Error, _}},
	       State) ->
    ?debug("ssh_cm..exit_signal", []),
    {stop, ChannelId,  State};
handle_ssh_msg({ssh_cm, _, {exit_status, ChannelId, _Status}}, State) ->
    ?debug("ssh_cm..exit_status", []),
    {stop, ChannelId, State};
handle_ssh_msg(_Msg, State) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handles other messages than SSH Connection Protocol, call, or cast
%% messages sent to the channel. 
%% @end
%%--------------------------------------------------------------------
-spec handle_msg(Msg :: timeout | term(), State :: #state{}) ->
    {ok, State :: #state{}} |
    {stop, ssh_channel_id(), State :: #state{}}.
handle_msg({ssh_channel_up, ChannelId, CM},
	   #state{welcome = Welcome} = State) ->
    ?debug("ssh_channel_up", []),
    ssh_connection:send(CM, ChannelId, Welcome++"\n"),
    prompt(CM, ChannelId, [], 0),
    {ok, State#state{id = ChannelId,
		     cm = CM}};
handle_msg(_Msg, State) ->
    ?debug("ssh ~p", [_Msg]),
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a channel process when it is about to
%% terminate. Before this function is called, ssh_connection:close/2
%% is called, if it has not been called earlier. This function does 
%% any necessary cleaning up. When it returns, the channel process 
%% terminates with reason Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
prompt(CM, ChannelId, Bytes, Cursor)->
    prompt(CM, ChannelId, Bytes, Cursor, undefined).

prompt(CM, ChannelId, Bytes, Cursor, RisTuple)->
    Move = cursor_move(Cursor),
    Str = lists:reverse(Bytes),
    P =
	case RisTuple of
	    undefined ->
		"pundun> ";
	    {failed, Ris} ->
		"(failed reverse-i-search)`"++lists:reverse(Ris)++"': ";
	    {ok, Ris} ->
		"(reverse-i-search)`"++lists:reverse(Ris)++"': "
	end,
    Out = lists:flatten("\33[2K\r"++P++Str++Move),
    %?debug("prompt: ~p", [Out]),
    ssh_connection:send(CM, ChannelId, Out).

cursor_move(0) ->
    "";
cursor_move(Int) ->
    io_lib:format("\33[~BD", [Int]).

expand(CM, ChannelId, Bytes, Routines) ->
    case option_expand(Bytes) of
	{true, Tokens} ->
	    expand_options(CM, ChannelId, Bytes, Routines, Tokens);
	false ->
	    expand_command(CM, ChannelId, Bytes, Routines)
    end.

expand_options(CM, ChannelId, Bytes, Routines, Tokens) ->
    [Base|_] = Tokens,
    case get_attr(Base, expand, Routines) of
	{M, F, A} ->
	    NewArgs = check_arity(A, Tokens, Routines),
	    ?debug("apply(~p,~p,~p)",[M,F,NewArgs]),
	    try apply(M, F, NewArgs) of
		{ok, []} ->
		    Bytes;
		{ok, [Result]} ->
		    lists:reverse(add_space(lists:droplast(Tokens)++[Result]));
		{ok, ResultList} ->
		    Exp = add_space(ResultList) ++ "\n",
		    ssh_connection:send(CM, ChannelId, "\n\33[2K\r" ++ Exp),
		    Bytes
	    catch
		error:Error ->
		    ?warning("CLI option expand error: ~p", [Error]),
		    Bytes
	    end;
	undefined ->
	    Bytes
    end.

expand_command(CM, ChannelId, Bytes, Routines) ->
    Prefix = lists:reverse(Bytes),
    ?debug("Expand Command Prefix: ~p", [Prefix]),
    Fun =
	fun(Cmd, _, {C, Acc}) ->
	    case lists:prefix(Prefix, Cmd) of
		true -> {C+1, Acc ++ Cmd ++ " "};
		_ -> {C, Acc}
	    end
	end,
    {Count, Cmds} = maps:fold(Fun, {0, []}, Routines),
    case Count of
	0 -> 
	    Bytes;
	1 -> 
	    lists:reverse(Cmds);
	_ ->
	    Expansion =  Cmds ++ "\n",
	    ssh_connection:send(CM, ChannelId, "\n\33[2K\r" ++ Expansion),
	    Bytes
    end.

option_expand(L) when length(L) =< 1->
    false;
option_expand([32|_] = Bytes) ->
    Prefix = lists:reverse(Bytes),
    Base = string:tokens(Prefix, " "),
    {true, Base++[""]};
option_expand(Bytes) ->
    Prefix = lists:reverse(Bytes),
    case string:tokens(Prefix, " ") of
	[_,_|_] = A -> {true, A};
	[_] -> false
    end.

add_space(L) ->
    add_space(L, []).

add_space([E|Rest], Acc) ->
    add_space(Rest, Acc ++ E ++ " ");
add_space([], Acc) ->
    Acc.

strip_trailing_spaces([32|Rest]) ->
    strip_trailing_spaces(Rest);
strip_trailing_spaces(Bytes) ->
    Bytes.

-spec execute(Cmd :: string(), Routines :: map()) ->
    {ok, Result :: string()} | {stop, Result :: string()}.
execute([], _Routines) ->
    {ok, []};
execute(Cmd, Routines) ->
    {Name, Args} = parse_cmd(Cmd),
    case get_attr(Name, mfa, Routines) of
	{M, F, A} ->
	    apply_cmd(M, F, A, Args, Routines);
	undefined ->
	    {ok, Cmd ++ ": command not found\n"}
    end.

-spec parse_cmd(Cmd :: string()) ->
    {Op :: string(), Args :: [string()]}.
parse_cmd(Cmd) ->
    [Op | Args] = string:tokens(Cmd, " "),
    {Op, Args}.

apply_cmd(M, F, A, Args, Routines) ->
    case check_arity(A, Args, Routines) of
	error ->
	    {ok, "Wrong number of arguments\n"};
	NewArgs ->
	    apply_cmd(M, F, NewArgs)
    end.

apply_cmd(M, F, Args) ->
    try apply(M, F, Args) of
	{ok, Result} ->
	    {ok, printable(Result) ++ "\n"};
	{stop, Msg} ->
	    {stop, printable(Msg) ++ "\n"}
    catch
	error:Error ->
	    ?warning("CLI command error: ~p", [Error]),
	    {ok, printable(Error) ++ "\n"}
    end.

check_arity(0, [], _) ->
    [];
check_arity(1, [_|_] = A, _) ->
    [A];
check_arity(2, [_|_] = A, R) ->
    [A, R];
check_arity(_, _, _) ->
    error.

add_to_history([], History) ->
    History;
add_to_history(Dmc, [Dmc | History]) ->
    [Dmc | History];
add_to_history(Dmc, History) ->
    [Dmc | History].

cursor_right(0) ->
    0;
cursor_right(N) ->
    N-1.

cursor_left(N, N) ->
    N;
cursor_left(N, _Len) ->
    N+1.

insert_char(Char, C, Bytes)->
    insert_char(Char, C, [], Bytes).

insert_char(Char, 0, S, Bytes)->
    lists:reverse(S)++[Char|Bytes];
insert_char(Char, C, S, [B|Rest])->
    insert_char(Char, C-1, [B|S], Rest).

delete_char(_C, []) ->
    [];
delete_char(C, Bytes) ->
    delete_char(C, [], Bytes).

delete_char(0, S, [_|Rest]) ->
     lists:reverse(S)++Rest;
delete_char(C, S, [B|Rest]) ->
    delete_char(C-1, [B|S], Rest).
		
reverse_search([], H, B, F) ->
    {ok, H, B, F, 0};
reverse_search(Ris, H, B, F) ->
    reverse_search(Ris, H, B, F, B).

reverse_search(Ris, [], B, F, L) ->
    case string:str(B, Ris) of
	0 ->
	    {H, NB, NF} = rewind(L, [B|F]),
	    {failed, H, NB, NF, 0};
	Start ->
	    Cursor = length(Ris) + Start - 1,
	    {ok, [], B, F, Cursor}
    end;
reverse_search(Ris, [C | HRest] = H, B, F, L) ->
    case string:str(B, Ris) of
	0 ->
	    reverse_search(Ris, HRest, C, [B|F], L);
	Start ->
	    Cursor = length(Ris) + Start - 1,
	    {ok, H, B, F, Cursor}
    end.

rewind(L, List) ->
    rewind([], L, List).

rewind(H, L, [L|FRest]) ->
    {H, L, FRest};
rewind(H, L, [E|FRest]) ->
    rewind([E|H], L, FRest).

parse_ip_address(any) ->
    any;
parse_ip_address("any") ->
    any;
parse_ip_address(IP) when is_list(IP) ->
    case inet:parse_address(IP) of
	{ok, InetIP} ->
	    InetIP;
	{error, Reason} ->
	    {error, Reason}
    end.

add_base_routines(Routines) ->
    Base = #{"exit" => #{mfa => {?MODULE, exit, 0},
			 usage => "exit",
			 desc => "Exit CLI session."},
	     "usage" => #{mfa => {?MODULE, usage, 2},
			  expand => {?MODULE, usage_expand, 2},
			  usage => "usage CMD",
			  desc => "Show usage of a given command."},
	     "help" => #{mfa => {?MODULE, usage, 2},
			 expand => {?MODULE, usage_expand, 2},
			 usage => "help CMD",
			 desc => "Show usage of a given command.."}},
    maps:merge(Base, Routines).

%%%===================================================================
%%% Base routine functions
%%% routine_callback() -> {ok, string()} | {stop, string()}.
%%% routine_callback(Args :: [string()]) ->
%%%    {ok, string()} | {stop, string()}.
%%%===================================================================
exit() ->
    {stop, "Exit signal received"}.

usage([Cmd|_], Routines) ->
    Desc =
	case get_attr(Cmd, desc, Routines) of
	    undefined -> "Usage: ";
	    Str ->
		Str ++ "\n\rUsage: "
	end,
    Usage = get_attr(Cmd, usage, Routines),
    {ok, Desc ++ Usage}.

%%%===================================================================
%%% Expand Callbacks
%%% expand_callback(Args :: [string()]) -> {ok, [string()]}.
%%%===================================================================
usage_expand([U, Prefix], Routines) when U == "usage";
					 U == "help" ->
    Fun =
	fun(Cmd, _, Acc) ->
	    case lists:prefix(Prefix, Cmd) of
		true -> [Cmd | Acc];
		_ -> Acc
	    end
	end,
    Cmds = maps:fold(Fun, [], Routines),
    {ok, Cmds}.

-spec get_attr(Name :: string(), Attr :: atom(), Routines :: map()) ->
    T :: term() | undefined.
get_attr(Name, Attr, Routines) ->
    case maps:get(Name, Routines, undefined) of
	#{} = Map ->
	    maps:get(Attr, Map, undefined);
	undefined ->
	    undefined
    end.

printable(L) ->
    printable(L, io_lib:printable_list(L)).

printable(L, true) ->
    L;
printable(E, false) ->
    ?debug("Not printable result: ~p", [E]),
    io_lib:format("~p", [E]).
