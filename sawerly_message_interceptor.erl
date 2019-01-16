%%%-------------------------------------------------------------------
%%% File    : sawerly_message_interceptor.erl
%%% Author  : Hare Kumar (harekumar1@gmail.com)
%%% Created : 13 January 2019 by Hare Kumar (harekumar1@gmail.com)
%%% 
%%% Should intercept each sent packet & check if the mobile number pattern in available in the message.
%%% If the message contains contanct number in it then do the followings
%%% 
%%% Log the details to the mysql-table with sender, receiver & message content in it.
%%% Keep the message count of sharing mobile number in chat & store it in some other new table
%%% If the phone number in message corsses threshold block the user.
%%% Send the email to the Admin about the blocked user.
%%% Add functionality for admin to unblock the user.
%%% 
%%%-------------------------------------------------------------------

-module(sawerly_message_interceptor).
-author('harekumar1@gmail.com').
-compile([{parse_transform, ejabberd_sql_pt}]).

-behaviour(gen_mod).

%% gen_mod callbacks
-export([start/2, stop/1, intercept_packet/1, depends/2, mod_options/1, init/2]).

%-include("ejabberd.hrl").
-include("xmpp.hrl").
-include("logger.hrl").
-include("lager.hrl").
-include("ejabberd_sql_pt.hrl").

-define(PROCNAME, ?MODULE).
-define(MOBILE_NUMBER_REGEX, "[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$").

violated_chats() ->
	"violated_chats".

violated_chats_counter() ->
	"violation_counter".

-record(violation_counter, {from, counter}).

start(_Host, Opts) ->
    lager:log(info, self(), "Starting sawerly_message_interceptor Hare Kumar module"),
    init(_Host, Opts),
    ejabberd_hooks:add(user_send_packet, _Host, ?MODULE,
		       intercept_packet, 88).

stop(_Host) ->
    lager:log(info, self(), "Stoping sawerly_message_interceptor module"),
    ejabberd_hooks:delete(user_send_packet, _Host, ?MODULE,
		       intercept_packet, 88).

%% called from start_link/2 and sets up the db connection
init(_Host, Opts) ->
	lager:log(info, self(), "Starting ~p", [?MODULE]),

	crypto:start(),
	application:start(emysql),

	Server = gen_mod:get_opt(server, Opts, fun(Val) -> binary_to_list(Val) end, "localhost"),
	Port = gen_mod:get_opt(port, Opts, fun(Val) -> Val end, 3306),
	Database = gen_mod:get_opt(database, Opts, fun(Val) -> binary_to_list(Val) end, "ejabberd"),
	Username = gen_mod:get_opt(username, Opts, fun(Val) -> binary_to_list(Val) end, "ejabberd"),
	Password = gen_mod:get_opt(password, Opts, fun(Val) -> binary_to_list(Val) end, "ejabberd"),
	PoolSize = gen_mod:get_opt(pool_size, Opts, fun(Val) -> Val end, 1),
	Encoding = gen_mod:get_opt(encoding, Opts, fun(Val) -> Val end, utf8),

	lager:log(info, self(), "Opening mysql connection ~s@~s:~p/~s ~p ~p ~p", [Username, Server, Port, Database, Password, PoolSize, Encoding]),
	emysql:add_pool(mod_log_chat_mysql5_db, PoolSize, Username, Password, Server, Port, Database, Encoding),
	%ejabberd_hooks:add(user_send_packet, _Host, ?MODULE, log_packet_send, 0),
	application:set_env(sawerly, s_mysql_host, Server),
	application:set_env(sawerly, s_mysql_username, Username),
	application:set_env(sawerly, s_mysql_pass, Password),
	application:set_env(sawerly, s_mysql_db, Database),
	application:set_env(sawerly, s_mysql_port, Port),
	{ok, undefined}.

depends(_Host, _Opts) ->
    [].

mod_options(Host) ->
    [].

intercept_packet(Pkt) ->
	lager:log(info, self(), "Intercepting each packet in sawerly_message_interceptor. PacketPP ~p", [Pkt]),
	PacketType = element(1, element(1, Pkt)),
	lager:log(info, self(), "PacketPP ~p", [PacketType]),
	case PacketType of 
		message -> 
			parse_and_process_chat_message(Pkt);
		_ ->
			Pkt
	end.
	
parse_and_process_chat_message({#message{id = _Id, from = From, to = To, body = Body} = Pkt, #{jid := JID} = C2SState}) -> 
%parse_and_process_chat_message({#id = Id, from = From, to = To, body = Body}, JID, C2SState) ->
	lager:log(info, self(), "inside parse_and_process_chat_message method"),
	Sender = binary_to_list(From#jid.luser),
    LServer = binary_to_list(JID#jid.lserver),
    Receiver = binary_to_list(To#jid.luser),
    Text = binary_to_list(element(3,lists:nth(1, Body))),

    %Text = fxml:get_cdata(Pkt),
    lager:log(info, self(), "From: ~p & To: ~p & message: ~p", [Sender, Receiver, Text]),

    case re:run(Text, ?MOBILE_NUMBER_REGEX) of
    	{match, _Captured} -> 
    		lager:log(info, self(), "Found contact number in the message text! Message: ~p ", [Text]),
    		NewPkt = construct_modified_packet_with_empty_text(Pkt, Body),
    		store_violated_chat(Receiver, Sender, Text),
    		block_or_increment_violation_counter(Sender, LServer),
    		proceed_with_modified_message(NewPkt, C2SState);
    	nomatch ->
    		lager:log(info, self(), "No match found for contact number in the message!"),
    		proceed_with_modified_message(Pkt, C2SState)
    end.

proceed_with_modified_message(Pkt, C2SState) ->
	{Pkt, C2SState}.

construct_modified_packet_with_empty_text(Pkt, Body) ->
	lager:log(info, self(), "PacketHK before conversion ~p ", [Pkt]),
	BodyTuple = lists:nth(1, Body),
	NewMessageString = "Message replaced!",
	NewPacket = setelement(8, Pkt,[setelement(3, BodyTuple, list_to_binary(NewMessageString))]),
	lager:log(info, self(), "PacketHK after conversion ~p ", [NewPacket]),
	NewPacket.

store_violated_chat(To, From, Text) ->
	
	Query = ["INSERT INTO ", violated_chats(), " (`from`, `to`, `text`) VALUES",
		"(?, ?, ?)"],
	sql_query(Query, [From, To, Text]),
	ok.

sql_query(Query, Params) ->
	case sql_query_internal_silent(Query, Params) of
		{error, Reason} ->
			lager:log(info, self(), "~p while ~p", [Reason, lists:append(Query)]),
			{error, Reason};
		Rez -> Rez
	end.

sql_query_internal_silent(Query, Params) ->
	lager:log(info, self(), "Query ~p, Params ~p ", [Query, Params]),
    emysql:prepare(mod_log_chat_mysql5_stmt, Query),
    emysql:execute(mod_log_chat_mysql5_db, mod_log_chat_mysql5_stmt, Params).

get_total_violation_count(Sender) -> 
	Query = ["SELECT * FROM ", violated_chats_counter(), " WHERE `from` = ", "?"],
	Result = sql_query(Query, [Sender]),
	lager:log(info, self(), "Result: ~p", [Result]),
	Recs = emysql:as_record(Result, violation_counter, record_info(fields, violation_counter)),
	lager:log(info, self(), "Recs: ~p", [Recs]),
	Counter = [Foo#violation_counter.counter || Foo <- Recs],
	case length(Counter) of 
		0 ->
			0;
		_ ->
			lists:nth(1, Counter)
	end.

block_or_increment_violation_counter(Sender, LServer) ->
	Counter = get_total_violation_count(Sender),
	lager:log(info, self(), "VIOLATION_COUNTER: ~p", [Counter]),
	case Counter < 3 of 
		true ->
			increment_violation_counter(Sender, Counter);
		_ ->
			block_user_if_exceeds_voilation(Sender, LServer)
	end.

increment_violation_counter(Sender, Counter) ->
	
	case Counter of 
		0 -> 
			% Insert into violated_chats_counter table
			insert_violation_counter(Sender, Counter+1);
		_ ->
			% Update counter into table
			update_violation_counter(Sender, Counter+1)
	end.

insert_violation_counter(Sender, Counter) ->
	Query = ["INSERT INTO ", violated_chats_counter(), " (`from`, `counter`) VALUES", "(?, ?)"],
	sql_query(Query, [Sender, Counter]),
	ok.

update_violation_counter(Sender, Counter) ->
	Query = ["UPDATE ", violated_chats_counter(), " set `counter` = ? WHERE `from` = ?"],
	sql_query(Query, [Counter, Sender]),
	ok.

% Block the user from chat
%<<"user3">>,<<"localhost">>,<<"hello">>
block_user_if_exceeds_voilation(Sender, LServer) -> 
	lager:log(info, self(), "About to block the user ~p & LServer ~p", [Sender, LServer]),
	User = list_to_binary(Sender),
	Server = list_to_binary(LServer),
	ReasonText = <<"Violated 3 times phone number rule in chat">>,
	mod_admin_extra:ban_account(User, Server, ReasonText),
	ok.
