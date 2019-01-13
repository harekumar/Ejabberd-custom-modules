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

-behaviour(gen_mod).

%% gen_mod callbacks
-export([start/2, stop/1, intercept_packet/1]).

-include("xmpp.hrl").
-include("logger.hrl").
-include("lager.hrl").

-define(PROCNAME, ?MODULE).
-define(MOBILE_NUMBER_REGEX, "[+]*[(]{0,1}[0-9]{1,4}[)]{0,1}[-\s\./0-9]*$").

start(_Host, _Opts) ->
    lager:log(info, self(), "Starting sawerly_message_interceptor Hare Kumar module"),
    ejabberd_hooks:add(user_send_packet, _Host, ?MODULE,
		       intercept_packet, 88).

stop(_Host) ->
    lager:log(info, self(), "Stoping sawerly_message_interceptor module"),
    ejabberd_hooks:delete(user_send_packet, _Host, ?MODULE,
		       intercept_packet, 88).

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
	
parse_and_process_chat_message({#message{id = Id, from = From, to = To, body = Body} = Pkt, #{jid := JID} = C2SState}) -> 
%parse_and_process_chat_message({#id = Id, from = From, to = To, body = Body}, JID, C2SState) ->
	lager:log(info, self(), "inside parse_and_process_chat_message method"),
	Sender = binary_to_list(From#jid.luser),
    LServer = binary_to_list(JID#jid.lserver),
    Receiver = binary_to_list(To#jid.luser),
    
    Text = binary_to_list(element(3,lists:nth(1, Body))),

    %Text = fxml:get_cdata(Pkt),
    lager:log(info, self(), "From: ~p & To: ~p & message: ~p", [Sender, Receiver, Text]),

    case re:run(Text, ?MOBILE_NUMBER_REGEX) of
    	{match, Captured} -> 
    		lager:log(info, self(), "Found contact number in the message text! Message: ~p ", [Text]),
    		NewPkt = construct_modified_packet_with_empty_text(Pkt, Body),
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
	lager:log(info, self(), "PacketHK BodyTuple ~p ", [BodyTuple]),
	NewMessageString = "Message replaced!",
	lager:log(info, self(), "PacketHK NewMessageString ~p ", [NewMessageString]),
	MessageBinary = list_to_binary(NewMessageString),
	lager:log(info, self(), "PacketHK MessageBinary ~p ", [MessageBinary]),
	NewBodyTuple = setelement(3, BodyTuple, MessageBinary),
	lager:log(info, self(), "PacketHK NewBodyTuple ~p ", [NewBodyTuple]),
	NewList = [NewBodyTuple],
	lager:log(info, self(), "PacketHK NewList ~p ", [NewList]),
	NewPacket = setelement(8, Pkt, NewList),
	lager:log(info, self(), "PacketHK after conversion ~p ", [NewPacket]),
	NewPacket.

