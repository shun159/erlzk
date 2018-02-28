%% 2013-2014 (c) Mega Yu <yuhg2310@gmail.com>
%% 2013-2014 (c) huaban.com <www.huaban.com>
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%    http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
-module(erlzk_codec).

-include("erlzk.hrl").

-export([pack/2, pack/3, pack/4, unpack/1, unpack/2, unpack/3]).

-define(ZK_PERM_READ, 1).   % can read node’s value and list its children
-define(ZK_PERM_WRITE, 2).  % can set the node’s value
-define(ZK_PERM_CREATE, 4). % can create children
-define(ZK_PERM_DELETE, 8). % can delete children
-define(ZK_PERM_ADMIN, 16). % can execute set_acl

-define(ZK_EVENT_TYPE_NODE_CREATED, 1).
-define(ZK_EVENT_TYPE_NODE_DELETED, 2).
-define(ZK_EVENT_TYPE_NODE_DATA_CHANGED, 3).
-define(ZK_EVENT_TYPE_NODE_CHILDREN_CHANGED, 4).

-define(ZK_OP_CREATE, 1).
-define(ZK_OP_DELETE, 2).
-define(ZK_OP_EXISTS, 3).
-define(ZK_OP_GET_DATA, 4).
-define(ZK_OP_SET_DATA, 5).
-define(ZK_OP_GET_ACL, 6).
-define(ZK_OP_SET_ACL, 7).
-define(ZK_OP_GET_CHILDREN, 8).
-define(ZK_OP_SYNC, 9).
-define(ZK_OP_GET_CHILDREN2, 12).
-define(ZK_OP_CHECK, 13).
-define(ZK_OP_MULTI, 14).
-define(ZK_OP_CREATE2, 15).
-define(ZK_OP_RECONFIG, 16).
-define(ZK_OP_AUTH, 100).
-define(ZK_OP_SET_WATCHES, 101).
-define(ZK_OP_SASL, 102).
-define(ZK_OP_ERROR, -1).

-define(ZK_CODE_OK, 0).
-define(ZK_CODE_SYSTEM_ERROR, -1).
-define(ZK_CODE_RUNTIME_INCONSISTENCY, -2).
-define(ZK_CODE_DATA_INCONSISTENCY, -3).
-define(ZK_CODE_CONNECTION_LOSS, -4).
-define(ZK_CODE_MARSHALLING_ERROR, -5).
-define(ZK_CODE_UNIMPLEMENTED, -6).
-define(ZK_CODE_OPERATION_TIMEOUT, -7).
-define(ZK_CODE_BAD_ARGUMENTS, -8).
-define(ZK_CODE_UNKNOWN_SESSION, -12).
-define(ZK_CODE_API_ERROR, -100).
-define(ZK_CODE_NO_NODE, -101).
-define(ZK_CODE_NO_AUTH, -102).
-define(ZK_CODE_BAD_VERSION, -103).
-define(ZK_CODE_NO_CHILDREN_FOR_EPHEMERALS, -108).
-define(ZK_CODE_NODE_EXISTS, -110).
-define(ZK_CODE_NOT_EMPTY, -111).
-define(ZK_CODE_SESSION_EXPIRED, -112).
-define(ZK_CODE_INVALID_CALLBACK, -113).
-define(ZK_CODE_INVALID_ACL, -114).
-define(ZK_CODE_AUTH_FAILED, -115).
-define(ZK_CODE_SESSION_MOVED, -118).
-define(ZK_CODE_NOT_READ_ONLY, -119).
-define(ZK_CODE_NEW_CONFIG_NO_QUORUM, -120).
-define(ZK_CODE_RECONFIG_IN_PROGRESS, -121).
-define(ZK_CODE_EPHEMERAL_ON_LOCAL_SESSION, -122).

%% ===================================================================
%% Public API
%% ===================================================================

-type uint8()  :: 0..16#ff.
-type uint32() :: 0..16#ffffffff.
-type uint64() :: 0..16#ffffffffffffffff.

-type int32()  :: -16#80000000..16#7fffffff.

-spec pack(connect,     {ProtocolVersion :: uint32(), LastZxidSeen :: uint64(), TimeOut :: uint32(), SessionId :: uint64(), Password :: iodata()}) -> binary();
          (set_watches, {LastZxidSeen :: uint64(), DataWatches :: iodata(), ExistWatches :: iodata(), ChildWatches :: iodata()}) -> binary().
pack(connect, {ProtocolVersion, LastZxidSeen, Timeout, SessionId, Password}) ->
    <<ProtocolVersion:32, LastZxidSeen:64, Timeout:32, SessionId:64, (pack_str(Password))/binary>>.

-spec pack(add_auth, {Scheme :: iodata(), Auth :: iodata()}, Xid :: int32()) -> binary();
          (set_watches, {LastZxidSeen :: uint64(), DataWatches :: iodata(), ExistWatches :: iodata(), ChildWatches :: iodata()}, Xid :: int32()) -> binary().
pack(add_auth, {Scheme, Auth}, Xid) ->
    Packet = <<0:32, (pack_str(Scheme))/binary, (pack_bytes(Auth))/binary>>,
    wrap_packet(?ZK_OP_AUTH, Xid, Packet);

pack(set_watches, {LastZxidSeen, DataWatches, ExistWatches, ChildWatches}, Xid) ->
    Packet = <<LastZxidSeen:64, (pack_watches(DataWatches))/binary, (pack_watches(ExistWatches))/binary, (pack_watches(ChildWatches))/binary>>,
    wrap_packet(?ZK_OP_SET_WATCHES, Xid, Packet).

-spec pack(create,        {Path :: iodata(), Data :: iodata(), Acl :: erlzk:acl(), erlzk:create_mode()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (delete,        {Path :: iodata(), Version :: uint32()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (exists,        {Path :: iodata(), Watch :: boolean() | uint8()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (get_data,      {Path :: iodata(), Watch :: boolean() | uint8()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (set_data,      {Path :: iodata(), Data :: iodata(), Version :: uint32()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (get_acl,       {Path :: iodata()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (set_acl,       {Path :: iodata(), Acl :: erlzk:acl(), Version :: uint32()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (sync,          {Path :: iodata()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (get_children,  {Path :: iodata(), Watch :: boolean() | uint8()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (get_children2, {Path :: iodata(), Watch :: boolean() | uint8()}, Xid :: int32(), Chroot :: iodata()) -> binary();
          (multi,         Ops :: [erlzk:op()], Xid :: int32(), Chroot :: iodata()) -> binary();
          (create2,       {Path :: iodata(), Data :: iodata(), Acl :: erlzk:acl(), erlzk:create_mode()}, Xid :: int32(), Chroot :: iodata()) -> binary().
pack(create, {Path, Data, Acl, CreateMode}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, (pack_bytes(Data))/binary, (pack_acl(Acl))/binary, (pack_create_mode(CreateMode))/binary>>,
    wrap_packet(?ZK_OP_CREATE, Xid, Packet);

pack(delete, {Path, Version}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, Version:32/signed>>,
    wrap_packet(?ZK_OP_DELETE, Xid, Packet);

pack(exists, {Path, true}, Xid, Chroot) ->
    pack(exists, {Path, 1}, Xid, Chroot);
pack(exists, {Path, false}, Xid, Chroot) ->
    pack(exists, {Path, 0}, Xid, Chroot);
pack(exists, {Path, Watch}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, Watch:8>>,
    wrap_packet(?ZK_OP_EXISTS, Xid, Packet);

pack(get_data, {Path, true}, Xid, Chroot) ->
    pack(get_data, {Path, 1}, Xid, Chroot);
pack(get_data, {Path, false}, Xid, Chroot) ->
    pack(get_data, {Path, 0}, Xid, Chroot);
pack(get_data, {Path, Watch}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, Watch:8>>,
    wrap_packet(?ZK_OP_GET_DATA, Xid, Packet);

pack(set_data, {Path, Data, Version}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, (pack_bytes(Data))/binary, Version:32/signed>>,
    wrap_packet(?ZK_OP_SET_DATA, Xid, Packet);

pack(get_acl, {Path}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary>>,
    wrap_packet(?ZK_OP_GET_ACL, Xid, Packet);

pack(set_acl, {Path, Acl, Version}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, (pack_acl(Acl))/binary, Version:32/signed>>,
    wrap_packet(?ZK_OP_SET_ACL, Xid, Packet);

pack(get_children, {Path, true}, Xid, Chroot) ->
    pack(get_children, {Path, 1}, Xid, Chroot);
pack(get_children, {Path, false}, Xid, Chroot) ->
    pack(get_children, {Path, 0}, Xid, Chroot);
pack(get_children, {Path, Watch}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, Watch:8>>,
    wrap_packet(?ZK_OP_GET_CHILDREN, Xid, Packet);

pack(sync, {Path}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary>>,
    wrap_packet(?ZK_OP_SYNC, Xid, Packet);

pack(get_children2, {Path, true}, Xid, Chroot) ->
    pack(get_children2, {Path, 1}, Xid, Chroot);
pack(get_children2, {Path, false}, Xid, Chroot) ->
    pack(get_children2, {Path, 0}, Xid, Chroot);
pack(get_children2, {Path, Watch}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, Watch:8>>,
    wrap_packet(?ZK_OP_GET_CHILDREN2, Xid, Packet);

pack(multi, Ops, Xid, Chroot) ->
    Packet = pack_ops(Ops, Chroot),
    wrap_packet(?ZK_OP_MULTI, Xid, Packet);

pack(create2, {Path, Data, Acl, CreateMode}, Xid, Chroot) ->
    Packet = <<(pack_str(chroot(Path, Chroot)))/binary, (pack_bytes(Data))/binary, (pack_acl(Acl))/binary, (pack_create_mode(CreateMode))/binary>>,
    wrap_packet(?ZK_OP_CREATE2, Xid, Packet).

-spec unpack(<<_:64, _:_*8>>) -> {Xid :: int32(), Zxid :: uint64(), Code :: zk_code(), Body :: binary()}.
unpack(Packet) ->
    <<Xid:32/signed, Zxid:64, Code:32/signed, Body/binary>> = Packet,
    {Xid, Zxid, code_to_atom(Code), Body}.

-spec unpack(connect, <<_:64, _:_*8>>) -> {ProtocolVersion :: uint32(), TimeOut :: uint32(), SessionId :: uint64(), Password :: binary()}.
unpack(connect, Packet) ->
    <<ProtocolVersion:32, TimeOut:32, SessionId:64, Left/binary>> = Packet,
    {Password, _}= unpack_bytes(Left),
    {ProtocolVersion, TimeOut, SessionId, Password}.

unpack(create, Packet, Chroot) ->
    {Path, _} = unpack_str(Packet),
    unchroot(Path, Chroot);

unpack(exists, Packet, _Chroot) ->
    {Stat, _} = unpack_stat(Packet),
    Stat;

unpack(get_data, Packet, _Chroot) ->
    {Data, Left} = unpack_bytes(Packet),
    {Stat, _} = unpack_stat(Left),
    {Data, Stat};

unpack(set_data, Packet, _Chroot) ->
    {Stat, _} = unpack_stat(Packet),
    Stat;

unpack(get_acl, Packet, _Chroot) ->
    {Acl, Left} = unpack_acl(Packet),
    {Acl, unpack_stat(Left)};

unpack(set_acl, Packet, _Chroot) ->
    {Stat, _} = unpack_stat(Packet),
    Stat;

unpack(get_children, Packet, _Chroot) ->
    {Children, _} = unpack_strs(Packet),
    Children;

unpack(sync, Packet, Chroot) ->
    {Path, _} = unpack_str(Packet),
    unchroot(Path, Chroot);

unpack(get_children2, Packet, _Chroot) ->
    {Children, Left} = unpack_strs(Packet),
    {Stat, _} = unpack_stat(Left),
    {Children, Stat};

unpack(multi, Packet, Chroot) ->
    unpack_ops(Packet, Chroot);

unpack(create2, Packet, Chroot) ->
    {Path, Left} = unpack_str(Packet),
    {Stat, _} = unpack_stat(Left),
    {unchroot(Path, Chroot), Stat};

unpack(watched_event, Packet, Chroot) ->
    <<Type:32/signed, State:32/signed, Left/binary>> = Packet,
    {Path, _} = unpack_str(Left),
    {event_type_to_atom(Type), State, unchroot(Path, Chroot)}.

%% ===================================================================
%% Internal Functions
%% ===================================================================

-spec chroot(Path :: iodata(), Chroot :: iodata()) -> string().
chroot(Path, Chroot) when is_binary(Path) ->
    chroot(binary_to_list(Path), Chroot);
chroot(Path, Chroot) ->
    case Chroot of
        "/" -> Path;
        ""  -> Path;
        _   -> join(Chroot, Path)
    end.

-spec join(iodata(), iodata()) -> string().
join(Left, "/" ++ Right) ->
    filename:join([Left, Right]);
join(Left, Right) ->
    filename:join([Left, Right]).

-spec unchroot(string(), iodata()) -> string().
unchroot(Path, Chroot) ->
    case Chroot of
        "/" -> Path;
        ""  -> Path;
        _   -> string:substr(Path, string:len(Chroot) + 1)
    end.

-spec pack_str(iodata()) -> binary().
pack_str(Str) ->
    Length = iolist_size(Str),
    if Length =:= 0 -> <<-1:32/signed>>;
       Length >   0 -> <<Length:32, (iolist_to_binary(Str))/binary>>
    end.

-spec pack_bytes(iodata()) -> binary().
pack_bytes(Bytes) ->
    Length = iolist_size(Bytes),
    if Length =:= 0 -> <<-1:32/signed>>;
       Length >   0 -> <<Length:32, (iolist_to_binary(Bytes))/binary>>
    end.

-spec pack_acl([erlzk:acl()]) -> binary().
pack_acl(Acl) ->
    pack_acl(Acl, <<>>, 0).

-spec pack_acl([erlzk:acl()] | [], binary(), non_neg_integer()) -> binary().
pack_acl([], Packet, Size) ->
    case Size of
        0 -> <<-1:32/signed>>;
        _ -> <<Size:32, Packet/binary>>
    end;
pack_acl([{Perms,Scheme,Id}|Left], Packet, Size) ->
    NewPacket = <<Packet/binary, (pack_perms(Perms)):32, (pack_str(Scheme))/binary, (pack_str(Id))/binary>>,
    pack_acl(Left, NewPacket, Size + 1).

-spec pack_create_mode(persistent | p | ephemeral | persistent_sequential | ephemeral_sequential | es) -> <<_:32>>.
pack_create_mode(CreateMode) ->
    Flags = case CreateMode of
        persistent -> 0;
        p -> 0;
        ephemeral  -> 1;
        e -> 1;
        persistent_sequential -> 2;
        ps -> 2;
        ephemeral_sequential  -> 3;
        es -> 3;
        _ -> 0
    end,
    <<Flags:32>>.

-spec pack_perms(atom()) -> non_neg_integer().
pack_perms(Perms) ->
    pack_perms(atom_to_list(Perms), 0).

-spec pack_perms(string(), non_neg_integer()) -> non_neg_integer().
pack_perms([], PermsValue) ->
    PermsValue;
pack_perms([Perm|Left], PermsValue) ->
    Value = case Perm of
        $r -> ?ZK_PERM_READ;
        $w -> ?ZK_PERM_WRITE;
        $c -> ?ZK_PERM_CREATE;
        $d -> ?ZK_PERM_DELETE;
        $a -> ?ZK_PERM_ADMIN;
        _ -> 0
    end,
    pack_perms(Left, (PermsValue bor Value)).

-spec pack_watches([iodata()]) -> binary().
pack_watches(Watches) ->
    pack_watches(Watches, <<>>, 0).

-spec pack_watches([iodata()], binary(), non_neg_integer()) -> binary().
pack_watches([], Packet, Size) ->
    case Size of
        0 -> <<0:32/signed>>;
        _ -> <<Size:32, Packet/binary>>
    end;
pack_watches([Watch|Left], Packet, Size) ->
    NewPacket = <<Packet/binary, (pack_str(Watch))/binary>>,
    pack_watches(Left, NewPacket, Size + 1).

-spec pack_ops([erlzk:op()], iodata()) -> binary().
pack_ops(Ops, Chroot) ->
    pack_ops(Ops, <<>>, Chroot).

-spec pack_ops([erlzk:op()], binary(), iodata()) -> binary().
pack_ops([], Packet, _Chroot) ->
    <<Packet/binary, (pack_multi_header(-1, true))/binary>>;
pack_ops([{create, Path, Data, Acl, CreateMode}|Left], Packet, Chroot) ->
    MultiHeaderPacket = pack_multi_header(?ZK_OP_CREATE, false),
    OpPacket = <<(pack_str(chroot(Path, Chroot)))/binary, (pack_bytes(Data))/binary, (pack_acl(Acl))/binary, (pack_create_mode(CreateMode))/binary>>,
    NewPacket = <<Packet/binary, MultiHeaderPacket/binary, OpPacket/binary>>,
    pack_ops(Left, NewPacket, Chroot);
pack_ops([{delete, Path, Version}|Left], Packet, Chroot) ->
    MultiHeaderPacket = pack_multi_header(?ZK_OP_DELETE, false),
    OpPacket = <<(pack_str(chroot(Path, Chroot)))/binary, Version:32/signed>>,
    NewPacket = <<Packet/binary, MultiHeaderPacket/binary, OpPacket/binary>>,
    pack_ops(Left, NewPacket, Chroot);
pack_ops([{set_data, Path, Data, Version}|Left], Packet, Chroot) ->
    MultiHeaderPacket = pack_multi_header(?ZK_OP_SET_DATA, false),
    OpPacket = <<(pack_str(chroot(Path, Chroot)))/binary, (pack_bytes(Data))/binary, Version:32/signed>>,
    NewPacket = <<Packet/binary, MultiHeaderPacket/binary, OpPacket/binary>>,
    pack_ops(Left, NewPacket, Chroot);
pack_ops([{check, Path, Version}|Left], Packet, Chroot) ->
    MultiHeaderPacket = pack_multi_header(?ZK_OP_CHECK, false),
    OpPacket = <<(pack_str(chroot(Path, Chroot)))/binary, Version:32/signed>>,
    NewPacket = <<Packet/binary, MultiHeaderPacket/binary, OpPacket/binary>>,
    pack_ops(Left, NewPacket, Chroot).

-spec pack_multi_header(int32(), boolean()) -> binary().
pack_multi_header(Type, true) ->
    <<Type:32/signed, 1:8, -1:32/signed>>;
pack_multi_header(Type, false) ->
    <<Type:32/signed, 0:8, -1:32/signed>>.

-spec wrap_packet(uint32(), int32(), binary()) -> binary().
wrap_packet(Type, Xid, Packet) ->
    <<Xid:32/signed, Type:32, Packet/binary>>.

-spec unpack_str(binary()) -> {string(), binary()}.
unpack_str(Packet) ->
    <<Length:32/signed, Left/binary>> = Packet,
    if Length =< 0  ->
        {"", Left};
       Length >  0  ->
        {Str, LeftData} = split_binary(Left, Length),
        {binary_to_list(Str), LeftData}
    end.

-spec unpack_strs(binary()) -> {[string()], binary()}.
unpack_strs(Packet) ->
    <<Size:32/signed, Left/binary>> = Packet,
    unpack_strs(Left, [], Size).

unpack_strs(Packet, Strs, Size) when Size =< 0 ->
    {Strs, Packet};
unpack_strs(Packet, Strs, Size) ->
    {Str, Left} = unpack_str(Packet),
    unpack_strs(Left, [Str|Strs], Size - 1).

-spec unpack_bytes(binary()) -> {binary(), binary()}.
unpack_bytes(Packet) ->
    <<Length:32/signed, Left/binary>> = Packet,
    if Length =< 0  ->
        {<<>>, Left};
       Length >  0  ->
        split_binary(Left, Length)
    end.

-spec unpack_acl(<<_:32, _:_*8>>) -> {erlzk:acl(), binary()}.
unpack_acl(Packet) ->
    <<Size:32, Left/binary>> = Packet,
    unpack_acl([], Left, Size).

unpack_acl(Acl, Packet, 0) ->
    {Acl, Packet};
unpack_acl(Acl, Packet, Size) ->
    <<PermsPacket:32, Left/binary>> = Packet,
    Perms = unpack_perms(PermsPacket),
    {Scheme, Left0} = unpack_str(Left),
    {Id,     Left1} = unpack_str(Left0),
    unpack_acl([{Perms,Scheme,Id}|Acl], Left1, Size - 1).

-spec unpack_perms(non_neg_integer()) -> atom().
unpack_perms(PermsValue) ->
    unpack_perms(PermsValue, [?ZK_PERM_READ,"r",?ZK_PERM_WRITE,"w",?ZK_PERM_CREATE,"c",?ZK_PERM_DELETE,"d",?ZK_PERM_ADMIN,"r"], "").

unpack_perms(_PermsValue, [], Perms) ->
    list_to_atom(Perms);
unpack_perms(PermsValue, [V,P|Left], Perms) ->
    NewPerms = if (PermsValue band V) =:= V ->
            Perms ++ P;
        true ->
            Perms
    end,
    unpack_perms(PermsValue, Left, NewPerms).

-spec unpack_stat(<<_:64, _:_*8>>) -> {#stat{}, binary()}.
unpack_stat(Packet) ->
    <<Czxid:64, Mzxid:64, Ctime:64, Mtime:64, Version:32, Cversion:32, Aversion:32, EphemeralOwner:64, DataLength:32, NumChildren:32, Pzxid:64, Left/binary>> = Packet,
    Stat = #stat{czxid = Czxid,
        mzxid = Mzxid,
        ctime = Ctime,
        mtime = Mtime,
        version = Version,
        cversion = Cversion,
        aversion = Aversion,
        ephemeral_owner = EphemeralOwner,
        data_length = DataLength,
        num_children = NumChildren,
        pzxid = Pzxid},
    {Stat, Left}.

-spec unpack_ops(binary(), iodata()) -> {zk_code(), [erlzk:op_result()]}.
unpack_ops(Packet, Chroot) ->
    {Code, Ops} = unpack_ops(ok, [], Packet, Chroot),
    {Code, lists:reverse(Ops)}.

unpack_ops(?ZK_OP_CREATE, Packet, Chroot) ->
    {Path, Left} = unpack_str(Packet),
    {{create, unchroot(Path, Chroot)}, Left};
unpack_ops(?ZK_OP_DELETE, Packet, _Chroot) ->
    {{delete}, Packet};
unpack_ops(?ZK_OP_SET_DATA, Packet, _Chroot) ->
    {Stat, Left} = unpack_stat(Packet),
    {{set_data, Stat}, Left};
unpack_ops(?ZK_OP_CHECK, Packet, _Chroot) ->
    {{check}, Packet};
unpack_ops(?ZK_OP_ERROR, Packet, _Chroot) ->
    <<Err:32/signed, Left/binary>> = Packet,
    {{error, code_to_atom(Err)}, Left}.

unpack_ops(Code, Ops, Packet, Chroot) ->
    <<Type:32/signed, Done:8, Err:32/signed, Left/binary>> = Packet,
    if Done =:= 0 ->
        {Op, NewPacket} = unpack_ops(Type, Left, Chroot),
        unpack_ops(multi_code(Code, code_to_atom(Err)), [Op|Ops], NewPacket, Chroot);
       true ->
        {Code, Ops}
    end.

multi_code(Code, ErrCode) ->
    if Code =:= ok ->
        ErrCode;
       Code =/= ok ->
        Code
    end.

-type zk_event_type() :: node_created | node_deleted | node_data_changed | node_children_changed.

-spec event_type_to_atom(1 | 2 | 3 | 4) -> zk_event_type().
event_type_to_atom(Type) ->
    case Type of
        ?ZK_EVENT_TYPE_NODE_CREATED -> node_created;
        ?ZK_EVENT_TYPE_NODE_DELETED -> node_deleted;
        ?ZK_EVENT_TYPE_NODE_DATA_CHANGED -> node_data_changed;
        ?ZK_EVENT_TYPE_NODE_CHILDREN_CHANGED -> node_children_changed
    end.

-type zk_code() ::
        ok |
        system_error |
        runtime_inconsistency |
        data_inconsistency |
        connection_loss |
        marshalling_error |
        unimplemented |
        operation_timeout |
        bad_arguments |
        unknown_session |
        api_error |
        no_node |
        no_auth |
        bad_version |
        no_children_for_ephemerals |
        node_exists |
        not_empty |
        session_expired |
        invalid_callback |
        invalid_acl |
        auth_failed |
        session_moved |
        not_read_only |
        new_config_no_quorum |
        reconfig_in_progress |
        ephemeral_on_local_session.

-spec code_to_atom(int32()) -> zk_code().
code_to_atom(Code) ->
    case Code of
        ?ZK_CODE_OK -> ok;
        ?ZK_CODE_SYSTEM_ERROR -> system_error;
        ?ZK_CODE_RUNTIME_INCONSISTENCY -> runtime_inconsistency;
        ?ZK_CODE_DATA_INCONSISTENCY -> data_inconsistency;
        ?ZK_CODE_CONNECTION_LOSS -> connection_loss;
        ?ZK_CODE_MARSHALLING_ERROR -> marshalling_error;
        ?ZK_CODE_UNIMPLEMENTED -> unimplemented;
        ?ZK_CODE_OPERATION_TIMEOUT -> operation_timeout;
        ?ZK_CODE_BAD_ARGUMENTS -> bad_arguments;
        ?ZK_CODE_UNKNOWN_SESSION -> unknown_session;
        ?ZK_CODE_API_ERROR -> api_error;
        ?ZK_CODE_NO_NODE -> no_node;
        ?ZK_CODE_NO_AUTH -> no_auth;
        ?ZK_CODE_BAD_VERSION -> bad_version;
        ?ZK_CODE_NO_CHILDREN_FOR_EPHEMERALS -> no_children_for_ephemerals;
        ?ZK_CODE_NODE_EXISTS -> node_exists;
        ?ZK_CODE_NOT_EMPTY -> not_empty;
        ?ZK_CODE_SESSION_EXPIRED -> session_expired;
        ?ZK_CODE_INVALID_CALLBACK -> invalid_callback;
        ?ZK_CODE_INVALID_ACL -> invalid_acl;
        ?ZK_CODE_AUTH_FAILED -> auth_failed;
        ?ZK_CODE_SESSION_MOVED -> session_moved;
        ?ZK_CODE_NOT_READ_ONLY -> not_read_only;
        ?ZK_CODE_NEW_CONFIG_NO_QUORUM -> new_config_no_quorum;
        ?ZK_CODE_RECONFIG_IN_PROGRESS -> reconfig_in_progress;
        ?ZK_CODE_EPHEMERAL_ON_LOCAL_SESSION -> ephemeral_on_local_session
    end.
