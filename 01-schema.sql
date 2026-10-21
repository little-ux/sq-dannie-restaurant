-- SQ开的餐厅 1.2.0. Run as the project database owner in Supabase SQL Editor.
-- This script owns only sq_* objects. It never grants browser users table access.
begin;
create schema if not exists sq_private;
revoke all on schema sq_private from public, anon, authenticated;

create table if not exists sq_private.admins (
 user_id uuid primary key references auth.users(id) on delete cascade,
 created_at timestamptz not null default now()
);
create table if not exists public.sq_players (
 user_id uuid primary key references auth.users(id) on delete cascade,
 display_name text not null check (length(display_name) between 1 and 24),
 banned boolean not null default false,
 ban_reason text not null default '',
 created_at timestamptz not null default now(),
 last_seen_at timestamptz not null default now()
);
create table if not exists public.sq_saves (
 user_id uuid primary key references public.sq_players(user_id) on delete cascade,
 revision bigint not null default 0 check (revision >= 0),
 save_raw text,
 summary jsonb not null default '{}'::jsonb,
 updated_at timestamptz,
 lease_owner uuid,
 lease_epoch bigint not null default 0,
 lease_until timestamptz,
 last_request_id uuid,
 last_request_hash text,
 check (save_raw is null or octet_length(save_raw) <= 8388608)
);
create table if not exists public.sq_reward_batches (
 id uuid primary key default gen_random_uuid(),
 actor_id uuid not null references auth.users(id),
 title text not null check (length(title) between 1 and 80),
 payload jsonb not null,
 created_at timestamptz not null default now()
);
create table if not exists public.sq_save_history (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.sq_players(user_id) on delete cascade,
 revision bigint not null,
 save_raw text not null,
 summary jsonb not null,
 created_at timestamptz not null default now(),
 unique(user_id,revision)
);
create table if not exists public.sq_rewards (
 id uuid primary key default gen_random_uuid(),
 batch_id uuid not null references public.sq_reward_batches(id),
 user_id uuid not null references public.sq_players(user_id) on delete cascade,
 claimed_at timestamptz,
 claimed_revision bigint,
 created_at timestamptz not null default now(),
 unique (batch_id, user_id)
);
create index if not exists sq_rewards_pending on public.sq_rewards(user_id,created_at) where claimed_at is null;
create table if not exists sq_private.requests (
 user_id uuid not null references auth.users(id) on delete cascade,
 request_id uuid not null,
 operation text not null,
 body_hash text not null,
 result jsonb not null,
 created_at timestamptz not null default now(),
 primary key (user_id, request_id)
);
create table if not exists sq_private.audit (
 id uuid primary key default gen_random_uuid(),
 actor_id uuid not null,
 target_id uuid,
 action text not null,
 detail jsonb not null,
 created_at timestamptz not null default now()
);
alter table public.sq_players enable row level security;
alter table public.sq_saves enable row level security;
alter table public.sq_reward_batches enable row level security;
alter table public.sq_rewards enable row level security;
alter table public.sq_save_history enable row level security;
alter table sq_private.admins enable row level security;
alter table sq_private.requests enable row level security;
alter table sq_private.audit enable row level security;
revoke all on public.sq_players, public.sq_saves, public.sq_reward_batches, public.sq_rewards from public,anon,authenticated;
revoke all on public.sq_save_history from public,anon,authenticated;
revoke all on sq_private.admins,sq_private.requests,sq_private.audit from public,anon,authenticated;

create or replace function sq_private.actor() returns uuid
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid := auth.uid(); p public.sq_players;
begin
 if u is null then raise exception 'AUTH_REQUIRED' using errcode='42501'; end if;
 select * into p from public.sq_players where user_id=u for update;
 if not found then raise exception 'BOOTSTRAP_REQUIRED' using errcode='42501'; end if;
 if p.banned then raise exception 'ACCOUNT_BANNED' using errcode='42501', detail=p.ban_reason; end if;
 return u;
end $$;
create or replace function sq_private.admin_actor() returns uuid
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid := sq_private.actor();
begin
 if not exists(select 1 from sq_private.admins where user_id=u) then raise exception 'ADMIN_REQUIRED' using errcode='42501'; end if;
 return u;
end $$;
create or replace function sq_private.digest(value text) returns text
language sql immutable set search_path=pg_catalog as $$select encode(sha256(convert_to(value,'UTF8')),'hex')$$;
create or replace function sq_private.int_ok(v jsonb,lo numeric,hi numeric) returns boolean
language sql immutable set search_path=pg_catalog as $$
 select coalesce(jsonb_typeof(v)='number' and (v::text)::numeric between lo and hi and trunc((v::text)::numeric)=(v::text)::numeric,false)
$$;
create or replace function sq_private.validate_save(raw text) returns jsonb
language plpgsql set search_path=pg_catalog as $$
declare p jsonb; d jsonb; g jsonb; f jsonb; k text; seen integer[] := '{}';
begin
 if raw is null or octet_length(raw)>8388608 then raise exception 'SAVE_SIZE_INVALID'; end if;
 begin p:=raw::jsonb; exception when others then raise exception 'SAVE_JSON_INVALID'; end;
 d:=p->'state';
 if p->>'game' is distinct from 'dncf-hard-campaign' or p->>'schemaVersion' is distinct from '8'
 or jsonb_typeof(d) is distinct from 'object' or p->'integrity'->>'algorithm' is distinct from 'fnv1a32-v1'
 or not coalesce(p->>'profileId' ~ '^[a-zA-Z0-9_-]{8,80}$',false)
 or not sq_private.int_ok(p->'revision',0,9007199254740991) then raise exception 'SAVE_FORMAT_INVALID'; end if;
 if not sq_private.int_ok(d->'gold',0,9007199254740991) or not sq_private.int_ok(d->'totalGold',0,9007199254740991)
 or not sq_private.int_ok(d->'surpriseStaminaReserve',0,9007199254740991) or not sq_private.int_ok(d->'cLv',1,200)
 or not sq_private.int_ok(d->'cExp',0,9007199254740991) or not sq_private.int_ok(d->'gridSize',14,72)
 or not sq_private.int_ok(d->'tempAdd',0,24) or not sq_private.int_ok(d->'maxStamina',120,510)
 or not sq_private.int_ok(d->'stamina',0,(d->>'maxStamina')::numeric)
 or jsonb_typeof(d->'grid') is distinct from 'array' or jsonb_typeof(d->'gens') is distinct from 'array'
 or jsonb_array_length(d->'gens')<>12 or jsonb_typeof(d->'inv') is distinct from 'object'
 or jsonb_typeof(d->'regularRoster') is distinct from 'object' or jsonb_typeof(d->'life') is distinct from 'object'
 or jsonb_typeof(d->'restaurant') is distinct from 'object' then raise exception 'SAVE_STATE_INVALID'; end if;
 if jsonb_array_length(d->'grid') <> (d->>'gridSize')::integer+(d->>'tempAdd')::integer then raise exception 'SAVE_GRID_INVALID'; end if;
 foreach k in array array['speed','bomb','tempSlot','mergeAll','infinite'] loop
  if not sq_private.int_ok(d->'inv'->k,0,9007199254740991) then raise exception 'SAVE_INVENTORY_INVALID'; end if;
 end loop;
 for g in select value from jsonb_array_elements(d->'gens') loop
  if not sq_private.int_ok(g->'itemId',1,12) or not sq_private.int_ok(g->'lv',1,12) then raise exception 'SAVE_GENERATOR_INVALID'; end if;
  if (g->>'itemId')::integer=any(seen) then raise exception 'SAVE_GENERATOR_INVALID'; end if;
  seen:=array_append(seen,(g->>'itemId')::integer);
 end loop;
 for f in select value from jsonb_array_elements(d->'grid') loop
  if f<>'null'::jsonb and (jsonb_typeof(f) is distinct from 'object' or not sq_private.int_ok(f->'itemId',1,999) or not sq_private.int_ok(f->'level',1,12)) then raise exception 'SAVE_FOOD_INVALID'; end if;
 end loop;
 return jsonb_build_object('level',d->'cLv','gold',d->'gold','stamina',d->'stamina','staminaCap',d->'maxStamina',
  'gridSize',d->'gridSize','deliver',d->'stats'->'deliver','profileId',p->'profileId','gameVersion',p->'version');
end $$;
create or replace function sq_private.snapshot(u uuid) returns jsonb
language sql stable security definer set search_path=pg_catalog as $$
 select jsonb_build_object('revision',s.revision,'raw',s.save_raw,'summary',s.summary,'updatedAt',s.updated_at,
  'epoch',s.lease_epoch,'leaseUntil',s.lease_until,'lastRequestId',s.last_request_id,'lastRequestHash',s.last_request_hash,
  'pendingCount',(select count(*) from public.sq_rewards where user_id=u and claimed_at is null))
 from public.sq_saves s where s.user_id=u
$$;
create or replace function sq_private.check_lease(s public.sq_saves,client_id uuid,epoch bigint) returns void
language plpgsql set search_path=pg_catalog as $$
begin
 if client_id is null or epoch is null or epoch<1 or s.lease_owner is distinct from client_id or s.lease_epoch<>epoch or s.lease_until is null or s.lease_until<=clock_timestamp()
 then raise exception 'SESSION_MOVED'; end if;
end $$;

create or replace function public.sq_bootstrap(p_display_name text default null) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=auth.uid(); p public.sq_players; name text;
begin
 if u is null then raise exception 'AUTH_REQUIRED' using errcode='42501'; end if;
 if p_display_name is null then select nullif(btrim(raw_user_meta_data->>'display_name'),'') into name from auth.users where id=u;
 else name:=nullif(btrim(p_display_name),''); end if;
 name:=left(coalesce(name,'餐厅店长'),24);
 insert into public.sq_players(user_id,display_name) values(u,name) on conflict(user_id) do nothing;
 perform sq_private.actor();
 insert into public.sq_saves(user_id) values(u) on conflict(user_id) do nothing;
 update public.sq_players set last_seen_at=now() where user_id=u returning * into p;
 return jsonb_build_object('apiVersion',1,'player',jsonb_build_object('id',u,'name',p.display_name,'createdAt',p.created_at),
  'admin',exists(select 1 from sq_private.admins where user_id=u),'cloud',sq_private.snapshot(u));
end $$;
create or replace function public.sq_open(p_client_id uuid,p_take_over boolean default false) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=sq_private.actor(); s public.sq_saves;
begin
 if p_client_id is null or p_take_over is null then raise exception 'CLIENT_REQUIRED'; end if;
 select * into s from public.sq_saves where user_id=u for update;
 if s.lease_owner is not null and s.lease_owner<>p_client_id and s.lease_until>clock_timestamp() and not p_take_over
 then return jsonb_build_object('busy',true,'summary',s.summary,'revision',s.revision,'leaseUntil',s.lease_until); end if;
 update public.sq_saves set lease_owner=p_client_id,
  lease_epoch=case when lease_owner=p_client_id and lease_until>clock_timestamp() then lease_epoch else lease_epoch+1 end,
  lease_until=clock_timestamp()+interval '45 seconds' where user_id=u;
 return sq_private.snapshot(u)||jsonb_build_object('busy',false);
end $$;
create or replace function public.sq_heartbeat(p_client_id uuid,p_epoch bigint) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=sq_private.actor(); s public.sq_saves;
begin
 select * into s from public.sq_saves where user_id=u for update;
 if p_client_id is null or p_epoch is null or p_epoch<1 or s.lease_owner is distinct from p_client_id or s.lease_epoch<>p_epoch then raise exception 'SESSION_MOVED'; end if;
 update public.sq_saves set lease_until=clock_timestamp()+interval '45 seconds' where user_id=u;
 update public.sq_players set last_seen_at=now() where user_id=u;
 return sq_private.snapshot(u)-'raw';
end $$;
create or replace function public.sq_release(p_client_id uuid,p_epoch bigint) returns void
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=auth.uid();
begin
 if u is null then return; end if;
 update public.sq_saves set lease_owner=null,lease_until=null,lease_epoch=lease_epoch+1
 where user_id=u and lease_owner=p_client_id and lease_epoch=p_epoch;
end $$;
create or replace function public.sq_commit(p_client_id uuid,p_epoch bigint,p_expected_revision bigint,p_request_id uuid,p_save_raw text,p_claim_id uuid default null) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=sq_private.actor(); s public.sq_saves; previous sq_private.requests; h text; v_summary jsonb;
 reward jsonb; old_state jsonb; new_state jsonb; k text; expected numeric; next_revision bigint;
begin
 if p_request_id is null then raise exception 'REQUEST_ID_REQUIRED'; end if;
 h:=sq_private.digest(p_save_raw||coalesce(p_claim_id::text,''));
 select * into s from public.sq_saves where user_id=u for update;
 perform sq_private.check_lease(s,p_client_id,p_epoch);
 select * into previous from sq_private.requests where user_id=u and request_id=p_request_id;
 if found then
  if previous.operation<>'commit' or previous.body_hash<>h then raise exception 'REQUEST_REUSED'; end if;
  return sq_private.snapshot(u)||jsonb_build_object('ackRevision',previous.result->'revision','requestId',p_request_id,'duplicate',true);
 end if;
 if p_expected_revision is null or p_expected_revision<0 or s.revision<>p_expected_revision then raise exception 'CLOUD_CONFLICT'; end if;
 v_summary:=sq_private.validate_save(p_save_raw);
 if p_claim_id is not null then
  select b.payload into reward from public.sq_rewards r join public.sq_reward_batches b on b.id=r.batch_id
  where r.id=p_claim_id and r.user_id=u and r.claimed_at is null for update of r;
  if not found or s.save_raw is null then raise exception 'REWARD_NOT_AVAILABLE'; end if;
  old_state:=(s.save_raw::jsonb)->'state'; new_state:=(p_save_raw::jsonb)->'state';
  if (old_state-array['gold','totalGold','inv','surpriseStaminaReserve']) is distinct from (new_state-array['gold','totalGold','inv','surpriseStaminaReserve']) then raise exception 'REWARD_STATE_CHANGED'; end if;
  if (new_state->>'gold')::numeric<>(old_state->>'gold')::numeric+(reward->>'gold')::numeric
  or (new_state->>'totalGold')::numeric<>(old_state->>'totalGold')::numeric+(reward->>'gold')::numeric
  or (new_state->>'surpriseStaminaReserve')::numeric<>(old_state->>'surpriseStaminaReserve')::numeric+(reward->>'stamina')::numeric
  then raise exception 'REWARD_AMOUNT_INVALID'; end if;
  foreach k in array array['speed','bomb','tempSlot','mergeAll','infinite'] loop
   expected:=(old_state->'inv'->>k)::numeric+(reward->'tools'->>k)::numeric;
   if (new_state->'inv'->>k)::numeric<>expected then raise exception 'REWARD_AMOUNT_INVALID'; end if;
  end loop;
  if ((new_state->'inv')-array['speed','bomb','tempSlot','mergeAll','infinite']) is distinct from ((old_state->'inv')-array['speed','bomb','tempSlot','mergeAll','infinite']) then raise exception 'REWARD_AMOUNT_INVALID'; end if;
 end if;
 next_revision:=s.revision+1;
 if s.save_raw is not null and (p_claim_id is not null or not exists(select 1 from public.sq_save_history where user_id=u and created_at>now()-interval '3 minutes')) then
  insert into public.sq_save_history(user_id,revision,save_raw,summary) values(u,s.revision,s.save_raw,s.summary) on conflict(user_id,revision) do nothing;
  delete from public.sq_save_history where user_id=u and id not in(select id from public.sq_save_history where user_id=u order by revision desc limit 5);
 end if;
 update public.sq_saves set revision=next_revision,save_raw=p_save_raw,summary=v_summary,updated_at=clock_timestamp(),
  lease_until=clock_timestamp()+interval '45 seconds',last_request_id=p_request_id,last_request_hash=h where user_id=u;
 if p_claim_id is not null then update public.sq_rewards set claimed_at=now(),claimed_revision=next_revision where id=p_claim_id; end if;
 insert into sq_private.requests(user_id,request_id,operation,body_hash,result) values(u,p_request_id,'commit',h,jsonb_build_object('revision',next_revision));
 return sq_private.snapshot(u)||jsonb_build_object('ackRevision',next_revision,'requestId',p_request_id,'duplicate',false);
end $$;
create or replace function public.sq_inbox() returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=sq_private.actor(); result jsonb;
begin
 select coalesce(jsonb_agg(t),'[]'::jsonb) into result from (
  select r.id,b.title,b.payload,r.created_at as "createdAt" from public.sq_rewards r join public.sq_reward_batches b on b.id=r.batch_id
  where r.user_id=u and r.claimed_at is null order by r.created_at,r.id limit 50
 )t;
 return jsonb_build_object('rewards',result,'count',(select count(*) from public.sq_rewards where user_id=u and claimed_at is null));
end $$;
create or replace function public.sq_rename(p_name text) returns void
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=sq_private.actor();
begin
 if p_name is null or length(btrim(p_name)) not between 1 and 24 then raise exception 'NAME_INVALID'; end if;
 update public.sq_players set display_name=btrim(p_name) where user_id=u;
end $$;
create or replace function public.sq_history(p_id uuid default null) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare u uuid:=sq_private.actor(); result jsonb;
begin
 if p_id is not null then
  select jsonb_build_object('id',id,'revision',revision,'raw',save_raw,'summary',summary,'createdAt',created_at) into result from public.sq_save_history where user_id=u and id=p_id;
  if result is null then raise exception 'BACKUP_NOT_FOUND'; end if;
 else
  select coalesce(jsonb_agg(t),'[]'::jsonb) into result from(select id,revision,summary,created_at as "createdAt" from public.sq_save_history where user_id=u order by revision desc limit 5)t;
 end if;
 return result;
end $$;

create or replace function public.sq_admin_list(p_search text default '',p_limit integer default 30,p_offset integer default 0) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare actor uuid:=sq_private.admin_actor(); result jsonb; total bigint; search text:=left(coalesce(p_search,''),80);
begin
 if p_limit is null or p_offset is null or p_limit not between 1 and 50 or p_offset not between 0 and 100000 then raise exception 'PAGE_INVALID'; end if;
 select count(*) into total from public.sq_players p join auth.users u on u.id=p.user_id where search='' or p.display_name ilike '%'||search||'%' or u.email ilike '%'||search||'%';
 select coalesce(jsonb_agg(t),'[]'::jsonb) into result from (
  select p.user_id as id,p.display_name as name,u.email,p.banned,p.ban_reason as "banReason",p.created_at as "createdAt",p.last_seen_at as "lastSeenAt",s.summary,s.revision,s.updated_at as "savedAt"
  from public.sq_players p join auth.users u on u.id=p.user_id left join public.sq_saves s on s.user_id=p.user_id
  where search='' or p.display_name ilike '%'||search||'%' or u.email ilike '%'||search||'%'
  order by p.created_at desc,p.user_id limit p_limit offset p_offset
 )t;
 return jsonb_build_object('players',result,'total',total,'offset',p_offset,'limit',p_limit);
end $$;
create or replace function public.sq_admin_player(p_user_id uuid) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare actor uuid:=sq_private.admin_actor(); result jsonb;
begin
 select jsonb_build_object('id',p.user_id,'name',p.display_name,'email',u.email,'banned',p.banned,'banReason',p.ban_reason,
  'lastSeenAt',p.last_seen_at,'cloud',sq_private.snapshot(p.user_id)) into result
 from public.sq_players p join auth.users u on u.id=p.user_id where p.user_id=p_user_id;
 if result is null then raise exception 'PLAYER_NOT_FOUND'; end if;
 insert into sq_private.audit(actor_id,target_id,action,detail) values(actor,p_user_id,'view_progress','{}');
 return result;
end $$;
create or replace function public.sq_admin_ban(p_user_id uuid,p_banned boolean,p_reason text,p_request_id uuid) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare actor uuid:=sq_private.admin_actor(); h text; previous sq_private.requests;
begin
 if p_user_id is null or p_banned is null or p_request_id is null or length(coalesce(p_reason,''))>200 then raise exception 'BAN_INPUT_INVALID'; end if;
 if p_banned and (p_user_id=actor or exists(select 1 from sq_private.admins where user_id=p_user_id)) then raise exception 'ADMIN_BAN_FORBIDDEN'; end if;
 h:=sq_private.digest(jsonb_build_array(p_user_id,p_banned,coalesce(p_reason,''))::text);
 -- Serialize admin mutations so retries with the same id cannot create extra audit rows.
 perform 1 from public.sq_players where user_id=actor for update;
 select * into previous from sq_private.requests where user_id=actor and request_id=p_request_id;
 if found then
  if previous.operation<>'ban' or previous.body_hash<>h then raise exception 'REQUEST_REUSED'; end if;
  return previous.result;
 end if;
 update public.sq_players set banned=p_banned,ban_reason=case when p_banned then coalesce(p_reason,'') else '' end where user_id=p_user_id;
 if not found then raise exception 'PLAYER_NOT_FOUND'; end if;
 if p_banned then update public.sq_saves set lease_owner=null,lease_until=null,lease_epoch=lease_epoch+1 where user_id=p_user_id; end if;
 insert into sq_private.audit(actor_id,target_id,action,detail) values(actor,p_user_id,case when p_banned then 'ban' else 'unban' end,jsonb_build_object('reason',coalesce(p_reason,'')));
 insert into sq_private.requests(user_id,request_id,operation,body_hash,result) values(actor,p_request_id,'ban',h,jsonb_build_object('ok',true));
 return jsonb_build_object('ok',true);
end $$;
create or replace function public.sq_admin_grant(p_request_id uuid,p_target_id uuid,p_title text,p_gold integer,p_stamina integer,p_tools jsonb) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare actor uuid:=sq_private.admin_actor(); tools jsonb:='{}'; payload jsonb; h text; previous sq_private.requests; k text; qty integer; batch uuid; count_players integer; result jsonb;
begin
 if p_request_id is null or length(btrim(coalesce(p_title,''))) not between 1 and 80 or p_gold is null or p_gold not between 0 and 1000000
 or p_stamina is null or p_stamina not between 0 and 500 or jsonb_typeof(p_tools) is distinct from 'object'
 or exists(select 1 from jsonb_object_keys(p_tools) as tool_keys(name) where tool_keys.name<>all(array['speed','bomb','tempSlot','mergeAll','infinite'])) then raise exception 'GRANT_INPUT_INVALID'; end if;
 foreach k in array array['speed','bomb','tempSlot','mergeAll','infinite'] loop
  if not sq_private.int_ok(coalesce(p_tools->k,'0'::jsonb),0,100) then raise exception 'GRANT_INPUT_INVALID'; end if;
  qty:=coalesce(p_tools->>k,'0')::integer;tools:=tools||jsonb_build_object(k,qty);
 end loop;
 if p_gold=0 and p_stamina=0 and not exists(select 1 from jsonb_each_text(tools) where value::integer>0) then raise exception 'EMPTY_GRANT'; end if;
 payload:=jsonb_build_object('gold',p_gold,'stamina',p_stamina,'tools',tools);
 h:=sq_private.digest(jsonb_build_array(p_target_id,btrim(p_title),payload)::text);
 perform 1 from public.sq_players where user_id=actor for update;
 select * into previous from sq_private.requests where user_id=actor and request_id=p_request_id;
 if found then
  if previous.operation<>'grant' or previous.body_hash<>h then raise exception 'REQUEST_REUSED'; end if;
  return previous.result;
 end if;
 if p_target_id is not null and not exists(select 1 from public.sq_players where user_id=p_target_id) then raise exception 'PLAYER_NOT_FOUND'; end if;
 insert into public.sq_reward_batches(actor_id,title,payload) values(actor,btrim(p_title),payload) returning id into batch;
 insert into public.sq_rewards(batch_id,user_id) select batch,user_id from public.sq_players where p_target_id is null or user_id=p_target_id;
 get diagnostics count_players=row_count;
 result:=jsonb_build_object('batchId',batch,'recipients',count_players);
 insert into sq_private.audit(actor_id,target_id,action,detail) values(actor,p_target_id,'grant',jsonb_build_object('batchId',batch,'recipients',count_players,'title',btrim(p_title),'payload',payload));
 insert into sq_private.requests(user_id,request_id,operation,body_hash,result) values(actor,p_request_id,'grant',h,result);
 return result;
end $$;
create or replace function public.sq_admin_audit(p_limit integer default 50) returns jsonb
language plpgsql security definer set search_path=pg_catalog as $$
declare actor uuid:=sq_private.admin_actor(); result jsonb;
begin
 if p_limit is null or p_limit not between 1 and 100 then raise exception 'PAGE_INVALID'; end if;
 select coalesce(jsonb_agg(t),'[]'::jsonb) into result from (
  select a.id,a.actor_id as "actorId",a.target_id as "targetId",a.action,a.detail,a.created_at as "createdAt"
  from sq_private.audit a order by a.created_at desc,a.id limit p_limit
 )t;
 return result;
end $$;

-- PostgreSQL grants function EXECUTE to PUBLIC by default; remove that explicitly.
revoke all on all functions in schema sq_private from public,anon,authenticated;
revoke all on function public.sq_bootstrap(text),public.sq_open(uuid,boolean),public.sq_heartbeat(uuid,bigint),public.sq_release(uuid,bigint),
 public.sq_commit(uuid,bigint,bigint,uuid,text,uuid),public.sq_inbox(),public.sq_rename(text),public.sq_history(uuid),
 public.sq_admin_list(text,integer,integer),public.sq_admin_player(uuid),public.sq_admin_ban(uuid,boolean,text,uuid),
 public.sq_admin_grant(uuid,uuid,text,integer,integer,jsonb),public.sq_admin_audit(integer) from public,anon;
grant execute on function public.sq_bootstrap(text),public.sq_open(uuid,boolean),public.sq_heartbeat(uuid,bigint),public.sq_release(uuid,bigint),
 public.sq_commit(uuid,bigint,bigint,uuid,text,uuid),public.sq_inbox(),public.sq_rename(text),public.sq_history(uuid),
 public.sq_admin_list(text,integer,integer),public.sq_admin_player(uuid),public.sq_admin_ban(uuid,boolean,text,uuid),
 public.sq_admin_grant(uuid,uuid,text,integer,integer,jsonb),public.sq_admin_audit(integer) to authenticated;
notify pgrst,'reload schema';
commit;
