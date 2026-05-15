create table if not exists approval_flows (
    flow_id              uuid        primary key default uuid_generate_v4(),
    flow_name            text        not null unique,
    description          text,
    l1_approver_group_id uuid        not null references groups(group_id) on delete restrict,
    l2_approver_group_id uuid        not null references groups(group_id) on delete restrict,
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now()
);
