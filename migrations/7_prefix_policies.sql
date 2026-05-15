create table if not exists prefix_policies (
    policy_id          uuid        primary key default uuid_generate_v4(),
    prefix             text        not null unique,
    aws_account_id     text        not null,
    aws_region         text        not null,
    requester_group_id uuid        not null references groups(group_id) on delete restrict,
    flow_id            uuid        not null references approval_flows(flow_id) on delete restrict,
    tags               text        not null default '{}',
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now()
);
