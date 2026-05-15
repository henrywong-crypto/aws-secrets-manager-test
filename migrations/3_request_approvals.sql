do $$ begin
    create type approval_decision as enum ('APPROVED', 'REJECTED');
exception when duplicate_object then null;
end $$;

do $$ begin
    create type approval_level as enum ('L1', 'L2');
exception when duplicate_object then null;
end $$;

create table if not exists request_approvals (
    approval_id       uuid              primary key default uuid_generate_v4(),
    secret_request_id uuid              not null references secret_requests(secret_request_id),
    level             approval_level    not null,
    decision          approval_decision not null,
    approver_user_id  uuid              not null references users(user_id),
    approver_group    text              not null,
    note              text,
    created_at        timestamptz       not null default now(),

    unique (secret_request_id, level)
);

create index if not exists idx_ra_request  on request_approvals (secret_request_id);
create index if not exists idx_ra_approver on request_approvals (approver_user_id);
