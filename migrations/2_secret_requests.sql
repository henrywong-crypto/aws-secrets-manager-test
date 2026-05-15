create type secret_request_status as enum ('PENDING_L1', 'PENDING_L2', 'APPROVED', 'REJECTED');

create table if not exists secret_requests (
    secret_request_id uuid                  primary key default uuid_generate_v4(),
    secret_name       text                  not null,
    encrypted_value   text                  not null,
    requester_user_id uuid                  not null references users(user_id),
    reason            text                  not null,
    status            secret_request_status not null default 'PENDING_L1',
    created_at        timestamptz           not null default now(),
    resolved_at       timestamptz,

    check ((status in ('PENDING_L1', 'PENDING_L2')) = (resolved_at is null))
);

create index if not exists idx_sr_status            on secret_requests (status);
create index if not exists idx_sr_requester_user_id on secret_requests (requester_user_id);
