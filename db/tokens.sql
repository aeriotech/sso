create table tokens
(
	client_id char(128) not null,
	user_id char(128) not null,
	access_token char(128) not null,
	access_token_expire bigint not null,
	refresh_token char(128) not null
);

comment on table tokens is 'Access and refresh tokens with expiration dates';

