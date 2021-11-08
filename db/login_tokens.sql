create table login_tokens
(
	user_id char(128) not null,
	series_id char(128) not null,
	token char(128) not null
);

comment on table login_tokens is 'User ids and tokens for remembering users';

