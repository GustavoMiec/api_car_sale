ALTER TABLE Comments ADD COLUMN user_id BIGINT;

ALTER TABLE Comments ADD CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES users(id);