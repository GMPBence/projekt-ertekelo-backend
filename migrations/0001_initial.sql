CREATE TABLE users (
    id CHAR(36) NOT NULL PRIMARY KEY,
    email VARCHAR(254) NOT NULL,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(60) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY users_email_unique (email),
    UNIQUE KEY users_username_unique (username)
);

CREATE TABLE projects (
    id CHAR(36) NOT NULL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    authors VARCHAR(500) NOT NULL,
    description TEXT NULL,
    website_url VARCHAR(2048) NULL,
    created_by CHAR(36) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY projects_created_at_idx (created_at),
    CONSTRAINT projects_created_by_fk FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE evaluations (
    id CHAR(36) NOT NULL PRIMARY KEY,
    project_id CHAR(36) NOT NULL,
    user_id CHAR(36) NOT NULL,
    grade TINYINT UNSIGNED NULL,
    theme TINYINT UNSIGNED NULL,
    design TINYINT UNSIGNED NULL,
    animations TINYINT UNSIGNED NULL,
    javascript TINYINT UNSIGNED NULL,
    feedback TEXT NULL,
    published BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY evaluations_project_user_unique (project_id, user_id),
    CONSTRAINT evaluations_project_fk FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    CONSTRAINT evaluations_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE recovery_tokens (
    user_id CHAR(36) NOT NULL PRIMARY KEY,
    token_hash CHAR(64) NOT NULL,
    attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    expires_at DATETIME(3) NOT NULL,
    CONSTRAINT recovery_tokens_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
