CREATE TABLE budget_lines (
    id integer NOT NULL,
    name TEXT NOT NULL,
    income integer NOT NULL,
    expense integer NOT NULL,
	comment TEXT,
	account TEXT,
    secondary_cost_centre_id integer NOT NULL,
	created_at timestamp,
    updated_at timestamp
);

CREATE TABLE cost_centres (
    id integer NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
	created_at timestamp,
    updated_at timestamp,
    CONSTRAINT cost_centres_type_check CHECK (type = ANY (ARRAY['committee', 'project', 'projectX', 'partition', 'other']))
);

CREATE TABLE secondary_cost_centres (
    id integer NOT NULL,
    name TEXT NOT NULL,
    cost_centre_id integer NOT NULL,
    created_at timestamp,
    updated_at timestamp
);

CREATE TABLE budget_files (
    id integer NOT NULL,
    filename TEXT NOT NULL,
    file TEXT NOT NULL,
    created_at timestamp
);