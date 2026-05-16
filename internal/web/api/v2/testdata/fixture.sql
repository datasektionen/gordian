-- Cost centres: top-level groupings (committees, projects, etc.)
INSERT INTO cost_centres (id, name, type, created_at, updated_at) VALUES
    (1, 'Styrelsen',           'committee', '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (2, 'Näringslivsgruppen',  'committee', '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (3, 'Mottagningen',        'project',   '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (4, 'Datasektionen.se',    'projectX',  '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (5, 'Övrigt',              'other',     '2025-01-01 09:00:00', '2025-01-01 09:00:00');

-- Secondary cost centres: sub-groupings under a cost centre
INSERT INTO secondary_cost_centres (id, name, cost_centre_id, created_at, updated_at) VALUES
    (10, 'Representation',     1, '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (11, 'Kontorsmaterial',    1, '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (20, 'Sponsring',          2, '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (21, 'Event',              2, '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (30, 'Nølle-pyjamas',      3, '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (31, 'Sittningar',         3, '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (40, 'Drift',              4, '2025-01-01 09:00:00', '2025-01-01 09:00:00');

-- Budget lines: individual income/expense entries
INSERT INTO budget_lines (id, name, income, expense, comment, account, secondary_cost_centre_id, created_at, updated_at) VALUES
    (100, 'Styrelsemiddag',         0,    8000, 'Höstterminen',        '5811', 10, '2025-01-15 10:00:00', '2025-01-15 10:00:00'),
    (101, 'Pennor och block',       0,    1200, NULL,                  '6110', 11, '2025-01-15 10:00:00', '2025-01-15 10:00:00'),
    (102, 'Företagsbidrag',     50000,       0, 'Huvudsponsor',        '3010', 20, '2025-02-01 10:00:00', '2025-02-01 10:00:00'),
    (103, 'Företagskväll',       2000,   15000, NULL,                  '5810', 21, '2025-02-10 10:00:00', '2025-02-10 10:00:00'),
    (104, 'Pyjamastryck',           0,    9500, '120 st',              '6072', 30, '2025-03-01 10:00:00', '2025-03-01 10:00:00'),
    (105, 'Gasque',              5000,   12000, 'Bilj. + mat',         '3050', 31, '2025-03-15 10:00:00', '2025-03-15 10:00:00'),
    (106, 'Serverhyra',             0,    4800, 'Årsavgift',           '6540', 40, '2025-01-01 09:00:00', '2025-01-01 09:00:00'),
    (107, 'Domännamn',              0,     200, NULL,                  '6540', 40, '2025-01-01 09:00:00', '2025-01-01 09:00:00');

-- A sample budget file
INSERT INTO budget_files (id, filename, file, created_at) VALUES
    (1, 'budget-2025.json', '{"version":1,"lines":[]}', '2025-01-01 09:00:00');
