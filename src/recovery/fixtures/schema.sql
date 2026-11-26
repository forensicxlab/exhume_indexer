CREATE TABLE items (id TEXT PRIMARY KEY, json TEXT);
CREATE TABLE conversations (id TEXT PRIMARY KEY, json TEXT, type TEXT, serviceId TEXT);
CREATE TABLE messages (id TEXT UNIQUE, type TEXT, conversationId TEXT, json TEXT,
    body TEXT, sent_at INTEGER, readStatus INTEGER, sourceServiceId TEXT);
INSERT INTO items VALUES ('uuid_id', '{"value":"aaaaaaaa-0000-4000-8000-000000000001.2"}');
INSERT INTO conversations VALUES
    ('owner', '{"profileName":"Synthetic Owner"}', 'private', 'aaaaaaaa-0000-4000-8000-000000000001'),
    ('peer', '{"profileName":"Synthetic Peer"}', 'private', 'bbbbbbbb-0000-4000-8000-000000000002');
INSERT INTO messages VALUES
    ('m1','incoming','peer','{}','BEGIN SYNTHETIC SIGNAL RECOVERY',1700000000000,0,'bbbbbbbb-0000-4000-8000-000000000002'),
    ('m2','incoming','peer','{"attachments":[{"contentType":"image/png","path":"ab/photo","fileName":"synthetic.png","size":3}]}',NULL,1700000001000,0,'bbbbbbbb-0000-4000-8000-000000000002'),
    ('m3','incoming','peer','{"poll":{"question":"Synthetic poll?","options":["A","B"],"allowMultiple":false}}',NULL,1700000002000,0,'bbbbbbbb-0000-4000-8000-000000000002');
