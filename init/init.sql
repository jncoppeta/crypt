-- Enable the uuid-ossp extension
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'uuid-ossp') THEN
        CREATE EXTENSION "uuid-ossp";
        RAISE NOTICE 'uuid-ossp extension created';
    ELSE
        RAISE NOTICE 'uuid-ossp extension already exists';
    END IF;
END $$;

-- Create the 'users' table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Use UUID v4 for primary key
    username TEXT NOT NULL  -- ENCRYPTED, store encrypted text
);


-- Create the 'users' table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Use UUID v4 for primary key
    username TEXT NOT NULL  -- ENCRYPTED, store encrypted text
);

-- Create the 'tokens' table
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Use UUID v4 for primary key
    user_id UUID ,
    value TEXT  -- ENCRYPTED
);

-- Create the 'secrets' table
CREATE TABLE IF NOT EXISTS secrets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),  -- Use UUID v4 for primary key
    value TEXT,  -- ENCRYPTED
    user_id UUID,
    token_id UUID,
    name TEXT,  -- ENCRYPTED
    description TEXT  -- ENCRYPTED
);
