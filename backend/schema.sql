-- ==============================================================================
-- PHASE 1: THE DOMAIN MODEL (PostgreSQL / Supabase)
-- ==============================================================================

-- Enable UUIDs (Universally Unique Identifiers)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ------------------------------------------------------------------------------
-- TABLE 1: Websites (The core entity a user wants to track)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS websites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL, -- Links to the Supabase Authenticated User
    domain_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- TABLE 2: Scans (The "Ticket" for background workers)
-- ------------------------------------------------------------------------------
DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('pending', 'crawling', 'analyzing', 'completed', 'failed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    website_id UUID REFERENCES websites(id) ON DELETE CASCADE,
    status scan_status DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- ------------------------------------------------------------------------------
-- TABLE 3: Audit Results
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL,
    raw_data JSONB DEFAULT '{}'::jsonb, 
    ai_insights JSONB DEFAULT '{}'::jsonb, 
    category_score INTEGER CHECK (category_score >= 0 AND category_score <= 100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================================================================
-- PHASE 2: SECURITY (Row Level Security)
-- ==============================================================================
ALTER TABLE websites ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_results ENABLE ROW LEVEL SECURITY;

-- Create policy so users can only read their own websites
DO $$ BEGIN
    CREATE POLICY "Users can only view their own websites" 
    ON websites FOR SELECT 
    USING (auth.uid() = user_id);
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create policy so users can only insert websites for themselves
DO $$ BEGIN
    CREATE POLICY "Users can only insert their own websites" 
    ON websites FOR INSERT 
    WITH CHECK (auth.uid() = user_id);
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;
