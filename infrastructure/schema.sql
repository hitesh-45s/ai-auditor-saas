-- ==============================================================================
-- PHASE 1: THE DOMAIN MODEL (PostgreSQL / Supabase)
-- ==============================================================================

-- Enable UUIDs (Universally Unique Identifiers)
-- 1% Tip: Never use auto-incrementing integers (1, 2, 3) for IDs in a SaaS. 
-- Hackers can guess them (e.g., website.com/scan/4) and scrape your data. 
-- We use UUIDs (e.g., 550e8400-e29b-41d4-a716-446655440000).
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ------------------------------------------------------------------------------
-- TABLE 1: Websites (The core entity a user wants to track)
-- ------------------------------------------------------------------------------
CREATE TABLE websites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL, -- Links to the Supabase Authenticated User
    domain_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- TABLE 2: Scans (The "Ticket" for our background workers)
-- ------------------------------------------------------------------------------
-- 1% Tip: We use an ENUM (Enumerated Type) to lock down the status.
-- This prevents a bug where a developer accidentally types 'crawilng' instead of 'crawling'.
CREATE TYPE scan_status AS ENUM ('pending', 'crawling', 'analyzing', 'completed', 'failed');

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    website_id UUID REFERENCES websites(id) ON DELETE CASCADE,
    status scan_status DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- ------------------------------------------------------------------------------
-- TABLE 3: Audit Results (The Heavy Lifter)
-- ------------------------------------------------------------------------------
-- 1% Tip: THE JSONB SECRET WEAPON.
-- We do NOT create columns for `missing_alt_text`, `cls_score`, `ssl_valid`, etc.
-- That would require 500 columns. Instead, we use JSONB.
-- PostgreSQL stores this JSON efficiently, and allows us to query *inside* the JSON lightning fast.
CREATE TABLE audit_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL, -- e.g., 'seo', 'accessibility', 'performance', 'ui_modernization'
    
    -- Stores the raw tool output (Lighthouse, Axe-core, Wappalyzer)
    raw_data JSONB DEFAULT '{}'::jsonb, 
    
    -- Stores the OpenAI generated response (Problem, Impact, Code Generation)
    ai_insights JSONB DEFAULT '{}'::jsonb, 
    
    category_score INTEGER CHECK (category_score >= 0 AND category_score <= 100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==============================================================================
-- PHASE 2: SECURITY (Row Level Security)
-- ==============================================================================
-- 1% Tip: Never trust the Backend API to be completely secure. 
-- We tell the database itself: "Only let users see rows where their ID matches the row's user_id."
-- This means even if you write a buggy API endpoint, the DB will physically block data leaks.

ALTER TABLE websites ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_results ENABLE ROW LEVEL SECURITY;

-- Create policy so users can only read their own websites
CREATE POLICY "Users can only view their own websites" 
ON websites FOR SELECT 
USING (auth.uid() = user_id);

-- Create policy so users can only insert websites for themselves
CREATE POLICY "Users can only insert their own websites" 
ON websites FOR INSERT 
WITH CHECK (auth.uid() = user_id);