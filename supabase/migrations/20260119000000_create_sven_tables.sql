-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create SVEN training table
CREATE TABLE IF NOT EXISTS public.sven_training (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    file_name text NOT NULL,
    function_code text NOT NULL,
    function_embedding vector(384),
    cwe text,
    cwe_title text,
    cwe_description text,
    is_vulnerable boolean NOT NULL
);

-- Create SVEN test table
CREATE TABLE IF NOT EXISTS public.sven_test (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    file_name text NOT NULL,
    function_code text NOT NULL,
    function_embedding vector(384),
    cwe text,
    cwe_title text,
    cwe_description text,
    is_vulnerable boolean NOT NULL
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS sven_training_file_name_idx ON public.sven_training(file_name);
CREATE INDEX IF NOT EXISTS sven_training_cwe_idx ON public.sven_training(cwe);
CREATE INDEX IF NOT EXISTS sven_training_is_vulnerable_idx ON public.sven_training(is_vulnerable);

CREATE INDEX IF NOT EXISTS sven_test_file_name_idx ON public.sven_test(file_name);
CREATE INDEX IF NOT EXISTS sven_test_cwe_idx ON public.sven_test(cwe);
CREATE INDEX IF NOT EXISTS sven_test_is_vulnerable_idx ON public.sven_test(is_vulnerable);

-- Create HNSW indexes for vector similarity search
CREATE INDEX IF NOT EXISTS sven_training_embedding_idx ON public.sven_training 
USING hnsw (function_embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS sven_test_embedding_idx ON public.sven_test 
USING hnsw (function_embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- Create SVEN results table
CREATE TABLE IF NOT EXISTS public.sven_results_c2v (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    file_name text NOT NULL,
    function_code text NOT NULL,
    actual_cwe text,
    actually_vulnerable boolean NOT NULL,
    assigned_cwes text[],
    found_vulnerable boolean NOT NULL,
    motivation text,
    relevant_documents uuid[]
);

CREATE INDEX IF NOT EXISTS sven_results_c2v_file_name_idx ON public.sven_results_c2v(file_name);

-- RPC function to find results by code
CREATE OR REPLACE FUNCTION find_result_c2v_by_code(code_to_find text)
RETURNS SETOF sven_results_c2v AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM sven_results_c2v
    WHERE function_code = code_to_find
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- RPC function to clear results
CREATE OR REPLACE FUNCTION clear_results_c2v()
RETURNS void AS $$
BEGIN
    DELETE FROM sven_results_c2v;
END;
$$ LANGUAGE plpgsql;
