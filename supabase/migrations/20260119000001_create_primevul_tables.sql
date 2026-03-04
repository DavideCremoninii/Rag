-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create PrimeVul training table
CREATE TABLE IF NOT EXISTS public.primevul_training (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    file_name text NOT NULL,
    function_code text NOT NULL,
    function_embedding vector(384),
    cwe text,
    cwe_title text,
    cwe_description text,
    is_vulnerable boolean NOT NULL
);

-- Create PrimeVul test table
CREATE TABLE IF NOT EXISTS public.primevul_test (
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
CREATE INDEX IF NOT EXISTS primevul_training_file_name_idx ON public.primevul_training(file_name);
CREATE INDEX IF NOT EXISTS primevul_training_cwe_idx ON public.primevul_training(cwe);
CREATE INDEX IF NOT EXISTS primevul_training_is_vulnerable_idx ON public.primevul_training(is_vulnerable);

CREATE INDEX IF NOT EXISTS primevul_test_file_name_idx ON public.primevul_test(file_name);
CREATE INDEX IF NOT EXISTS primevul_test_cwe_idx ON public.primevul_test(cwe);
CREATE INDEX IF NOT EXISTS primevul_test_is_vulnerable_idx ON public.primevul_test(is_vulnerable);

-- Create HNSW indexes for vector similarity search
CREATE INDEX IF NOT EXISTS primevul_training_embedding_idx ON public.primevul_training 
USING hnsw (function_embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS primevul_test_embedding_idx ON public.primevul_test 
USING hnsw (function_embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- Create PrimeVul results table
CREATE TABLE IF NOT EXISTS public.primevul_results_c2v (
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

CREATE INDEX IF NOT EXISTS primevul_results_c2v_file_name_idx ON public.primevul_results_c2v(file_name);

-- RPC function to find results by code
CREATE OR REPLACE FUNCTION find_primevul_result_c2v_by_code(code_to_find text)
RETURNS SETOF primevul_results_c2v AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM primevul_results_c2v
    WHERE function_code = code_to_find
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- RPC function to clear results
CREATE OR REPLACE FUNCTION clear_primevul_results_c2v()
RETURNS void AS $$
BEGIN
    DELETE FROM primevul_results_c2v;
END;
$$ LANGUAGE plpgsql;
