#!/usr/bin/env python3
"""
count_cwe_error_types_per_model_rows_from_filename_col.py

Per ogni modello nella directory base, conta quattro tipi di errori/hallucinations nelle predizioni CWE:

1) Entity-Error (Wrong Weakness ID) [UPDATED RULE]:
   - La predizione contiene SOLO CWE Weakness valide (presenti in <Weaknesses>)
   - La ground truth contiene almeno una CWE Weakness valida
   - NESSUNA CWE Weakness predetta coincide con la/e CWE Weakness di ground truth
     (cioè intersezione vuota tra predette e GT)
   NOTE: se la predizione include anche la CWE corretta (anche insieme ad altre CWE errate),
         NON è entity-error nel tuo setting.

2) Wrong-Level (Category/View):
   - La predizione contiene almeno una CWE ID valida MA NON di tipo Weakness (Category o View)

3) Invented CWE (Out-of-taxonomy):
   - La predizione contiene almeno una CWE ID che NON è presente in MITRE CWE taxonomy
     (né Weakness, né Category, né View)

4) Context Inconsistency (Out-of-scope per C/C++):
   - La predizione contiene almeno una CWE Weakness valida (in <Weaknesses>)
   - almeno una CWE Weakness predetta NON è nella allowlist C/C++ (Excel con CWE applicabili a C/C++)
   - NON Invented e NON Wrong-Level (per evitare overlap)
   - Soppressione: NON contare come context inconsistency se anche la ground truth contiene
     CWE Weakness out-of-scope (cioè non presenti nella allowlist C/C++)

Denominatore:
- Numero totale di righe non-NaN nella colonna "File Name" (aggregato su tutti i file analizzati per modello)

Output:
A) Un file Excel principale (output_xlsx) con:
   - Sheet "Summary" (ordinato secondo MODEL_ORDER) con conteggi e percentuali (0..100):
       EntityError_Rate, WrongLevel_Rate, Invented_Rate, ContextInconsistency_Rate
   - Un sheet per ciascun modello con dettaglio per file Excel analizzato

B) Una cartella (configurabile) con sottocartelle per modello e, dentro, un Excel per ciascuna categoria:
   <out-dir>/<ModelNameSanitized>/<Category>.xlsx

   Ogni Excel per categoria contiene le righe (FileName) dove la categoria è stata rilevata, con colonne:
     - FileName
     - Found CWE (valore raw della cella)
     - Actual CWE (valore raw della cella)
     - SourceExcelPath (path del file excel sorgente)
     - Dataset, PromptDir, ExcelFile, RowIndex (tracciabilità)

Usage:
  python count_cwe_error_types_per_model_rows_from_filename_col.py /path/to/Models output.xlsx \
    --c-cpp-allowlist-xlsx CWE_Weakness_C_Cpp_List.xlsx \
    --out-dir ./hallucination_outputs
"""

import re
import io
import zipfile
import sys
from pathlib import Path
from typing import Set, Dict, List, Tuple, Optional
import xml.etree.ElementTree as ET

import pandas as pd

try:
    import requests
except Exception:
    requests = None


# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
# NOTE: Some users might have the correct URL (xml.zip). If you get 404,
# change to: "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
# Keeping original behavior is risky; we set correct below.
CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

COL_PREDICTED_DEFAULT = "Found CWE"
COL_FILENAME_DEFAULT = "File Name"

GT_COL_CANDIDATES = [
    "Ground Truth CWE", "GroundTruth CWE", "GroundTruth", "Ground Truth",
    "GT CWE", "GT", "Actual CWE", "Label", "CWE", "CWE-ID", "CWE ID"
]

DATASETS = ["Sven", "PrimeVul", "DiverseVul"]
DEFAULT_PROMPT_COUNT = 3

MODEL_ORDER = [
    "Qwen2.5-7B-Instruct1M",
    "Qwen2.5-14B-Instruct1M",
    "Qwen2.5-32B-Instruct",
    "Qwen2.5-Coder-7B-Instruct",
    "Qwen2.5-Coder-14B-Instruct",
    "Qwen2.5-Coder-32B-Instruct",
    "CodeLlama-7B-Instruct",
    "CodeLlama-13B-Instruct",
    "CodeLlama-34B-Instruct",
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama3.1-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "DeepSeek-R1-Distill-Qwen-32B",
    "CodeAstra-7B",
    "Pongo-13B",
    "Gemini2.0-Flash",
    "Gemini2.5-Flash",
    "Gemma3-4B",
    "Gemma3-12B",
    "Gemma3-27B",
]

CATEGORIES = [
    "EntityError",
    "WrongLevel",
    "Invented",
    "ContextInconsistency",
]


# ---------------------------------------------------------------------
# MODEL ORDERING
# ---------------------------------------------------------------------
def sort_models_in_summary(df: pd.DataFrame, model_col: str = "Nome del Modello") -> pd.DataFrame:
    """
    Ordina df secondo MODEL_ORDER. I modelli non presenti finiscono in fondo (ordine alfabetico).
    """
    df = df.copy()

    in_order = df[df[model_col].isin(MODEL_ORDER)].copy()
    not_in_order = df[~df[model_col].isin(MODEL_ORDER)].copy()

    in_order["_order"] = in_order[model_col].apply(lambda x: MODEL_ORDER.index(x))
    in_order = in_order.sort_values("_order").drop(columns="_order")

    not_in_order = not_in_order.sort_values(model_col)
    return pd.concat([in_order, not_in_order], ignore_index=True)


# ---------------------------------------------------------------------
# NAME SANITIZERS
# ---------------------------------------------------------------------
INVALID_FS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1F]')


def sanitize_fs_name(name: str, max_len: int = 120) -> str:
    """
    Safe directory/file name (cross-platform).
    """
    name = INVALID_FS_CHARS.sub("_", str(name)).strip()
    name = re.sub(r"\s+", " ", name)
    if len(name) > max_len:
        name = name[:max_len].rstrip()
    return name or "Unnamed"


def sanitize_sheet_name(name: str, max_len: int = 31) -> str:
    cleaned = re.sub(r'[:\\\/\?\*\[\]]', '_', str(name)).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned or "Sheet"


def unique_sheet_name(writer: pd.ExcelWriter, desired: str) -> str:
    """
    Ensure sheet name is unique in workbook (<=31 chars).
    """
    desired = sanitize_sheet_name(desired, 31)
    if desired not in writer.book.sheetnames:
        return desired

    i = 1
    while True:
        suffix = f"_{i}"
        base = desired[: max(1, 31 - len(suffix))]
        cand = f"{base}{suffix}"
        if cand not in writer.book.sheetnames:
            return cand
        i += 1


# ---------------------------------------------------------------------
# CWE XML HELPERS
# ---------------------------------------------------------------------
def download_and_extract_cwe_xml(dest_path: Path) -> bool:
    if dest_path.is_file():
        print(f"  -> CWE XML già presente: {dest_path}")
        return True
    if not requests:
        print("ERRORE: 'requests' non installato. Installa con: pip install requests")
        return False

    print(f"Scarico CWE XML da {CWE_ZIP_URL} ...")
    try:
        r = requests.get(CWE_ZIP_URL, timeout=60)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            xml_name = next((n for n in z.namelist() if n.endswith(".xml")), None)
            if not xml_name:
                print("ERRORE: nessun file .xml trovato nell'archivio scaricato.")
                return False
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(xml_name) as src, open(dest_path, "wb") as tgt:
                tgt.write(src.read())
        print("  -> Download e estrazione completati.")
        return True
    except Exception as e:
        print(f"ERRORE durante il download/estrazione: {e}")
        return False


def _collect_ids(root, ns, container_name: str) -> Set[str]:
    out: Set[str] = set()
    container = root.find(f"cwe:{container_name}", ns)
    if container is None:
        return out
    for item in container:
        m = re.search(r"\d+", item.get("ID", ""))
        if m:
            out.add(str(int(m.group(0))))
    return out


def parse_cwe_sets_from_xml(xml_path: Path) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    """
    Ritorna:
      (weakness_ids, category_ids, view_ids, all_ids)
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns = {"cwe": "http://cwe.mitre.org/cwe-7"}

        weakness_ids = _collect_ids(root, ns, "Weaknesses")
        category_ids = _collect_ids(root, ns, "Categories")
        view_ids = _collect_ids(root, ns, "Views")
        all_ids = set().union(weakness_ids, category_ids, view_ids)
        return weakness_ids, category_ids, view_ids, all_ids
    except Exception as e:
        print(f"ERRORE parsing XML CWE: {e}")
        return set(), set(), set(), set()


# ---------------------------------------------------------------------
# C/C++ ALLOWLIST LOADER
# ---------------------------------------------------------------------
def load_c_cpp_allowlist_ids(xlsx_path: Path) -> Set[str]:
    """
    Carica la allowlist C/C++ (Excel) con colonna 'CWE-ID' contenente valori tipo 'CWE-79' o '79'.
    Ritorna set di ID numerici come stringhe (es. '79').
    """
    try:
        df = pd.read_excel(xlsx_path, engine="openpyxl")
    except Exception as e:
        raise RuntimeError(f"Impossibile leggere allowlist Excel '{xlsx_path}': {e}")

    if "CWE-ID" not in df.columns:
        raise RuntimeError(f"Allowlist '{xlsx_path}' non contiene la colonna 'CWE-ID'.")

    ids: Set[str] = set()
    for v in df["CWE-ID"].dropna().astype(str).tolist():
        m = re.search(r"(\d+)", v)
        if m:
            ids.add(str(int(m.group(1))))
    return ids


# ---------------------------------------------------------------------
# TEXT PARSING
# ---------------------------------------------------------------------
def extract_cwes_from_text(text: str) -> List[str]:
    """
    Estrae numeri CWE da testo (CWE-79, CWE 079, CWE-00079 -> '79')
    """
    if not isinstance(text, str):
        return []
    found = re.findall(r"CWE[-\s]*0*(\d+)", text, flags=re.IGNORECASE)
    out: List[str] = []
    for x in found:
        try:
            out.append(str(int(x)))
        except Exception:
            continue
    return out


def pick_gt_column(df: pd.DataFrame, explicit: Optional[str]) -> Optional[str]:
    if explicit and explicit in df.columns:
        return explicit
    for c in GT_COL_CANDIDATES:
        if c in df.columns:
            return c
    return None


# ---------------------------------------------------------------------
# ROW CLASSIFICATION
# ---------------------------------------------------------------------
def classify_row(
    pred_text: str,
    gt_text: str,
    weakness_ids: Set[str],
    category_ids: Set[str],
    view_ids: Set[str],
    all_ids: Set[str],
    c_cpp_allowlist_ids: Set[str],
) -> Tuple[bool, bool, bool, bool]:
    """
    Returns: (entity_error, wrong_level, invented, context_inconsistency)
    """
    pred_all = set(extract_cwes_from_text(pred_text))
    gt_all = set(extract_cwes_from_text(gt_text))

    pred_weak = pred_all & weakness_ids
    gt_weak = gt_all & weakness_ids

    invented = bool(pred_all) and any((c not in all_ids) for c in pred_all)
    wrong_level = bool(pred_all) and any((c in category_ids or c in view_ids) for c in pred_all)

    # Ground truth out-of-scope weakness?
    gt_has_out_of_scope = bool(gt_weak) and any((c not in c_cpp_allowlist_ids) for c in gt_weak)

    # Context inconsistency (out-of-scope predicted weakness), suppressed if GT out-of-scope too.
    context_inconsistency = (
        bool(pred_weak)
        and (not invented)
        and (not wrong_level)
        and any((c not in c_cpp_allowlist_ids) for c in pred_weak)
        and (not gt_has_out_of_scope)
    )

    # Entity-Error (UPDATED RULE):
    # only if prediction has ONLY Weakness IDs and GT has Weakness IDs, and NO correct overlap.
    pred_has_only_weakness = bool(pred_all) and all((c in weakness_ids) for c in pred_all)
    has_any_correct = bool(pred_weak & gt_weak)
    entity_error = (
        pred_has_only_weakness
        and bool(pred_weak)
        and bool(gt_weak)
        and (not has_any_correct)
    )

    return entity_error, wrong_level, invented, context_inconsistency


# ---------------------------------------------------------------------
# EXCEL ANALYSIS (per file)
# ---------------------------------------------------------------------
def analyze_excel(
    file_path: Path,
    weakness_ids: Set[str],
    category_ids: Set[str],
    view_ids: Set[str],
    all_ids: Set[str],
    c_cpp_allowlist_ids: Set[str],
    col_predicted: str,
    col_filename: str,
    col_gt_explicit: Optional[str],
) -> Tuple[int, int, int, int, int, List[Dict]]:
    """
    Returns:
      (ee_rows, wl_rows, inv_rows, ctx_rows, filename_rows, row_hits)

    row_hits: list of dict, one per (row, category) hit, including:
      FileName, Found CWE (raw), Actual CWE (raw), SourceExcelPath, + traceability
    """
    try:
        df = pd.read_excel(file_path, engine="openpyxl")
    except Exception as e:
        print(f"  WARNING: impossibile leggere {file_path.name}: {e}")
        return 0, 0, 0, 0, 0, []

    # denominator
    if col_filename in df.columns:
        filename_rows = int(df[col_filename].notna().sum())
    else:
        print(f"  WARNING: colonna '{col_filename}' non trovata in {file_path.name}. FileNameRows=0.")
        filename_rows = 0

    if col_predicted not in df.columns:
        print(f"  WARNING: colonna '{col_predicted}' non trovata in {file_path.name}. Tutti gli error rows=0.")
        return 0, 0, 0, 0, filename_rows, []

    gt_col = pick_gt_column(df, col_gt_explicit)
    gt_available = gt_col is not None
    if not gt_available:
        print(f"  WARNING: colonna ground truth non trovata in {file_path.name}. Entity-error non calcolabile. Altre categorie sì.")

    ee_rows = wl_rows = inv_rows = ctx_rows = 0
    row_hits: List[Dict] = []

    for idx, row in df.iterrows():
        found_raw = "" if pd.isna(row.get(col_predicted, "")) else str(row.get(col_predicted, ""))
        actual_raw = "" if (not gt_available or pd.isna(row.get(gt_col, ""))) else str(row.get(gt_col, ""))

        fname_val = row.get(col_filename, None)
        file_name_value = "" if (fname_val is None or pd.isna(fname_val)) else str(fname_val)

        entity_error, wrong_level, invented, context_inconsistency = classify_row(
            pred_text=found_raw,
            gt_text=actual_raw,
            weakness_ids=weakness_ids,
            category_ids=category_ids,
            view_ids=view_ids,
            all_ids=all_ids,
            c_cpp_allowlist_ids=c_cpp_allowlist_ids,
        )

        if invented:
            inv_rows += 1
        if wrong_level:
            wl_rows += 1
        if context_inconsistency:
            ctx_rows += 1
        if gt_available and entity_error:
            ee_rows += 1

        # collect row-level details for category files (require FileName)
        if not file_name_value:
            continue

        base_hit = {
            "RowIndex": int(idx),
            "FileName": file_name_value,
            "Found CWE": found_raw,
            "Actual CWE": actual_raw,
            "SourceExcelPath": str(file_path.resolve()),
        }

        if gt_available and entity_error:
            h = dict(base_hit)
            h["Category"] = "EntityError"
            row_hits.append(h)
        if wrong_level:
            h = dict(base_hit)
            h["Category"] = "WrongLevel"
            row_hits.append(h)
        if invented:
            h = dict(base_hit)
            h["Category"] = "Invented"
            row_hits.append(h)
        if context_inconsistency:
            h = dict(base_hit)
            h["Category"] = "ContextInconsistency"
            row_hits.append(h)

    return ee_rows, wl_rows, inv_rows, ctx_rows, filename_rows, row_hits


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Conta entity-error, wrong-level, invented e context inconsistency per modello; "
            "usa File Name rows come denominatore; salva Summary + dettagli e file per categoria."
        )
    )
    parser.add_argument("models_base_dir", type=Path, help="Directory che contiene le cartelle dei modelli (es. Models/)")
    parser.add_argument("output_xlsx", type=Path, help="File Excel principale di output (Summary + sheets per modello)")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help=(
            "Directory di output per i file Excel per-categoria per modello. "
            "Se non specificata: <output_xlsx_stem>_by_model accanto a output_xlsx."
        ),
    )
    parser.add_argument("--cwe-xml", type=Path, default=Path("cwec_latest.xml"), help="Percorso locale per salvare/leggere l'XML CWE")
    parser.add_argument("--c-cpp-allowlist-xlsx", type=Path, required=True, help="Excel allowlist CWE applicabili a C/C++ (colonna 'CWE-ID')")
    parser.add_argument("--prompt-count", type=int, default=DEFAULT_PROMPT_COUNT, help=f"Numero di parser_output_prompt_N da scansionare (default {DEFAULT_PROMPT_COUNT})")
    parser.add_argument("--predicted-col", type=str, default=COL_PREDICTED_DEFAULT, help=f"Nome colonna predizioni CWE (default: '{COL_PREDICTED_DEFAULT}')")
    parser.add_argument("--filename-col", type=str, default=COL_FILENAME_DEFAULT, help=f"Nome colonna File Name (default: '{COL_FILENAME_DEFAULT}')")
    parser.add_argument("--gt-col", type=str, default=None, help="Nome colonna ground truth CWE (opzionale). Se non fornito, prova una lista di candidati.")
    args = parser.parse_args()

    base_dir = args.models_base_dir
    if not base_dir.is_dir():
        print(f"ERRORE: directory base non valida: {base_dir}")
        sys.exit(1)

    # allowlist
    try:
        c_cpp_allowlist_ids = load_c_cpp_allowlist_ids(args.c_cpp_allowlist_xlsx)
    except Exception as e:
        print(f"ERRORE: {e}")
        sys.exit(1)

    if not c_cpp_allowlist_ids:
        print("ERRORE: allowlist C/C++ vuota.")
        sys.exit(1)
    print(f"-> Allowlist C/C++ caricata: {len(c_cpp_allowlist_ids)} CWE")

    # CWE XML
    if not download_and_extract_cwe_xml(args.cwe_xml):
        print("Impossibile ottenere CWE XML. Esco.")
        sys.exit(1)

    weakness_ids, category_ids, view_ids, all_ids = parse_cwe_sets_from_xml(args.cwe_xml)
    if not all_ids or not weakness_ids:
        print("ERRORE: parsing CWE XML fallito o insiemi vuoti. Esco.")
        sys.exit(1)

    print(
        f"-> CWE Weakness: {len(weakness_ids)} | "
        f"Categories: {len(category_ids)} | Views: {len(view_ids)} | Totale: {len(all_ids)}"
    )

    # output paths
    out_main = args.output_xlsx
    out_main.parent.mkdir(parents=True, exist_ok=True)

    if args.out_dir is not None:
        per_model_root = args.out_dir
    else:
        per_model_root = out_main.parent / f"{out_main.stem}_by_model"

    per_model_root = per_model_root.resolve()
    per_model_root.mkdir(parents=True, exist_ok=True)

    summary_rows: List[Dict] = []
    per_model_details: Dict[str, List[Dict]] = {}
    model_category_hits: Dict[str, Dict[str, List[Dict]]] = {}

    # iterate models
    for model_dir in sorted([d for d in base_dir.iterdir() if d.is_dir()]):
        model_name = model_dir.name

        total_ee = total_wl = total_inv = total_ctx = 0
        total_filename_rows = 0

        details_list: List[Dict] = []
        model_category_hits[model_name] = {c: [] for c in CATEGORIES}

        print(f"\nAnalizzo modello: {model_name}")

        for dataset in DATASETS:
            dataset_dir = model_dir / dataset
            if not dataset_dir.is_dir():
                continue

            for i in range(1, args.prompt_count + 1):
                prompt_dir = dataset_dir / f"parser_output_prompt_{i}"
                if not prompt_dir.is_dir():
                    continue

                for xlsx in sorted(prompt_dir.glob("*.xlsx")):
                    ee, wl, inv, ctx, fn_rows, row_hits = analyze_excel(
                        file_path=xlsx,
                        weakness_ids=weakness_ids,
                        category_ids=category_ids,
                        view_ids=view_ids,
                        all_ids=all_ids,
                        c_cpp_allowlist_ids=c_cpp_allowlist_ids,
                        col_predicted=args.predicted_col,
                        col_filename=args.filename_col,
                        col_gt_explicit=args.gt_col,
                    )

                    details_list.append({
                        "Dataset": dataset,
                        "PromptDir": prompt_dir.name,
                        "ExcelFile": xlsx.name,
                        "FileName_Rows": fn_rows,
                        "EntityError_Rows": ee,
                        "WrongLevel_Rows": wl,
                        "Invented_Rows": inv,
                        "ContextInconsistency_Rows": ctx,
                        "ExcelPath": str(xlsx.resolve()),
                    })

                    total_ee += ee
                    total_wl += wl
                    total_inv += inv
                    total_ctx += ctx
                    total_filename_rows += fn_rows

                    for h in row_hits:
                        h2 = dict(h)
                        h2["Model"] = model_name
                        h2["Dataset"] = dataset
                        h2["PromptDir"] = prompt_dir.name
                        h2["ExcelFile"] = xlsx.name
                        cat = h2["Category"]
                        model_category_hits[model_name][cat].append(h2)

        def pct(x: int, den: int) -> float:
            return round((x * 100.0 / den), 2) if den > 0 else 0.0

        summary_rows.append({
            "Nome del Modello": model_name,
            "Numero di FileName Rows Analizzati": total_filename_rows,
            "EntityError_Rows": total_ee,
            "WrongLevel_Rows": total_wl,
            "Invented_Rows": total_inv,
            "ContextInconsistency_Rows": total_ctx,
            "EntityError_Rate": pct(total_ee, total_filename_rows),
            "WrongLevel_Rate": pct(total_wl, total_filename_rows),
            "Invented_Rate": pct(total_inv, total_filename_rows),
            "ContextInconsistency_Rate": pct(total_ctx, total_filename_rows),
        })

        per_model_details[model_name] = details_list

        print(
            f"-> Totali per '{model_name}': "
            f"EntityError={total_ee}, WrongLevel={total_wl}, Invented={total_inv}, Context={total_ctx} "
            f"su FileNameRows={total_filename_rows}"
        )

    # summary
    summary_df = pd.DataFrame(summary_rows)
    summary_df = sort_models_in_summary(summary_df, model_col="Nome del Modello")

    # -----------------------------------------------------------------
    # WRITE MAIN EXCEL (Summary + per-model details)
    # -----------------------------------------------------------------
    try:
        with pd.ExcelWriter(out_main, engine="openpyxl") as writer:
            summary_df.to_excel(writer, sheet_name=unique_sheet_name(writer, "Summary"), index=False)

            for model_name, details in per_model_details.items():
                sheet_name = unique_sheet_name(writer, model_name)
                df_details = pd.DataFrame(details).sort_values(by=["Dataset", "PromptDir", "ExcelFile"])
                df_details.to_excel(writer, sheet_name=sheet_name, index=False)

        print(f"\nSalvato workbook principale: {out_main.resolve()}")
    except Exception as e:
        print(f"ERRORE scrittura output Excel principale: {e}")
        print("\nAnteprima Summary:")
        print(summary_df.head(20))

    # -----------------------------------------------------------------
    # WRITE PER-MODEL FOLDERS WITH PER-CATEGORY EXCEL FILES
    # -----------------------------------------------------------------
    for model_name, cat_map in model_category_hits.items():
        model_folder = per_model_root / sanitize_fs_name(model_name, max_len=120)
        model_folder.mkdir(parents=True, exist_ok=True)

        for cat, hits in cat_map.items():
            out_path = model_folder / f"{cat}.xlsx"

            if not hits:
                df_empty = pd.DataFrame([{"Info": "Nessuna riga rilevata per questa categoria."}])
                with pd.ExcelWriter(out_path, engine="openpyxl") as w:
                    df_empty.to_excel(w, sheet_name="Rows", index=False)
                continue

            df_hits = pd.DataFrame(hits)

            keep_cols = [
                "FileName",
                "Found CWE",
                "Actual CWE",
                "SourceExcelPath",
                "Dataset",
                "PromptDir",
                "ExcelFile",
                "RowIndex",
            ]
            for c in keep_cols:
                if c not in df_hits.columns:
                    df_hits[c] = ""

            df_hits = df_hits[keep_cols]

            # De-duplicate: same FileName within same source excel for same category
            df_hits = df_hits.drop_duplicates(subset=["SourceExcelPath", "FileName"])
            df_hits = df_hits.sort_values(by=["Dataset", "PromptDir", "ExcelFile", "FileName"])

            with pd.ExcelWriter(out_path, engine="openpyxl") as w:
                df_hits.to_excel(w, sheet_name="Rows", index=False)

    print(f"\nSalvati file per-categoria per modello sotto: {per_model_root.resolve()}")


if __name__ == "__main__":
    main()
