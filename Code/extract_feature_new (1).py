import os
import time
import re
import csv
import pandas as pd
from urllib.parse import unquote_plus

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN FILE
# ==========================================
INPUT_FILE_PATH = r"C:\Users\Admin\OneDrive\Máy tính\Krawl-main\Nginx\nginx-1.31.1\logs\access.log"
OUTPUT_FILE_PATH = "realtime_features_outputnew1.csv"

# ======================
# Keyword sets (Đã nâng cấp XSS_KEYWORDS)
# ======================
SQL_KEYWORDS = [
    "union",
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "or",
    "and",
    "'",
    "--",
    "sleep",
    "benchmark",
    "information_schema",
    "concat",
    "char",
    "exec",
    "ascii",
    "substring",
    "order by",
    "1=1",
    "union select"
]
XSS_KEYWORDS = ["<script", "javascript:", "onerror=", "onload=", "alert(",
    "onmouseover=", "onfocus=", "onclick=", "srcdoc=", "confirm(", "prompt(",
    "svg", "img", "iframe", "body", "src=", "href=", "onload"]
PATH_KEYWORDS = ["../", "..\\", "/etc/passwd", "boot.ini", "win.ini"]
CMD_KEYWORDS = ["cmd.exe", "/bin/sh", "powershell", "wget", "curl", "whoami", "net user"]
SQLI_PATTERNS = [
    r"'\s*or\s*'?\d+'?\s*=\s*'?\d+'?",
    r"'\s*or\s*'?[a-z]+'?\s*=\s*'?[a-z]+'?",
    r"\bor\b\s+1\s*=\s*1",
    r"union\s+select",
    r"--",
    r"/\*",
    r"#"
]

# ======================
# Helper functions
# ======================
def decode_nginx_hex(text):
    """Giải mã các ký tự bị Nginx mã hóa dạng \x3C, \x3E trong access.log thô"""
    text = str(text)
    return re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)


def contains_keywords(text, keywords):
    text = str(text).lower()

    for k in keywords:
        k = k.lower().strip()

        if k in ["or", "and"]:
            if re.search(r"\b" + re.escape(k) + r"\b", text):
                return 1
        else:
            if k in text:
                return 1

    return 0

def count_sqli_patterns(text):
    text = str(text).lower()

    count = 0

    for pattern in SQLI_PATTERNS:
        count += len(re.findall(pattern, text))

    return count
def digit_ratio(text):
    text = str(text)
    if len(text) == 0:
        return 0
    return float(sum(c.isdigit() for c in text) / len(text))


def special_char_count(text):
    text = str(text)
    chars = set("<>'\";()=%/\\{}[]:$&|")
    return sum(c in chars for c in text)


def percent_encoding_count(text):
    text = str(text)
    return len(re.findall(r"%[0-9a-fA-F]{2}", text))


# --- THÊM CÁC HÀM TRÍCH XUẤT ĐẶC TRƯNG ĐỊNH DANH MỚI ---
def count_html_brackets(text):
    text = str(text)
    return text.count("<") + text.count(">")


def count_quotes(text):
    text = str(text)
    return text.count("'") + text.count('"')


def count_js_brackets(text):
    text = str(text)
    return sum(text.count(char) for char in "()[]{}")


# ==========================================
# FEATURE EXTRACTION (Đã thêm 3 cột đặc trị XSS/SQLi và xử lý giải mã Hex)
# ==========================================
def extract_features_dict(method, path, query, body):
    method = str(method).upper()

    # Bước 1: Giải mã mã độc mã hóa Hex đặc thù của Nginx (\x3C -> <, \x3E -> >)
    path = decode_nginx_hex(path)
    query = decode_nginx_hex(query)
    body = decode_nginx_hex(body)

    # Bước 2: Giải mã mã độc mã hóa URL Percent Encoding thông thường
    path = unquote_plus(path) if pd.notna(path) and str(path).lower() != 'nan' else ""
    query = unquote_plus(query) if pd.notna(query) and str(query).lower() != 'nan' else ""
    body = unquote_plus(body) if pd.notna(body) and str(body).lower() != 'nan' else ""

    # Bước 3: Tạo văn bản toàn diện và làm sạch tất cả khoảng trắng thừa, tab, xuống dòng (\s+)
    full_text = " ".join([path, query, body]).lower()
    full_text = re.sub(r'\s+', ' ', full_text).strip()

    method_map = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4}

    return {
        "method": method_map.get(method, -1),
        "path_length": len(path),
        "query_length": len(query),
        "body_length": len(body),
        "slash_count": path.count("/"),
        "dot_count": path.count("."),
        # Sửa đổi: Đã tách thành 3 trường riêng biệt thay vì 1 trường gom chung
        "path_special_chars": special_char_count(path),
        "query_special_chars": special_char_count(query),
        "body_special_chars": special_char_count(body),
        "digit_ratio": round(digit_ratio(full_text), 6),  # Làm tròn 6 chữ số thập phân để đồng bộ
        "percent_encoding_count": percent_encoding_count(full_text),
        "has_sql_keyword": contains_keywords(full_text, SQL_KEYWORDS),
        "sqli_pattern_count": count_sqli_patterns(full_text),
        "has_xss_keyword": contains_keywords(full_text, XSS_KEYWORDS),
        "has_path_traversal": contains_keywords(full_text, PATH_KEYWORDS),
        "has_cmd_keyword": contains_keywords(full_text, CMD_KEYWORDS),
        # --- 3 Cột mới nối tiếp vào cuối bảng đặc trưng ---
        "html_bracket_count": count_html_brackets(full_text),
        "quote_count": count_quotes(full_text),
        "js_bracket_count": count_js_brackets(full_text)
    }


# ==========================================
# LUỒNG ĐỌC - GHI REALTIME CẬP NHẬT LIÊN TỤC
# ==========================================
def watch_and_write_features(input_path, output_path):
    print(f"=== [SYSTEM] Đang lắng nghe dữ liệu trực tiếp từ log Nginx: {input_path} ===")
    print(f"=== [SYSTEM] Kết quả đặc trưng sẽ xuất vào: {output_path} ===")

    # ĐÃ ĐỒNG BỘ: Thay thế 'special_char_count' bằng 3 cột đặc trưng chi tiết mới
    fieldnames = [
        "method", "path_length", "query_length", "body_length",
        "slash_count", "dot_count",
        "path_special_chars", "query_special_chars", "body_special_chars",  # Đã sửa ở đây
        "digit_ratio", "percent_encoding_count", "has_sql_keyword","sqli_pattern_count", "has_xss_keyword",
        "has_path_traversal", "has_cmd_keyword",
        "html_bracket_count", "quote_count", "js_bracket_count"
    ]

    if not os.path.exists(output_path):
        with open(output_path, "w", newline="", encoding="utf-8") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()

    while not os.path.exists(input_path):
        time.sleep(1)

    current_request = {}

    with open(input_path, "r", encoding="utf-8") as f_in:
        f_in.seek(0, os.SEEK_END)

        while True:
            line = f_in.readline()
            if not line:
                time.sleep(0.05)
                continue

            line = line.strip()
            if not line:
                continue

            match = re.match(r"^([^:]+):(.*)$", line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()

                if value == "-":
                    value = ""

                current_request[key] = value

                if key == "body":
                    method = current_request.get("method", "GET")
                    path = current_request.get("path", "")
                    query = current_request.get("query", "")
                    body = current_request.get("body", "")

                    features = extract_features_dict(method, path, query, body)
                    print("\n==============================")
                    print("REQUEST")
                    print("==============================")
                    print("METHOD:", method)
                    print("PATH  :", path)
                    print("QUERY :", query)
                    print("BODY  :", body)

                    print("\nFEATURES")
                    print(features)
                    with open(output_path, "a", newline="", encoding="utf-8") as f_out:
                        writer = csv.DictWriter(f_out, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
                        writer.writerow(features)

                    print(f"🔹 Đã trích xuất đặc trưng nâng cấp từ RAM: {method} {path}")
                    current_request = {}


if __name__ == "__main__":
    watch_and_write_features(INPUT_FILE_PATH, OUTPUT_FILE_PATH)
