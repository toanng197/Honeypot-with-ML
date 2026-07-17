import os
import time
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

# ==========================================
# 1. CẤU HÌNH ĐƯỜNG DẪN & LOAD MODEL
# ==========================================
INPUT_FEATURES_FILE = "realtime_features_outputnew1.csv"

print("=== [SYSTEM] Đang khởi động luồng hiển thị dự đoán Realtime (XGBoost)... ===")
try:
    # Load mô hình XGBoost đã được cập nhật từ file train mới
    model = joblib.load("attack_modelxgnew1.pkl")

    # Lấy danh sách nhãn tương ứng từ thuộc tính tùy biến
    classes = model.custom_classes_
    normal_idx = list(classes).index("Normal")

    print("=== [SYSTEM] Load mô hình thành công. Đang đợi request mới... ===\n")
except Exception as e:
    print(f"=== [ERROR] Lỗi load mô hình: {e} ===")
    exit()

# ĐÃ ĐỒNG BỘ: Cập nhật chính xác 18 cột đặc trưng theo đúng mô hình XGBoost yêu cầu
feature_headers = [
    "method",
    "path_length",
    "query_length",
    "body_length",
    "slash_count",
    "dot_count",
    "path_special_chars",   # Cột mới tách 1
    "query_special_chars",  # Cột mới tách 2
    "body_special_chars",   # Cột mới tách 3
    "digit_ratio",
    "percent_encoding_count",
    "has_sql_keyword",
    "sqli_pattern_count",
    "has_xss_keyword",
    "has_path_traversal",
    "has_cmd_keyword",
    "html_bracket_count",
    "quote_count",
    "js_bracket_count"
]


# ==========================================
# 2. HÀM DỰ ĐOÁN THEO NGƯỠNG AN TOÀN (THRESHOLD)
# ==========================================
def predict_single_request(features_dict):
    X_single = pd.DataFrame([features_dict])[feature_headers].astype(np.float32)

    proba = model.predict_proba(X_single)[0]

    print("\n===== RAW PROBABILITIES =====")
    for cls, p in zip(classes, proba):
        print(f"{cls}: {p:.4f}")

    pred_idx = np.argmax(proba)
    result = classes[pred_idx]

    return result, proba


# ==========================================
# 3. LUỒNG ĐỌC FILE LIÊN TỤC VÀ IN MÀN HÌNH
# ==========================================
def watch_and_display():
    while not os.path.exists(INPUT_FEATURES_FILE):
        print(f"⚠️ Đang đợi file đặc trưng xuất hiện: {INPUT_FEATURES_FILE}...")
        time.sleep(1)

    with open(INPUT_FEATURES_FILE, "r", encoding="utf-8") as f_in:
        # Nhảy thẳng xuống cuối file để bỏ qua dữ liệu cũ, chỉ chờ dòng mới phát sinh
        f_in.seek(0, os.SEEK_END)

        while True:
            line = f_in.readline()

            if not line:
                time.sleep(0.05)  # Tiết kiệm tài nguyên CPU
                continue

            line = line.strip()
            if not line:
                continue

            try:
                # Phân tách dòng CSV đặc trưng vừa nhận
                parts = [p.strip() for p in line.split(",")]

                # Bỏ qua nếu dòng đó là dòng tiêu đề (Header) hoặc không đủ số lượng cột
                if parts[0].lower() in ["method", "method_map"] or len(parts) < len(feature_headers):
                    continue

                # Ép dữ liệu chuỗi thô của cả 18 cột về kiểu số float dựa theo map zip
                features_dict = {}
                for idx, col_name in enumerate(feature_headers):
                    features_dict[col_name] = float(parts[idx])

                # Dự đoán loại request
                if (
                        features_dict["sqli_pattern_count"] >= 1
                        and features_dict["quote_count"] >= 2
                ):
                    pred_label = "Injection"
                    proba_scores = np.array([0, 1, 0, 0])

                else:
                    pred_label, proba_scores = predict_single_request(features_dict)

                # Hiển thị trực tiếp kết quả ra màn hình console
                if pred_label == "Normal":
                    print(f"🟢 [REQUEST SẠCH] -> Kết quả: {pred_label}")
                else:
                    print(f"🚨 [CẢNH BÁO TẤN CÔNG] -> Phát hiện: {pred_label}")
                    print(
                        f"   ↳ Chi tiết xác suất phân loại: {dict(zip(classes, np.round(proba_scores, 4)))}"
                    )
                print("-" * 60)

            except Exception as e:
                print(f"❌ Lỗi xử lý dòng dữ liệu: {e}")


if __name__ == "__main__":
    try:
        watch_and_display()
    except KeyboardInterrupt:
        print("\n👋 Đã dừng luồng giám sát Realtime.")