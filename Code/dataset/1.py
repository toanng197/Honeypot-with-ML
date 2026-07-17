import pandas as pd

def clean_dataset(input_file, output_file):
    print(f"--- BẮT ĐẦU DỌN DẸP DỮ LIỆU ---")
    print(f"File đầu vào: {input_file}")
    
    # 1. Đọc dữ liệu
    try:
        df = pd.read_csv(input_file)
        print(f"[+] Số dòng ban đầu: {df.shape[0]}")
    except FileNotFoundError:
        print("❌ Lỗi: Không tìm thấy file dữ liệu. Vui lòng kiểm tra lại tên file!")
        return

    # 2. Xóa các dòng trùng lặp hoàn toàn
    df_clean = df.drop_duplicates()
    print(f"[+] Số dòng sau khi xóa copy/paste: {df_clean.shape[0]}")

    # 3. Lọc các HTTP method hợp lệ (xóa các dòng bị xô lệch format)
    valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
    df_clean = df_clean[df_clean['method'].isin(valid_methods)]
    print(f"[+] Số dòng sau khi lọc method lỗi: {df_clean.shape[0]}")

    # 4. Xử lý giá trị khuyết thiếu (NaN)
    # Cột text điền chuỗi rỗng "", cột số điền số 0
    df_clean['path'] = df_clean['path'].fillna('')
    df_clean['query'] = df_clean['query'].fillna('')
    df_clean['body'] = df_clean['body'].fillna('')
    df_clean['content_length'] = df_clean['content_length'].fillna(0)
    print("[+] Đã xử lý xong các ô trống (NaN).")

    # 5. Xóa triệt để các dữ liệu mâu thuẫn (Contradictory Data)
    # Lấy các cột input làm cơ sở so sánh (không bao gồm nhãn)
    features = ['method', 'path', 'query', 'content_length', 'body']
    # keep=False nghĩa là nếu có trùng lặp input (dù khác hay giống nhãn), xóa sạch không giữ lại dòng nào
    df_clean = df_clean.drop_duplicates(subset=features, keep=False)
    print(f"[+] Số dòng chuẩn cuối cùng: {df_clean.shape[0]}")

    # 6. In thống kê nhãn thực tế
    print("\n--- PHÂN PHỐI NHÃN SAU KHI LÀM SẠCH ---")
    print(df_clean['label'].value_counts())
    print("---------------------------------------")

    # 7. Xuất ra file CSV mới
    df_clean.to_csv(output_file, index=False)
    print(f"✅ HOÀN THÀNH! Đã lưu dữ liệu sạch vào file: {output_file}")

if __name__ == "__main__":
    # Tên file gốc của bạn
    INPUT_CSV = "realtime_string_features_train_filtered.csv"
    
    # Tên file mới sẽ được sinh ra
    OUTPUT_CSV = "realtime_string_features_train_cleaned.csv"
    
    # Thực thi hàm
    clean_dataset(INPUT_CSV, OUTPUT_CSV)