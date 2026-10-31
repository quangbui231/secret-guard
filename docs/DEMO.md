# Hướng dẫn sử dụng và demo cải tiến AST

Chạy các lệnh từ thư mục gốc repository. Các file trong `examples` chứa dữ liệu
giả lập để quét, không chạy trực tiếp bằng Python.

## 1 Lấy nhánh và cài đặt trên Windows PowerShell

Nếu chưa clone repository:

```powershell
git clone --branch feat/python-ast-context https://github.com/quangbui231/secret-guard.git
cd secret-guard
```

Nếu đã có repository, kiểm tra và lưu thay đổi đang làm trước khi chuyển nhánh:

```powershell
git fetch origin
git switch feat/python-ast-context
```

Tạo môi trường Python (khuyến nghị 3.12, phiên bản đã kiểm thử):

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Kết quả đã kiểm tra: **106 passed**. Dùng đường dẫn Python trực tiếp nên không cần
activate môi trường hoặc thay đổi ExecutionPolicy của PowerShell.
Trên Linux/macOS, thay `.\.venv\Scripts\python.exe` bằng `.venv/bin/python`.

## 2 Demo giảm cảnh báo nhầm

Mở `examples/demo_steps/01_reference.py`: `password = load_password()`.

```powershell
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/01_reference.py --no-python-context
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/01_reference.py
```

Trước: báo biểu thức lấy mật khẩu như secret. Sau: `No secrets detected.`
Giải thích: AST nhận biết giá trị là lời gọi hàm, không phải chuỗi mật khẩu viết
trực tiếp. Không có nghĩa hàm an toàn; chưa phân tích bên trong hàm.

## 3 Demo tìm secret dưới khóa dictionary

Mở `02_dictionary.py`: `config = {"password": "DemoPass123!"}`.

```powershell
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/02_dictionary.py --no-python-context
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/02_dictionary.py
```

Trước: bỏ sót ví dụ này. Sau: cảnh báo có `Detected by: Python AST`, lý do
`Hardcoded value under a sensitive dictionary key`, hành động BLOCK.
Secret hiển thị đã được che; không cần hiện nguyên mật khẩu để demo.

## 4 Demo giải thích đối số hàm

Mở `03_argument.py`: `connect(client_secret="alpha!987")`.

```powershell
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/03_argument.py --no-python-context
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/03_argument.py
```

Cả bản cũ và mới có thể phát hiện ví dụ này bằng Keyword. Điểm cần trình bày là
bản mới bổ sung bằng chứng `Python AST` và lý do
`Hardcoded sensitive keyword argument`, sau đó gộp cùng phát hiện cũ.
Không tuyên bố đây là ví dụ bản cũ bỏ sót.

## 5 Demo mật khẩu mặc định trong biến môi trường

Mở `04_default.py`: `value = os.getenv("PASSWORD", "Fallback!123")`.

```powershell
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/04_default.py --no-python-context
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/04_default.py
```

Trước: bỏ sót ví dụ này. Sau: cảnh báo giá trị mặc định, lý do
`Hardcoded default in a sensitive lookup`. Công cụ không bỏ qua cả lời gọi chỉ
vì nó dùng biến môi trường: fallback vẫn là secret viết trực tiếp.

## 6 Demo placeholder vẫn được lọc

```powershell
.\.venv\Scripts\python.exe -m secret_guard.main examples/demo_steps/05_placeholder.py
```

Kết quả: `No secrets detected.` Mẫu `your_password_here` được bộ lọc loại bỏ.
Demo này thể hiện phần AST phối hợp với bộ lọc có sẵn, không phải chức năng lọc mới.

## 7 Chạy so sánh có số liệu

```powershell
.\.venv\Scripts\python.exe -m evaluation.compare_context --output results/context_comparison.json
.\.venv\Scripts\python.exe -m evaluation.evaluate --dataset development
.\.venv\Scripts\python.exe -m evaluation.evaluate --dataset test
```

Trên 32 tình huống ngữ cảnh và 22 secret gán nhãn, bản tắt/bật AST lần lượt có
TP=4/20, FP=7/1, FN=18/2. Bộ dữ liệu cũ giữ kết quả theo dòng: TP=19 và 53,
FP=0, FN=0. Tập ngữ cảnh chấm theo dòng và giá trị chính xác, khác phép chấm theo
dòng của tập cũ. Không dùng hai tỷ lệ đó để so sánh trực tiếp.

Tập ngữ cảnh là tập phát triển viết tay, chưa độc lập với việc triển khai. Còn
bỏ sót giá trị qua biến trung gian và fallback bằng toán tử `or`; ca `or` còn
tạo một đoạn trích sai. Chưa benchmark với Gitleaks/detect-secrets.

## 8 Lưu ý khi trình bày

- Mã thoát 1 khi có BLOCK là hành vi dự kiến, không phải chương trình bị lỗi.
  Xem `$LASTEXITCODE` ngay sau lệnh nếu muốn demo mã thoát.
- Mã 0 có thể vẫn có REVIEW hoặc có file bị bỏ qua. Luôn đọc SCAN SUMMARY.
- Chỉ `.py` được áp dụng AST. File lỗi cú pháp quay lại cơ chế văn bản cũ.
- Không chạy `.py` demo trực tiếp: các tên hàm/biến chỉ là tình huống giả lập.
- AST không thực thi file và không giải quyết luồng dữ liệu qua biến/hàm/file.
- Kết luận phù hợp: cải tiến chất lượng phát hiện so với bản Secret Guard gốc
  trong các tình huống đã đo, không phải phát minh thuật toán AST mới.
