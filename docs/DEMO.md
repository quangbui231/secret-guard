# Hướng dẫn sử dụng và demo Secret Guard

Chạy các lệnh từ thư mục gốc repository. Các file trong `examples` chứa dữ liệu
giả lập để quét, không chạy trực tiếp bằng Python.

## 1 Lấy nhánh và cài đặt trên Windows PowerShell

Nếu chưa clone repository:

```powershell
git clone --branch feat/real-world-scanning https://github.com/quangbui231/secret-guard.git
cd secret-guard
```

Nếu đã có repository, kiểm tra và lưu thay đổi đang làm trước khi chuyển nhánh:

```powershell
git fetch origin
git switch feat/real-world-scanning
```

Tạo môi trường Python (khuyến nghị 3.12, phiên bản đã kiểm thử):

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Kết quả đã kiểm tra: **177 passed** (106 test cũ + 71 test cho phần quét file thực tế). Dùng đường dẫn Python trực tiếp nên không cần
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
tạo một đoạn trích sai. So sánh với Gitleaks/detect-secrets trên dữ liệu độc lập:
xem mục 9.

## 8 Lưu ý khi trình bày

- Mã thoát 1 khi có BLOCK là hành vi dự kiến, không phải chương trình bị lỗi.
  Xem `$LASTEXITCODE` ngay sau lệnh nếu muốn demo mã thoát.
- Mã 0 có thể vẫn có REVIEW hoặc có file bị bỏ qua. Luôn đọc SCAN SUMMARY.
- Chỉ `.py` được áp dụng AST. File lỗi cú pháp quay lại cơ chế văn bản cũ.
- Không chạy `.py` demo trực tiếp: các tên hàm/biến chỉ là tình huống giả lập.
- AST không thực thi file và không giải quyết luồng dữ liệu qua biến/hàm/file.
- Kết luận phù hợp: cải tiến chất lượng phát hiện so với bản Secret Guard gốc
  trong các tình huống đã đo, không phải phát minh thuật toán AST mới.

## 9 Demo quét file thực tế nhiều định dạng

Tạo bộ file mẫu (21 secret giả lập trong 20 loại file: `.env`, `.netrc`,
JSON, YAML, XML, PHP, JS, Word, Excel, PDF, notebook, zip, tar.gz, gz, UTF-16,
cp1252, `.htpasswd`...) rồi quét cả thư mục:

```powershell
.\.venv\Scripts\python.exe scripts/generate_dataset.py --real-world
.\.venv\Scripts\python.exe -m secret_guard.main dataset/real_world --show-skipped
```

Nhớ giữ cờ `--real-world`: chạy `generate_dataset.py` không có cờ sẽ tạo lại
bộ `dataset/positive`, `dataset/negative` của bản gốc và ghi đè file đang có
(khôi phục bằng `git checkout -- dataset`). Thư mục `dataset/real_world` đã
nằm trong `.gitignore`.

Điểm cần chỉ ra khi trình bày:

- File trong file nén hiện dạng `backup/config_backup.zip!config/.env`.
- Word/Excel/PDF/notebook được đọc chữ; file UTF-16 và cp1252 đọc đúng.
- `assets/logo.png`, `data/model.bin` bị bỏ qua có lý do; `package-lock.json`
  bị loại vì là lock file (`Excluded by rules: 1`).
- `src/clean.py` (`os.getenv`) và `const password = getPassword()` trong
  `web/app.js` không bị báo.
- Kết quả: 21 BLOCK, 0 REVIEW. Mỗi phát hiện từ định dạng mới có dòng `Context`.

Quét một dự án thật bất kỳ trên máy (ví dụ thư mục code của chính bạn):

```powershell
.\.venv\Scripts\python.exe -m secret_guard.main C:\duong\dan\du_an --only-block
.\.venv\Scripts\python.exe -m secret_guard.main C:\duong\dan\du_an --format json --output report.json
```

Đánh giá trên bộ dữ liệu độc lập leaky-repo (cần mạng để clone):

```powershell
git clone https://github.com/Plazmaz/leaky-repo ..\leaky-repo
.\.venv\Scripts\python.exe -m evaluation.performance ..\leaky-repo
```

Kết quả đã chạy ngày 06/11/2026: chỉ tính BLOCK, Secret Guard bắt 78/175 secret
ở 37/44 file, 0 báo dư (bản trước nâng cấp: 26/175, 16/44 file). Cùng cách chấm,
detect-secrets 1.5.0 đạt 42/175, Gitleaks 8.21.2 đạt 25/175.
