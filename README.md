# Secret Guard

Quét secret viết trực tiếp trong file bằng Regex, Entropy và Keyword.
Phiên bản cải tiến bổ sung ngữ cảnh cú pháp Python bằng `ast` của thư viện chuẩn.
Không thực thi mã nguồn đang quét.

## Cài và chạy

Dùng Python 3.10 trở lên (đã kiểm tra với Python 3.12.14). Chạy từ gốc repository:

```sh
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m secret_guard.main path/to/project
```

Mã thoát: 1 khi có BLOCK; 0 khi không có BLOCK (vẫn có thể có REVIEW);
2 cho các lỗi được CLI xử lý. File không đọc được có thể bị bỏ qua: luôn đọc
thống kê skipped, không diễn giải mã 0 là chứng nhận toàn bộ dự án an toàn.

## Quét file và dự án thực tế

Bản nâng cấp (nhánh `feat/real-world-scanning`) quét được thư mục dự án thật và
file bất kỳ, không chỉ bộ dữ liệu mẫu của nhóm.

**Đọc được nhiều loại file** (`secret_guard/filters/file_filter.py`):

| Loại | Cách xử lý |
| --- | --- |
| Văn bản, mã nguồn, dotfile (`.env`, `.netrc`, `Dockerfile`...) | Tự nhận bảng mã: UTF-8, UTF-8 BOM, UTF-16/32 (có hoặc không BOM), lùi về cp1252/latin-1 |
| Word, Excel, PowerPoint (`.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.odp`) | Trích chữ từ XML bên trong |
| PDF | Trích chữ bằng `pypdf` (thiếu thư viện thì bỏ qua và ghi lý do) |
| Jupyter notebook (`.ipynb`) | Lấy mã và kết quả in ra của từng ô |
| File nén (`.zip`, `.jar`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`, `.gz`) | Quét từng file bên trong, tên dạng `backup.zip!config/.env`; giới hạn độ sâu, số thành phần, dung lượng và tỷ lệ nén để chống zip bomb |
| Ảnh, video, font, file thực thi, cơ sở dữ liệu, mô hình | Bỏ qua, ghi lý do trong SCAN SUMMARY |

**Hiểu thêm định dạng chứa secret** (`FormatDetector` trong `secret_guard/detectors/keyword_detector.py`):
khóa JSON/JS/dict (`"password": "..."`), mảng PHP (`'db_pass' => '...'`),
`define('AUTH_KEY', '...')`, thẻ XML (`<password>`, `<Pass>`), URL có mật khẩu
với mọi giao thức (`https://user:pass@host`), `.netrc`, `.pgpass`, cấu hình dạng
`password "..."`, mã băm mật khẩu crypt (`/etc/shadow`, `.htpasswd`) và khóa PuTTY.

**Giảm báo nhầm trên mã thật**: bỏ qua thư mục phụ thuộc/build (`node_modules`,
`dist`, `build`, `.venv`...) và lock file (`package-lock.json`, `uv.lock`...);
entropy bỏ qua tên định danh, đường dẫn URL, mã băm có tên (`rev`, `sha256`,
`integrity`) và mã commit gắn sau `@`; với JS/PHP/Java... giá trị không có dấu
nháy sau phép gán là biểu thức, không phải secret; Regex/Keyword không còn khớp
vượt qua dòng mới. Với `.py`, AST vẫn xử lý như trước nên cờ
`--no-python-context` vẫn tái hiện đúng bản gốc để so sánh.

```sh
python -m secret_guard.main D:/projects/my-app                 # một thư mục
python -m secret_guard.main .env config/ backup.zip            # nhiều đường dẫn
python -m secret_guard.main . --exclude tests --exclude "*.csv" # bỏ qua thêm
python -m secret_guard.main . --respect-gitignore              # chỉ file git không bỏ qua
python -m secret_guard.main . --only-block --show-skipped      # gọn hơn, liệt kê file bỏ qua
python -m secret_guard.main . --format json --output report.json  # báo cáo JSON (đã che secret)
```

Tùy chọn khác: `--max-file-size MB` (mặc định 10), `--no-archives`,
`--no-documents`, `--no-default-excludes`. Báo cáo JSON chỉ chứa giá trị đã che,
không bao giờ chứa secret gốc.

Thử nhanh với bộ file mẫu nhiều định dạng (21 secret giả lập trong 20 loại file):

```sh
python scripts/generate_dataset.py --real-world
python -m secret_guard.main dataset/real_world
```

### Kết quả trên dữ liệu thực tế (06/11/2026)

| Bộ thử | Bản trước nâng cấp | Bản nâng cấp |
| --- | --- | --- |
| [pallets/flask](https://github.com/pallets/flask) (dự án sạch, 235 file) | 5.057 phát hiện (31 BLOCK, 5.026 REVIEW), 3.491 trong `uv.lock` | 32 phát hiện (20 BLOCK, 12 REVIEW) |
| [Plazmaz/leaky-repo](https://github.com/Plazmaz/leaky-repo), chỉ tính BLOCK | 26/175 secret, 16/44 file | 78/175 secret, 37/44 file, 0 báo dư |
| Bộ file mẫu `dataset/real_world` | Không đọc được Office/PDF/notebook/file nén/UTF-16 | 21/21 secret, 0 báo dư |

20 BLOCK còn lại trên Flask là chuỗi viết thẳng trong tài liệu và test
(`SECRET_KEY = '192b9bdd...'`, `password='test'`): đúng là secret mẫu nằm trong
mã, công cụ không biết chúng chỉ là ví dụ. Dùng `--exclude tests` hoặc allowlist.

leaky-repo do người khác gán nhãn nên là bộ đánh giá độc lập với nhóm. Cùng cách
chấm (giống `.leaky-meta/benchmark.py`), cấu hình mặc định: detect-secrets 1.5.0
đạt 42/175 (24/44 file, 4 báo dư), Gitleaks 8.21.2 đạt 25/175 (13/44 file).
Gitleaks mạnh với secret thật theo định dạng nhà cung cấp; leaky-repo chủ yếu là
mật khẩu trong file cấu hình nên kết quả này không có nghĩa Gitleaks kém hơn nói chung.

```sh
git clone https://github.com/Plazmaz/leaky-repo
python -m evaluation.performance leaky-repo --compare
```

## Cải tiến ngữ cảnh Python

Chỉ áp dụng với tên file có đuôi `.py`. Khi dùng API scan_text, truyền filename
có đuôi `.py` để bật phân tích ngữ cảnh. `<memory>` và các định dạng khác giữ
cách dò văn bản. File Python lỗi cú pháp hoặc cú pháp không được phiên bản Python
đang chạy hỗ trợ quay lại cơ chế cũ.

Các trường hợp được xử lý:

- Phân biệt giá trị chuỗi với lời gọi hàm, biến, thuộc tính và biểu thức truy xuất
  trong phép gán, dictionary và đối số có tên nhạy cảm.
- Bổ sung phát hiện literal dưới khóa dictionary và trong đối số có tên nhạy cảm.
- Phát hiện giá trị mặc định literal trong `os.getenv`, `os.environ.get`,
  `environ.get`, `config.get` khi tên lookup hoặc biến nhận là nhạy cảm.
- Giữ nguồn phát hiện `Python AST` và lý do ngữ cảnh trong báo cáo đã che secret.
- Chuyển vị trí byte UTF-8 của AST về offset ký tự để xử lý tên biến tiếng Việt.

Tên lookup được nhận diện theo cú pháp, chưa giải quyết alias/shadowing. Không
khẳng định hàm lấy dữ liệu là an toàn. Không truy vết nguồn giá trị qua biến,
qua hàm hoặc qua file. Nhánh điều kiện, f-string động và các biến đổi chuỗi
phức tạp chưa được phân tích ngữ nghĩa; detector cũ vẫn chạy. Với lời gọi bất kỳ,
giữ các phát hiện literal có sẵn trong đối số, chưa suy luận mọi đối số là secret.
Ngưỡng tối thiểu 4 ký tự và bộ lọc placeholder cũ vẫn áp dụng.

## Demo trước và sau

Xem [hướng dẫn cài đặt và demo từng tình huống](docs/DEMO.md).

```sh
python -m secret_guard.main examples/context_demo.py --no-python-context
python -m secret_guard.main examples/context_demo.py
```

Demo chứa dữ liệu giả lập, không chạy trực tiếp file demo. So sánh: lời gọi
`load_password()` không còn bị nhận nhầm là giá trị secret; mật khẩu trong
dictionary và giá trị mặc định vẫn bị phát hiện. Cả hai lệnh có thể trả 1 vì có
BLOCK; cần đọc từng finding, không chỉ nhìn mã thoát.

## Đo trước và sau

```sh
python -m evaluation.compare_context --output results/context_comparison.json
python -m evaluation.evaluate --dataset development
python -m evaluation.evaluate --dataset test
```

`--no-python-context` / `SecretGuard(enable_python_context=False)` tắt duy nhất
phần phân tích AST để tạo đối chứng. File `evaluation/context_cases.json` có 32
tình huống viết tay và 22 secret được gán nhãn, gồm cả giới hạn chưa xử lý.
Đây là tập phát triển/kiểm tra chức năng, không phải tập kiểm định độc lập.
Chấm theo case, dòng và giá trị secret đã giải mã chính xác; gộp cùng giá trị
trên cùng dòng. Các đoạn trích sai được tính FP, secret không tìm đúng tính FN.
Không tính accuracy vì TN không có định nghĩa hữu ích ở đơn vị trích xuất này.

Kết quả ngày 31/10/2026:

| Cấu hình | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Tắt AST | 4 | 7 | 18 | 36,36% | 18,18% | 24,24% |
| Bật AST | 20 | 1 | 2 | 95,24% | 90,91% | 93,02% |

Hai giới hạn trong tập kiểm tra: giá trị đi qua biến trung gian và fallback dùng
toán tử `or`. Dòng fallback còn sinh một đoạn trích sai từ detector cũ. Các bộ
Development/Test ban đầu vẫn giữ TP=19/53, FP=0, FN=0 theo cách chấm theo dòng.
Không so trực tiếp tỷ lệ của hai kiểu chấm. Kết quả trên mã thực tế và so sánh
với Gitleaks/detect-secrets nằm ở mục "Quét file và dự án thực tế" phía trên.

Tài liệu AST và vị trí UTF-8:
https://docs.python.org/3.12/library/ast.html#ast.AST
