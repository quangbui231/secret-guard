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
Không so trực tiếp tỷ lệ của hai kiểu chấm. Không suy rộng kết quả thành độ chính
xác trên code thực tế hoặc kết luận vượt Gitleaks/detect-secrets.

Tài liệu AST và vị trí UTF-8:
https://docs.python.org/3.12/library/ast.html#ast.AST
