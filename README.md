# PathGuard Agent

Lõi điều tra đọc một hồ sơ thử nghiệm. Amazon Bedrock chọn công cụ, tra bằng chứng rồi đề xuất giữ, thu hẹp, thu hồi hoặc báo chưa đủ bằng chứng. Bộ kiểm chứng tính tập nguồn được phép trước và sau trên snapshot giả lập một đích và một cổng.

## Kiểm thử cục bộ

```powershell
python -m unittest discover -s work/pathguard -p test_agent.py -v
```

Các bài kiểm thử dùng phản hồi Bedrock giả lập để kiểm tra vòng gọi tool và các điều kiện từ chối thay đổi.

Bộ test gồm 18 bài viết riêng và 189 biến thể kiểm tra chính sách. Trong ma trận, mỗi nguồn có một trạng thái do bộ test định trước: cần giữ, đã xác nhận không cần hoặc chưa xác nhận. Phương án chỉ đạt khi cắt đúng các nguồn đã xác nhận không cần. Mỗi biến thể là một lượt kiểm thử riêng.

## Kiểm thử kết nối trong lab hybrid

Lab WSL tạo bốn vùng mạng cô lập đại diện AWS Dev, Staging, Production và on-prem. Router Linux nối bốn vùng. Các service có IP riêng. Mỗi ca chạy probe TCP/HTTP thật trước và sau khi áp chính sách Linux `tc`, hoặc đo lại trên cấu hình cũ nếu không có hành động. Báo cáo nêu phương án thu hẹp, thu hồi, giữ hoặc tiếp tục xác minh kèm kết quả đo theo từng nguồn.

Chạy từ thư mục workspace trong PowerShell. Ubuntu WSL cần có Python 3, iproute2 và curl.

```powershell
$pgRoot = (wsl.exe -d Ubuntu -- wslpath -a "$((Get-Location).Path.Replace('\','/'))").Trim()
wsl.exe -d Ubuntu -u root -- unshare --mount --net --propagation private env PYTHONDONTWRITEBYTECODE=1 python3 "$pgRoot/work/pathguard/hybrid_lab.py" --report "$pgRoot/outputs/pathguard-hybrid-lab-report.md"
```

Tám ca dùng dữ liệu và đề xuất định trước để kiểm thử lớp mạng và bộ kiểm chứng. Ca Kubernetes kiểm tra hai workload cùng vùng bằng quyền IP trong lab. AWS account, thiết bị on-prem, Kubernetes NetworkPolicy, NAT thật và suy luận Bedrock cần các bài tích hợp riêng.

## Lab Docker Compose

Docker Compose dựng bốn mạng bridge đại diện Dev, Staging, Production và on-prem. Các container workload dùng chung danh mục dịch vụ với lab WSL. Một container firewall định tuyến giữa các vùng. Ca cùng vùng áp chính sách tại đích. Lab không publish cổng ra host và bỏ đường mặc định trong các container.

Chạy từ thư mục workspace trên Windows với Docker Engine đang hoạt động. Có thể dùng PowerShell hoặc terminal cục bộ của MobaXterm.

```powershell
docker compose -f work/pathguard/compose.lab.yaml up --build -d --wait
python work/pathguard/docker_lab.py scenarios
python work/pathguard/docker_lab.py hotfix --report outputs/pathguard-docker-hotfix.json
```

Ca hotfix đọc lại `iptables` và chạy probe TCP/HTTP tại bốn mốc. File JSON lưu rule thực tế và rule nào cấp quyền cho từng nguồn sau mỗi mốc. Lệnh kiểm thử phải chạy lần lượt vì dùng chung firewall lab.

Dừng lab khi cần bằng `docker compose -f work/pathguard/compose.lab.yaml down`.

### Giám sát tự động

Bộ giám sát tự đọc chain `FORWARD` của firewall Docker mỗi 5 giây mặc định, trên toàn bộ danh mục endpoint của lab. Chưa cần nhập ID rule. Nó nhận diện quyền Dev/Staging tới Production hoặc on-prem, quyền do nhiều rule cùng cấp, và quyền còn sau khi xóa rule. Một phát hiện giữ cùng ID qua các lượt quét. Kết nối bị đóng trong cấu hình được đánh dấu `cleared_in_configuration`. Kết quả probe được ghi riêng trong bài test lab.

```powershell
python work/pathguard/monitor.py --state outputs/pathguard-monitor-state.json
```

Dùng `--once` để quét một lượt và tiếp tục cùng lịch sử bằng cùng file state. Chạy một tiến trình ghi cho mỗi file. Nếu cấu hình ngoài định dạng được hỗ trợ, bộ giám sát giữ lại bản chụp hợp lệ gần nhất và báo lỗi trong terminal.

Để tự chuyển cảnh báo vào agent Bedrock đang có, thêm cả `--region` và `--model-id`, và tùy chọn `--profile`. Nếu chưa bật model, trường `investigation.status` giữ `pending`. Nguồn lab hiện cung cấp cấu hình và thay đổi giữa các lượt quét. Cần nối thêm log luồng và xác nhận vận hành để đánh giá mục đích và đề xuất sửa. Bộ giám sát giữ cảnh báo ngay cả khi model trả lỗi.

#### Lịch sử bằng chứng SQLite

Có thể thêm một lịch sử bằng chứng dùng SQLite tích hợp trong Python. Nó ghi nhận các flow được cấu hình cho phép, phát hiện monitor và độ phủ của lần quét. Phạm vi hiện tại chỉ là snapshot firewall Docker và inventory lab. Trạng thái `observed_config_only` không phải flow log và không chứng minh traffic thực sự đã đi qua.

```powershell
python work/pathguard/monitor.py --state outputs/pathguard-monitor-state.json --evidence-db outputs/pathguard-evidence.sqlite --workspace judge-lab
```

Mỗi workspace ghi vào truy vấn riêng. Mã bằng chứng ổn định trong một snapshot để lượt phát lại không nhân đôi bản ghi. Thời gian truy vấn phải có múi giờ. Chạy một monitor writer trên mỗi file SQLite.

```powershell
python work/pathguard/evidence_store.py --db outputs/pathguard-evidence.sqlite query --workspace judge-lab --resource checkout-staging --start 2026-11-24T00:00:00Z --limit 50
python work/pathguard/evidence_store.py --db outputs/pathguard-evidence.sqlite coverage --workspace judge-lab
```

Đầu ra JSON chỉ đọc. Không cung cấp API mạng hoặc xác thực đa workspace cho người dùng cuối. Không ghi traffic, CI/CD, IAM hoặc hồ sơ vận hành vì những connector đó chưa được nối. SQLite là store phát triển/lab, chưa phải kho dùng chung cho nhiều replica hoặc triển khai đa vùng.

Chạy toàn bộ test cục bộ bằng `python -m unittest discover -s work/pathguard -p "test_*.py" -q`.

### Thu thập và giám sát Wallet lab trên AWS

Chạy một lượt, lưu phát hiện và bằng chứng vào state riêng:

```powershell
python work/pathguard/monitor.py --wallet-aws --once --state outputs/PathGuard-Wallet-Monitor-Live.json
```

Chế độ này dùng hai AWS CLI profile của lab. Nó đọc route hai phía, ingress hiệu lực tại ENI Ledger, Flow Logs S3, CloudTrail và lịch sử các CodePipeline PathGuard nếu có. Bật điều tra Bedrock bằng `--model-id`, `--region` và `--profile`. Bỏ `--once` để tiếp tục quét định kỳ. Trường `verification_scope` giới hạn kết luận tại điểm áp ingress TCP 8080 trên Ledger trong cụm giả lập.

Thêm `--operations-export <file.json>` để đọc hồ sơ phụ thuộc đã xác nhận từ nguồn vận hành đáng tin cậy. File là mảng JSON. Mỗi dòng có `id`, `destination` (`ledger-api`), `port` (`8080`), `source` (IPv4 CIDR), `classification` (`required` hoặc `obsolete`), `valid_from`, `valid_until` (ISO 8601 kèm múi giờ) và `confirmation_ref` (tham chiếu tới job, runbook, deploy hoặc xác nhận của owner). Dòng `obsolete` cần thêm `confirmed_obsolete: true`. Dùng phạm vi CIDR rời nhau. Bộ kiểm chứng yêu cầu hồ sơ bao phủ toàn bộ rule, đọc đủ các quyền thay thế và xác minh Security Group chỉ phục vụ ENI đích trước khi chấp nhận đề xuất. Log vắng, log chỉ có probe hoặc hồ sơ hết hạn vẫn dẫn đến yêu cầu xác minh. Luồng này chỉ đọc.

## Chạy với Bedrock

Cần Python, `boto3`, thông tin xác thực AWS và quyền gọi một model hoặc inference profile hỗ trợ tool use. Chạy từ thư mục workspace. Với thông tin xác thực mặc định, bỏ tham số `--profile`.

```powershell
python work/pathguard/agent.py --region YOUR_REGION --model-id YOUR_MODEL_OR_PROFILE_ID --profile YOUR_AWS_PROFILE
```

Kết quả JSON gồm quyết định, ID bằng chứng, lịch sử truy vấn và kết quả kiểm chứng nếu có đề xuất thay đổi. Ca mặc định dùng rule báo cáo AWS → on-prem và dữ liệu giả lập trong `fixtures/reporting.json`.

Dùng `--case work/pathguard/fixtures/hotfix.json` để điều tra quyền hotfix không có ticket hoặc `--case work/pathguard/fixtures/migration.json` để điều tra quyền còn sót sau khi di trú.

## Phạm vi tiếp theo

- Chạy ba ca demo bằng model thật và kiểm thử đủ tám ca trước khi công bố độ bao phủ.
- Kết nối dữ liệu thử nghiệm thật và đưa hồ sơ điều tra lên web với phân quyền theo workspace.
- Tạo báo cáo tuần theo workspace từ các hồ sơ đã lưu. Phân biệt đã đề xuất, đã áp dụng và đã kiểm chứng. Cho giám khảo tạo báo cáo ngay trong sandbox.

### Collector cho hybrid thật (đang chuẩn bị onboarding)

Thư mục `work/pathguard/collectors/` hiện có collector đọc inventory AWS Config Aggregator đa tài khoản/vùng theo kiểu streaming JSONL và collector site chỉ đọc cho host Linux/Kubernetes cùng file export đã chuẩn hóa từ firewall/flow logs. Collector site có thể ghi bundle lên S3 private với SSE-KMS qua AWS credential chain; triển khai thật nên dùng IAM Roles Anywhere `credential_process`, không đặt access key dài hạn lên máy vật lý.

Đây là nền connector, chưa được nối vào monitor/agent đang chạy và chưa có endpoint, aggregator hay collector vật lý nào được cấu hình trong tài khoản khách hàng. Xem [hướng dẫn thu thập hybrid và các giới hạn](collectors/README-hybrid-collection.md). Thiếu Flow Logs/CloudTrail/CI-CD/CMDB hoặc thiếu coverage phải giữ kết luận ở trạng thái chưa đủ bằng chứng.

### Change evidence contract (schema only)

`change_evidence.py` validates normalized Terraform plan/apply and Ansible check/job metadata before any connector exists. `wallet_monitor.scan(..., change_evidence=batch, change_scope={"tenant": ..., "site": ..., "environment": ...}, change_window_start=..., change_window_end=...)` is optional; existing callers need no changes. Batch fields are allowlisted (`schema_version=pathguard.change-evidence.v1`, source, scope, UTC observation window, collection time, coverage/drop/error metadata, and records). Records contain a stable `id`, kind, observation time, constrained outcome, resource references, and optional change reference. Unknown fields, raw payloads, secrets, state, variables, stdout, and arbitrary error text are rejected. Normalized IDs and coverage status appear in the agent's existing `changes` trace group.

`terraform_plan` and `ansible_check` are intent only. A successful Terraform apply or Ansible job is source-reported execution, not proof of final network configuration. AWS Config and CloudTrail remain authoritative observed state. External change events alone cannot authorize keep, narrow, or revoke; existing independent network and operations checks still apply. Incomplete, stale, invalid, empty, or loss-bearing feeds fail closed. This contract performs no connector calls or credential access.

# MOMO-CONTEST
