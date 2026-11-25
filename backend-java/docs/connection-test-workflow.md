# PathGuard: kiểm tra kết nối AWS và on-prem

## Mục tiêu người dùng

Trong giao diện, người quản trị chọn **Thêm kết nối → AWS** hoặc **Thêm kết nối → On-prem**, điền thông tin định danh cần thiết rồi bấm **Kiểm tra kết nối**. PathGuard trả về trạng thái, thời điểm kiểm tra và bằng chứng tối thiểu để giải thích trạng thái đó. Mỗi kết nối được gắn với tenant ở backend; người dùng không tự gửi `tenant_id` để chọn nơi lưu dữ liệu.

“Kết nối thành công” không đồng nghĩa đã thu thập đủ dữ liệu để dựng bản đồ. Kết quả cần tách riêng: xác thực được danh tính, đọc được nguồn nào, nguồn nào bị từ chối/thiếu cấu hình, và thời điểm dữ liệu gần nhất.

## AWS: AssumeRole và thu thập inventory từ AWS Config

### Luồng dự kiến

1. Người dùng đã đăng nhập vào tenant của mình và chọn `connectionId` cho account/connection trong tenant.
2. Tổ chức khách hàng tạo một IAM role chỉ đọc cho PathGuard. Trust policy giới hạn principal của PathGuard và External ID của kết nối. Không dùng access key dài hạn của người dùng.
3. Giao diện gọi `POST /api/v1/aws/connections/prepare` với `connectionId`. Backend tạo External ID xác định bằng HMAC, gắn với tenant và connection ID, rồi trả External ID để thêm vào trust policy.
4. Người dùng gửi `POST /api/v1/aws/connections/test` với ARN role, account ID mong đợi và Region. Backend dùng runtime identity để gọi STS `AssumeRole`, kiểm tra account, đọc trạng thái AWS Config recorder, liệt kê các resource đang được recorder theo dõi, rồi lấy cấu hình theo lô. Quy trình chỉ đọc, không bật Config, Flow Logs, VPC hay route.
5. Backend lưu snapshot theo tenant và `connectionId`. Có thể truy vấn snapshot gần nhất bằng `GET /api/v1/aws/connections/{connectionId}/inventory`.

Kết quả nên hiển thị từng bước, ví dụ:

| Kiểm tra | Ví dụ trạng thái |
|---|---|
| AssumeRole / xác thực tài khoản | Đạt / Sai account / AccessDenied |
| AWS Config recorder và inventory | Đang ghi / Dừng / Không thấy; số resource đã đọc |
| Độ phủ | `COMPLETE`, `PARTIAL` hoặc `UNKNOWN`, kèm loại resource thiếu và cảnh báo |

IAM policy role lab được sinh từ các lời gọi trong mã bằng IAM Policy Autopilot. Các hành động Config cần có là `DescribeConfigurationRecorders`, `DescribeConfigurationRecorderStatus`, `ListDiscoveredResources`, `BatchGetResourceConfig`. `BaseConfigurationItem` giữ cấu hình từng resource nhưng chưa chuẩn hóa tất cả liên kết thành cạnh service-to-service; Flow Logs và CloudTrail lịch sử chưa được thu thập. Vì vậy snapshot hỗ trợ dựng bản đồ cấu hình ban đầu, chưa đủ để AI kết luận phụ thuộc thực tế hay đề xuất thu quyền một cách tự tin.

## On-prem: collector trong mạng khách hàng chủ động gọi ra

PathGuard chạy trên cloud không thể tự kết nối vào IP private của khách hàng nếu không có VPN/Direct Connect và route/firewall tương ứng. Mặc định phù hợp cho sản phẩm cài ở nhiều tổ chức là **outbound-only collector**: khách hàng cài một container/service nhỏ trong vùng quản trị của họ; collector gọi HTTPS đến PathGuard. Không mở cổng inbound từ Internet vào mạng nội bộ.

### Luồng dự kiến

1. Quản trị viên tạo kết nối on-prem với `siteId` và, nếu cần, `zoneId`; backend phát enrollment token một lần, hết hạn sau thời gian ngắn.
2. Collector đổi token lấy credential riêng của collector rồi lưu trong secret store/file được giới hạn quyền đọc. Token không nằm trong log hay file cấu hình thường.
3. Collector kiểm tra từ bên trong mạng các adapter đã cấu hình (ví dụ CMDB/inventory, Kubernetes API, firewall export/API, flow-log export). Mỗi adapter báo riêng `accessible`, `permission_denied`, `not_configured` hoặc `error`.
4. Collector gửi heartbeat và normalized site evidence bundle qua HTTPS bằng cùng connector credential. Backend xác định tenant/site/zone từ credential, kiểm tra các tham chiếu site/zone trong bundle và không nhận tenant do collector khai báo.
5. UI báo **Collector online** khi heartbeat gần nhất đến trong cửa sổ cho phép; đồng thời liệt kê nguồn dữ liệu đọc được, lỗi và `last_seen`. “Online” không có nghĩa mọi nguồn đã đầy đủ.

### Contract trạng thái on-prem

Collector gửi heartbeat bằng connector bearer đã enrollment; request không được tự khai báo tenant hoặc site khác:

```http
POST /api/v1/site-connector/heartbeat
Authorization: PathGuardConnector <connector-token>
Content-Type: application/json
```

```json
{
  "checkedAt": "2026-11-24T12:00:00Z",
  "overallStatus": "PARTIAL",
  "sources": [
    {"name": "kubernetes", "status": "OK", "checkedAt": "2026-11-24T11:59:50Z"},
    {"name": "firewall-export", "status": "NOT_CONFIGURED", "checkedAt": "2026-11-24T11:59:50Z"},
    {"name": "cmdb", "status": "ERROR", "checkedAt": "2026-11-24T11:59:50Z", "errorCode": "AUTH_DENIED"}
  ]
}
```

Các trạng thái nguồn hợp lệ: `OK`, `UNAVAILABLE`, `ERROR`, `NOT_CONFIGURED`, `NOT_SELECTED`; trạng thái tổng thể: `OK`, `PARTIAL`, `FAILED`. Lỗi gửi về cần là mã đã làm sạch, không kèm token, mật khẩu, response body nhạy cảm hay cấu hình nội bộ. UI lấy trạng thái bằng `GET /api/v1/connectors/{connectorId}/status`; backend kiểm tra connector thuộc tenant trong JWT và trả 404 cho ID không thuộc tenant.

Để cài connector thật, xem [ONPREM-CONNECTOR-SETUP.md](../../collectors/ONPREM-CONNECTOR-SETUP.md). Phần cấu hình cần có `backend.base_url` và `backend.credential_file`; chuyển enrollment token một lần qua biến môi trường `PATHGUARD_ENROLLMENT_TOKEN`, không ghi token vào JSON. Collector đổi token lấy connector credential, lưu credential vào file giới hạn quyền, rồi gửi heartbeat và bundle. Sau bước đầu, các lần chạy tiếp theo dùng credential đã lưu. API trả số bản ghi, trạng thái coverage và bundle ID; bundle vượt giới hạn bị từ chối và collector báo lỗi.

Nếu cần truy vấn mạng trực tiếp từ PathGuard SaaS tới on-prem, khách hàng phải chủ động thiết lập private connectivity (VPN/Direct Connect) và chính sách định tuyến/tường lửa. Đó là phương án triển khai riêng, không phải giả định mặc định của collector.

## Nhiều tài khoản, VPC, site và môi trường

- Một tổ chức là một tenant. Mỗi AWS account/OU/aggregator hoặc on-prem site có connection record riêng dưới tenant đó.
- Tất cả VPC và resource con được gắn account + Region + resource ID; không tạo tenant mới cho mỗi VPC.
- `environment` (dev/staging/prod) nên đến từ tag/config mapping đã được xác nhận. Không suy ra môi trường chỉ từ tên VPC hay CIDR.
- UI cần hiển thị tổng độ phủ: số account/Region/site dự kiến, đã kết nối, đã thu thập gần nhất và đang thiếu. Connector token chỉ được phép gửi đúng loại và phạm vi đã enrollment.

## Chạy backend local bằng Docker

Từ thư mục `work/pathguard/backend-java`, Compose dựng PostgreSQL, Spring Boot API và Keycloak với realm local để kiểm thử đăng nhập:

```powershell
if (-not $env:PATHGUARD_AWS_EXTERNAL_ID_HMAC_SECRET) { $env:PATHGUARD_AWS_EXTERNAL_ID_HMAC_SECRET = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) }
docker compose up --build -d
docker compose logs -f api
```

`PATHGUARD_AWS_EXTERNAL_ID_HMAC_SECRET` được tạo ngẫu nhiên trong PowerShell; giữ nguyên giá trị khi khởi động lại vì đổi secret sẽ đổi External ID và làm trust policy role không còn khớp. Không đưa secret này vào Git; production phải lấy từ secret manager. Local Keycloak có sẵn user `demo-admin` / `pathguard-demo-only`, tenant UUID `00000000-0000-0000-0000-000000000001`, chỉ dùng trên máy local. **Không dùng thông tin này ở môi trường thật.** Health endpoint công khai tại `http://localhost:8080/actuator/health`. API không có chế độ giả lập tenant bằng header. Để AWS test gọi AWS thật, API container phải có runtime credentials của sandbox backend identity; local Compose hiện không tự cấp AWS credentials. `docker compose down` chỉ dừng dịch vụ; dữ liệu Postgres vẫn nằm trong volume trừ khi volume bị xóa.

Health check công khai:

```powershell
curl.exe http://localhost:8080/actuator/health
```

`/actuator/health` chỉ chứng minh ứng dụng đang chạy, không chứng minh AWS/on-prem đã kết nối.

Lấy JWT cho các API local (giữ token trong biến, không commit hay ghi log):

```powershell
$tokenResponse = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8081/realms/pathguard/protocol/openid-connect/token" -ContentType "application/x-www-form-urlencoded" -Body @{ grant_type = "password"; client_id = "pathguard-local-cli"; username = "demo-admin"; password = "pathguard-demo-only" }
$jwt = $tokenResponse.access_token
```

## AWS connection-test API

Cả hai route cần JWT hợp lệ từ tenant admin. Trước hết yêu cầu External ID của kết nối:

```http
POST /api/v1/aws/connections/prepare
Authorization: Bearer <tenant-admin-jwt>
Content-Type: application/json
```

```json
{"connectionId":"aws-prod-account-1"}
```

Response có `connectionId`, `externalId`, `instruction`. Backend suy ra External ID từ tenant ID đã xác thực và connection ID bằng HMAC-SHA256; không tin tenant ID từ body. Secret HMAC phải được đặt ở `PATHGUARD_AWS_EXTERNAL_ID_HMAC_SECRET`, có ít nhất 32 ký tự ngẫu nhiên, lưu trong secret manager và giữ ổn định giữa các replicas. Nếu thiếu secret, API trả `503`. Chỉ chia sẻ External ID với trust policy của role tương ứng và yêu cầu role trust kiểm tra `sts:ExternalId`.

Sau khi customer role trust policy được cài đặt, chạy probe chỉ đọc:

```http
POST /api/v1/aws/connections/test
Authorization: Bearer <tenant-admin-jwt>
Content-Type: application/json
```

```json
{
  "connectionId": "aws-prod-account-1",
  "roleArn": "arn:aws:iam::123456789012:role/PathGuardReadOnly",
  "expectedAccountId": "123456789012",
  "region": "ap-southeast-1",
  "aggregatorName": "pathguard-org-aggregator"
}
```

Response thực tế gồm `identityVerified`, `configApiReachable`, `resourceCount`, `auditEventCount`, `flowRecordCount`, `coverageStatus`, `snapshotId`, `missingResourceTypes` và `warnings`. `connectionReady` chỉ nói role được xác minh và inventory có ít nhất một tài nguyên; không có nghĩa tất cả nguồn dữ liệu đã đầy đủ. Không gửi access key/secret key. AWS test chỉ hoạt động nếu runtime identity của backend được cấu hình và có `sts:AssumeRole`; customer role phải trust đúng principal và External ID.

Hiện test route gắn request với `connectionId` và suy ra External ID phía server, nhưng vẫn chỉ chạy probe theo request: chưa persist cấu hình connection hay trạng thái test gần nhất để UI truy vấn sau. Đây là phần còn cần hoàn thiện cho trải nghiệm nhiều account bền vững.

**Phạm vi hiện tại:** endpoint AssumeRole và đọc AWS Config để lấy network inventory, lấy Flow Log definitions từ EC2, đọc tối đa 7 ngày Flow Logs từ các đích CloudWatch Logs/S3 đã cấu hình, và truy vấn tối đa 90 ngày sự kiện thay đổi được chọn từ CloudTrail. Collector có giới hạn số sự kiện/stream/object để tránh tải dữ liệu không giới hạn. Xem [AWS connection and network inventory](aws-connection-test.md) để biết IAM action, giới hạn và phần còn thiếu. Cần kiểm tra `coverageStatus`, cảnh báo và thời gian cửa sổ trước khi diễn giải kết quả; một lần chạy sandbox xác nhận quyền và dữ liệu của đúng tài khoản đó, không khẳng định độ phủ toàn tổ chức.

## API hiện có và giới hạn của bản hiện tại

Đăng ký connector hiện cần JWT hợp lệ từ OIDC và role `TENANT_ADMIN`:

```http
POST /api/v1/connectors/enrollments
Authorization: Bearer <tenant-admin-jwt>
Content-Type: application/json
```

AWS body:

```json
{"connectorType":"AWS","connectionId":"aws-prod","expiresInSeconds":600}
```

On-prem body:

```json
{"connectorType":"ON_PREM","siteId":"dc-hcm-1","zoneId":"prod","expiresInSeconds":600}
```

Connector đổi enrollment token một lần qua `POST /api/v1/connectors/enroll`. AWS probe là `POST /api/v1/aws/connections/prepare` rồi `POST /api/v1/aws/connections/test`. On-prem collector gửi heartbeat qua `POST /api/v1/site-connector/heartbeat` và bundle qua `POST /api/v1/evidence/bundles`. Người dùng xem trạng thái tenant-scoped bằng `GET /api/v1/connectors/{connectorId}/status` và các bundle đã nhận bằng `GET /api/v1/evidence`.

Human endpoints dùng OIDC issuer nội bộ `http://keycloak:8080/realms/pathguard` trong Compose. Realm fixture ánh xạ `tenant_id` và `TENANT_ADMIN` vào access token. Compose cấp thông tin đăng nhập demo chỉ phục vụ local; production phải thay bằng OIDC thật và không dùng user/mật khẩu demo.

## Điều kiện để chứng minh kết nối thật

- **AWS:** cần một AWS account sandbox, IAM role trust đúng principal/External ID, quyền read-only tối thiểu, Config aggregator hoạt động, và backend được triển khai với runtime identity có quyền `AssumeRole`. Chỉ test trong tài khoản được phép.
- **On-prem:** cần collector chạy được trong một VM/VPS/container đại diện cho mạng on-prem, có DNS/HTTPS outbound tới backend và quyền đọc ít nhất một nguồn dữ liệu thử nghiệm. Backend SaaS không thể tự chứng minh quyền truy cập vào mạng riêng khi collector chưa chạy.
- **Cả hai:** hiển thị trạng thái từng nguồn cùng timestamp và lỗi cụ thể; không báo “đã kết nối đầy đủ” chỉ dựa trên HTTP 200 hoặc heartbeat.
