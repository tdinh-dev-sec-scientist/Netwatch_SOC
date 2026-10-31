# NetWatch — Thẩm định kế hoạch phát triển & Kế hoạch v2

*30/10/2026 · Thẩm định bản "NetWatch Product & Engineering Development Plan"
(24 tuần), đối chiếu với code và kết quả đang có trong repo này.*

---

## TL;DR

- **Kế hoạch gốc tốt về kỹ thuật nhưng yếu về sản phẩm.** Nếu chấm như một
  kế hoạch kỹ thuật: ~80/100. Nếu chấm như kế hoạch startup: ~46/100 (thang điểm ở mục 9).
- **Hướng đi (detection validation) đúng.** Cách thực hiện thì chưa: kế hoạch
  vẫn tiếp tục xây một IDS/NDR (runtime, incident, multi-user, AI assistant)
  trong khi luận điểm của chính nó là *đo chất lượng detection*.
- **Ba lỗi chiến lược:** (1) NetWatch vừa là thí sinh vừa là giám khảo; (2)
  phỏng vấn người dùng bị đẩy xuống tuần 19–24; (3) không nói rõ ai trả
  tiền, vì sao là bây giờ, và cái gì khó sao chép.
- **Định vị đề xuất:** *"pytest + CI cho network detection"*: một công cụ
  không phụ thuộc engine, chấm Suricata/Zeek/Snort/NetWatch trên cùng một
  bộ PCAP có ground truth, đo độ phủ, tiếng ồn, độ giòn (mutation) và regression,
  kèm bằng chứng tái lập được. Lý do làm bây giờ: **luật detection do AI
  viết đang tăng nhanh, và cần một bộ kiểm chứng (test oracle) độc lập trước khi đưa lên production.**
- **Kế hoạch v2: 12 tuần, một người**, discovery chạy song song từ tuần 1,
  có kill criteria bằng con số, và một deliverable công khai (báo cáo benchmark
  mở + talk) để tối đa ảnh hưởng dù startup thành hay không.

---

## 1. Độ khả thi

### 1.1 Cái đã có sẵn (kế hoạch gốc đánh giá thấp)

Phase 0–1 của kế hoạch gốc phần lớn **đã tồn tại** trong `eval/cicids2018/`:

| Kế hoạch gốc yêu cầu | Đã có trong repo |
|---|---|
| Evaluation runner trên PCAP cố định | `run.py`: replay song song, mỗi capture một detector instance |
| Ground truth, khớp alert ↔ scenario | `ground_truth.json`, `match_scenario()`: cửa sổ thời gian, attacker/victim, pivot |
| Tách dev / holdout | `holdout.json`, `holdout2.json`; code đóng băng trước khi replay holdout |
| Per-scenario metrics, FP/host-hour, nguyên nhân FP | `score()`, `fp_cause()`, `report.md`, `summary.json` |
| So sánh chéo engine | `suricata.py`: ET Open, có và không có engine-anomaly events |
| Regression test cho bug đã sửa | `tests/test_real_traffic_regressions.py` |

**Hệ quả:** Phase 0–1 (6 tuần) có thể rút xuống khoảng 3 tuần. Việc thật sự còn thiếu
là *tổng quát hoá* harness, vì hiện nó gắn chặt với CIC-IDS2018 và với taxonomy của NetWatch.

### 1.2 Cái không khả thi

| Hạng mục | Vấn đề |
|---|---|
| 24 tuần, 5 phase, cho 1 người (đang học + tìm việc) | Khối lượng tương đương 2–3 kỹ sư. Phase 3 (secure multi-user deployment) và Phase 4 (AI assistant có retrieval boundary, prompt-injection testing) mỗi cái tự nó đã là một dự án. |
| Python IDS làm runtime production | 5.873 pkt/s ≈ vài chục Mbps. Suricata chạy multi-Gbps. Đầu tư "runtime reliability" cho engine này không bao giờ cạnh tranh được, và cũng không cần. |
| Phase 5 mới phỏng vấn | Nếu giả thuyết về pain sai thì 18 tuần trước đó là chi phí chìm. |

### 1.3 Kết luận khả thi

Kỹ thuật: **khả thi cao**, vì phần khó nhất (harness có ground truth, kỷ luật holdout)
đã làm xong. Phạm vi: **không khả thi** như đang viết, phải cắt khoảng 50%.

---

## 2. Ứng dụng thực tế: ai đau, đau ở đâu

### 2.1 Câu hỏi sản phẩm phải trả lời được

1. **Coverage:** Rule/detector của tôi có bắt được tấn công X không? Còn các biến thể của X thì sao?
2. **Noise cost:** Trên traffic bình thường của tôi, nó tốn bao nhiêu false alert mỗi host-hour?
3. **Regression:** Lần đổi rule, đổi engine hay đổi config này có làm hỏng gì không?
4. **Brittleness:** Attacker chỉ cần đổi nhịp, cổng, fragment hay encoding là qua mặt được?
5. **So sánh:** Với *traffic của tôi*, engine/ruleset nào phủ được technique nào, và có bằng chứng không?
6. **Bằng chứng:** Tôi có chứng minh được với auditor, khách hàng hay sếp rằng detection hoạt động không?

### 2.2 Người dùng và người trả tiền (kế hoạch gốc thiếu phần này)

| Phân khúc | Pain cụ thể | Khả năng trả tiền | Ưu tiên |
|---|---|---|---|
| **Detection engineer ở MSSP / SOC lớn** có custom Suricata rules | Đổi rule xong không biết có phá rule cũ không; test bằng script tự viết + Dalton | Trung bình–cao (ruleset chính là sản phẩm của MSSP) | **Wedge #1** |
| **Nhà cung cấp rule feed / NDR** (loại Proofpoint ET, Stamus, Corelight) | QA regression cho hàng nghìn rule mỗi tuần | Cao, nhưng họ thường tự xây | Design partner / bên mua lại tiềm năng |
| **Team dùng AI để sinh rule** | Rule do LLM viết trông hợp lý nhưng chưa ai kiểm chứng | Đang hình thành, tăng nhanh | **"Why now"** |
| Tổ chức chịu NIS2 / DORA / TIBER-EU / PCI DSS 11.5 | Cần bằng chứng rằng năng lực phát hiện đã được kiểm thử | Cao, nhưng chu kỳ bán dài | Giai đoạn sau |
| Giảng dạy / CTF / blue-team training | Thiếu bài tập detection có chấm điểm khách quan | Thấp | Kênh phân phối và cộng đồng |

### 2.3 Đối thủ thật (kế hoạch gốc nói chung chung "đã có sản phẩm")

| Công cụ | Làm được gì | Không làm |
|---|---|---|
| `suricata-verify` (OISF) | Regression test cho *chính engine Suricata*: PCAP + output mong đợi | Không có ground truth tấn công, không đo noise trên benign, chỉ một engine |
| Dalton (Secureworks) | Chạy rule Suricata/Snort/Zeek trên PCAP, xem alert | Không chấm điểm, không holdout, không regression gate |
| Splunk `attack_range` / `attack_data` | Detection-as-code + CI cho detection dựa trên **log** | Không tập trung vào network/PCAP |
| BAS (AttackIQ, SafeBreach, Picus, Cymulate…) | Mô phỏng tấn công trên hạ tầng **đang chạy** | Đắt, cần agent, kiểm thử control trong production chứ không phải logic rule trước khi deploy |
| Dataset học thuật (CIC, UNSW-NB15, CTU-13) | Dữ liệu | Có lỗi nhãn đã được công bố (Engelen et al. 2021; Liu et al. 2022 về CIC-IDS2017/2018), không có tooling |

**Khoảng trống thật**, hẹp nhưng có thật: *chấm điểm network detection không phụ
thuộc engine, dựa trên ground truth, có noise budget trên benign, có mutation và
regression gate trong CI, có bằng chứng tái lập được.* Hiện chưa công cụ mở nào gộp đủ các phần này.

---

## 3. Đây đã phải là hướng đi tốt nhất chưa? Chưa. Sáu điểm cần sửa

### 3.1 Xung đột lợi ích: thí sinh không được làm giám khảo
Bảng "6/6 vs 3/6" do chính tác giả của NetWatch chấm, trên dataset mà NetWatch đã được
tune (dev và holdout cùng một mạng lab 2018), với taxonomy scoring do NetWatch đặt ra.
Người ngoài sẽ không tin số này, dù nó trung thực.
**Sửa:** sản phẩm là *giám khảo*. Detector NetWatch hạ xuống thành
"reference behavioural engine", tức một adapter như mọi engine khác.

### 3.2 Con số chủ lực chưa có ý nghĩa thống kê
6/6 so với 3/6: Fisher exact two-sided **p ≈ 0,18**. Khoảng tin cậy Wilson 95%:
NetWatch [0,61; 1,00], Suricata [0,19; 0,81]. Hai khoảng chồng nhau.
FP/host-hour 1,0 so với 26,7 có sức nặng hơn, nhưng so với Suricata *chưa tune* thì chưa công bằng.
**Sửa:** báo cáo luôn kèm CI. Thêm cột "Suricata sau cùng ngân sách tuning"
(ví dụ suppress top-N signature ồn nhất trên tập dev). Thêm một **dataset khác hẳn**
(cross-dataset), vì holdout cùng mạng chưa kiểm tra được distribution shift.

### 3.3 Discovery đặt sai chỗ
**Sửa:** phỏng vấn từ tuần 1, song song với code. Pivot hay dừng dựa trên ngưỡng định lượng (mục 6).

### 3.4 Scope creep ngược với thesis của chính kế hoạch
Phase 2 (runtime backpressure), Phase 3 (incident intelligence, secure multi-user)
và Phase 4 (AI investigation assistant) đều là xây NDR.
**Sửa:** dừng hẳn. Mọi tính năng phải trả lời được một trong sáu câu hỏi ở mục 2.1.

### 3.5 AI đặt sai vai
Kế hoạch gốc dùng AI làm "assistant", tức một tính năng phụ.
**Sửa:** AI là *nguồn nhu cầu*. Có càng nhiều rule do máy viết thì càng cần một bộ kiểm chứng
tự động. NetWatch là cổng kiểm duyệt: *"No AI-written rule ships without a
scorecard."* Tính năng AI duy nhất nên làm sớm là ngược chiều: cho AI sinh **biến thể tấn công**
để tìm chỗ rule bị giòn.

### 3.6 Không có moat
Code chấm điểm thì ai cũng viết lại được. Thứ khó sao chép là:
1. **Corpus đã được sửa nhãn, có version, có biến thể** (scenario packs).
2. **Ground truth tự sinh theo cách xây dựng:** lab docker tự chạy attack tool, tự capture và tự gắn nhãn,
   nên không còn phải dò nhãn bằng tay như CIC.
3. **Báo cáo benchmark mở hằng năm** được cộng đồng trích dẫn, trở thành chuẩn tham chiếu.
4. **Vị trí trong CI** của người dùng (switching cost).

---

## 4. Định vị sản phẩm v2

> **NetWatch Bench: CI cho network detection.**
> Đưa vào một PCAP có nhãn và một rule. Nhận về một scorecard: rule bắt được gì,
> bỏ sót gì, tốn bao nhiêu noise, bị qua mặt khi nào, và lần đổi này có
> làm hỏng gì không. Mỗi con số trỏ ngược về được bằng chứng của nó.

### 4.1 Vòng lặp cốt lõi

```
scenario pack (pcap + truth.yaml + benign background)
        │
        ▼
engine adapters ── suricata │ zeek │ snort │ netwatch-ref │ custom
        │            (cùng PCAP, cùng ranh giới, ghi lại version/config/hash)
        ▼
normalized findings ──► matcher (unit: scenario │ flow │ alert, không trộn)
        │
        ▼
scorecard: coverage±CI · FP/host-hour · latency · mutation score · Δ vs baseline
        │
        ├──► report.md / summary.json / SARIF
        └──► CI gate: fail nếu coverage giảm hoặc noise vượt budget
```

### 4.2 Lệnh người dùng chạy (giao diện sản phẩm là CLI, không phải dashboard)

```bash
netwatch-bench run    --engine suricata --rules local.rules --pack packs/web-attacks
netwatch-bench diff   --baseline main --candidate HEAD       # regression gate
netwatch-bench mutate --pack packs/bruteforce --budget 50    # độ giòn của rule
netwatch-bench report --format md,json,sarif
```

### 4.3 Tính năng tạo khác biệt (theo thứ tự)

1. **Noise budget:** FP/host-hour trên benign background của chính người dùng, chạy cục bộ, dữ liệu không rời máy.
2. **Regression gate** dưới dạng GitHub Action: so với baseline đã pin, ngưỡng cấu hình được.
3. **Mutation testing cho detection:** biến đổi traffic tấn công (timing jitter, tốc độ,
   cổng, IP fragmentation, TCP segmentation, đổi user-agent, encoding payload, bọc TLS),
   rồi báo "rule chịu được 7/12 biến thể". Đây là tính năng chưa công cụ mở nào có.
4. **Provenance manifest:** sha256 của PCAP, ruleset, binary engine, config, seed, môi trường.
   Có thể ký bằng Sigstore để làm bằng chứng cho auditor.
5. **Coverage map ATT&CK có bằng chứng:** mỗi ô trỏ về PCAP và alert đã chứng minh nó, không dựa trên
   khai báo của vendor.

### 4.4 Không làm (ít nhất 6 tháng)

Dashboard mới, thêm detector, live capture, multi-tenant SaaS, Kubernetes, AI
investigation assistant, Splunk features mới, tối ưu throughput của Python engine.

---

## 5. Kế hoạch 12 tuần (thay cho 24 tuần)

Mỗi giai đoạn có **một deliverable công khai**, để thứ gì cũng tạo ra
ảnh hưởng ngay cả khi phần sau không thành.

### Tuần 1–3: Tách giám khảo khỏi thí sinh + discovery
- Trích `eval/cicids2018/` thành package `netwatch_bench/`: `engines/` (adapter
  Suricata, NetWatch-ref), `matching/`, `metrics/`, `manifest/`. Harness cũ thành pack đầu tiên.
- Định nghĩa `truth.yaml` v0: scenario, windows, attackers/victims, expected
  technique (không dùng tên threat_type của NetWatch, chỉ dùng ATT&CK để trung lập với engine).
- Metric contract bằng văn bản: detection, FP, host-hour, unit, matching window. Thêm Wilson CI.
- **Discovery:** 15 cuộc trò chuyện 20 phút (OISF forum/Discord, r/blueteamsec,
  LinkedIn detection engineers, cựu đồng nghiệp MSSP). Dùng bộ câu hỏi mục 14 của kế
  hoạch gốc, vì bộ đó viết rất tốt.
- **Public:** repo `netwatch-bench` v0.1 + README có 1 GIF chạy 60 giây.

### Tuần 4–6: Regression gate + engine thứ ba
- `diff` + GitHub Action + output SARIF (hiện ngay trong tab Security của GitHub).
- Adapter Zeek (notice.log / weird.log) để chứng minh không phụ thuộc engine.
- Docker image pin version, đảm bảo `make reproduce` từ clean checkout cho ra đúng số.
- **Fix fairness:** cột "Suricata tuned trên dev" + một dataset thứ hai (ví dụ CTU-13
  hoặc capture lab tự sinh) cho cross-dataset.
- **Public:** blog "I benchmarked my own IDS against Suricata, then tried to
  prove myself wrong", kể lại câu chuyện p ≈ 0,18. Bài kiểu này tạo uy tín cao hơn khoe 6/6.

### Tuần 7–9: Mutation + ground truth tự sinh
- `mutate`: 8–12 phép biến đổi PCAP, tính mutation score cho từng rule.
- Lab `docker compose` attacker/victim/tcpdump: chạy kịch bản (hydra, nmap,
  slowloris, sqlmap, beacon giả lập), nhãn sinh tự động từ log của attacker.
- 10 scenario mới, trong đó vài cái theo CVE web 2025–2026, kèm benign background.
- **Public:** pack mở CC-BY + datasheet (nguồn, giới hạn, license).

### Tuần 10–12: Báo cáo mở + design partners + quyết định
- **"Open Network Detection Benchmark 2026":** ET Open, Zeek, NetWatch-ref, và nếu
  được thì một ruleset do LLM sinh. Có methodology, CI, per-scenario, mutation score.
- Gửi talk: SuriCon, BSides, Black Hat/DEF CON Arsenal (tool demo).
- 3 design partner chạy trên PCAP của chính họ, có tiêu chí thành công thoả thuận trước.
- **Decision gate** (mục 6).

---

## 6. Kill criteria và chỉ số

**North-star:** số *evaluation run do người ngoài thực hiện mỗi tuần*. GitHub stars
không phải north-star.

| Mốc | Tiếp tục nếu | Pivot hoặc dừng nếu |
|---|---|---|
| Hết tuần 3 (15 cuộc trò chuyện) | ≥ 5 người kể được *một lần cụ thể* gần đây rule hỏng hoặc gây ồn mà không ai biết trước | < 3 người, khi đó pivot sang hướng *training/education corpus* |
| Hết tuần 6 | ≥ 2 người ngoài tự chạy được `run` mà không cần hỏi | 0 người, nghĩa là vấn đề nằm ở onboarding, sửa trước rồi mới làm tính năng mới |
| Hết tuần 12 | ≥ 1 design partner chạy ≥ 2 lần trên dữ liệu của họ hoặc gắn vào CI | 0 người, dừng hướng sản phẩm, giữ project làm portfolio và nghiên cứu |
| Tín hiệu thương mại | ≥ 1 người hỏi về license, hosted runner, hoặc pack trả phí | Không có ai, giữ mô hình OSS thuần |

---

## 7. Nếu coi là startup: mô hình và tầm nhìn

- **Open-core:** CLI, adapter, pack công khai miễn phí (tạo phân phối và uy tín).
  Thu tiền ở: (a) *scenario feed* cập nhật hằng tuần theo CVE mới, tức "test feed" song
  hành với rule feed; (b) runner on-prem cho corpus riêng, phân quyền, báo cáo
  ký số cho audit; (c) dịch vụ benchmark độc lập cho vendor.
- **Thị trường:** ngách. Trung thực mà nói, đây khó thành công ty venture-scale đứng một mình. Lối ra
  thực tế là một công cụ OSS được dùng rộng, rồi được thuê hoặc mua lại bởi một vendor NDR hoặc rule feed.
  Đây vẫn là kết quả rất tốt cho một founder-sinh viên.
- **Why now:** detection-as-code đã phổ biến. Rule do LLM sinh tăng nhanh. NIS2 và DORA
  đòi bằng chứng kiểm thử. Mã hoá lan rộng làm signature-only giòn hơn, nên cần đo được hiệu quả.

---

## 8. Tác động đến sự nghiệp (mục tiêu ngầm, nhưng quan trọng)

Hướng v2 tối đa hoá ảnh hưởng ở cả hai kịch bản:

- **Nếu startup không thành:** vẫn có một tool OSS, một báo cáo benchmark có methodology,
  một talk và một dataset. Đây đúng là bộ kỹ năng mà vị trí *Detection Engineer* tuyển
  (detection-as-code, testing, đo lường), giá trị hơn nhiều so với "đã viết một IDS bằng Python".
- **Nếu thành:** bắt đầu với người dùng thật, câu chuyện thật, và một chuẩn tham chiếu do chính bạn đặt ra.

---

## 9. Thang điểm

| Tiêu chí (10đ mỗi mục) | Kế hoạch gốc | Kế hoạch v2 |
|---|---|---|
| Vấn đề rõ ràng | 7 | 9 |
| Khách hàng / người trả tiền cụ thể | 3 | 8 |
| Khác biệt & moat | 5 | 8 |
| Khả thi với nguồn lực thật (1 người) | 4 | 8 |
| Trình tự (validate trước, build sau) | 4 | 9 |
| Độ chặt của methodology | 9 | 10 |
| Mục tiêu đo được + kill criteria | 4 | 9 |
| Phân phối / GTM | 2 | 8 |
| Tận dụng tài sản đang có | 6 | 9 |
| Why now | 2 | 8 |
| **Tổng (/100)** | **46** | **86** |

*Phần còn thiếu để lên 100 không viết ra trên giấy được: đó là bằng chứng từ
người dùng thật ở tuần 3, 6 và 12. Một kế hoạch chỉ đạt 100 khi thị trường đã xác nhận nó.*

---

## 10. Việc làm ngay tuần này

1. Tạo `netwatch_bench/` và di chuyển `match_scenario`, `score`, `fp_cause` vào đó, giữ nguyên test.
2. Viết `docs/strategy/metric-contract.md` (1 trang).
3. Thêm Wilson CI vào `render()`, cập nhật README: ghi "6/6 [0,61–1,00]" thay vì chỉ "6/6".
4. Gửi 15 tin nhắn xin 20 phút phỏng vấn, hỏi về workflow chứ không pitch.
5. Viết `truth.yaml` v0 cho 3 scenario CIC đầu tiên theo dạng trung lập với engine.
