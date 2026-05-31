# مراجعة الكود — Siyaj SecureConfig Auditor v1.0

---

## نتيجة المراجعة الإجمالية

أُجريت **جولتان**: مراجعة كود أولى (9 ملاحظات)، ثم مراجعة ثانية بعد الاختبار الفعلي كشفت 4 ملاحظات مفهومية إضافية (انظر القسم 9). **جميع الـ13 عُولِجت في النسخة الحالية.**

| المستوى | الجولة 1 | الجولة 2 (بعد الاختبار) | الإجمالي |
|---------|:--------:|:----------------------:|:--------:|
| حرج / خطير | 3 | 1 | 4 |
| متوسط | 3 | 2 | 5 |
| منخفض | 3 | 1 | 4 |

> ملاحظة على الاتجاه: الملاحظات الخطيرة في الجولة 1 كانت **False PASS** (اتجاه خطير — طمأنينة كاذبة). أما ملاحظات الجولة 2 فكلها في الاتجاه **الآمن** (False FAIL / تشدّد زائد) — تمسّ عدالة الدرجة لا موثوقيتها.

---

## 1. main.py — نقطة الدخول

### ماذا يفعل؟
- يستقبل المعاملات من المستخدم عبر `argparse`
- يحمّل قواعد CIS من `cis_rules.json`
- يستدعي وحدات الفحص حسب الخيار المختار
- يحسب الدرجات ويعرضها، ويصدّر التقرير إن طُلب

### المشاكل

#### [MEDIUM] لا يتحقق من صلاحية root قبل التشغيل
```python
# الكود الحالي — لا يوجد فحص للصلاحيات
def main():
    print_banner()
    rules = load_rules()
    run_audit(args.audit, rules, args.output)
```
**المشكلة:** الأداة تحتاج `sudo` للوصول لـ `/etc/shadow` و`sudoers`.
إذا شغّلها المستخدم بدون `sudo`، ستنجح بعض الفحوصات بشكل **خاطئ** (false PASS)
لأن أخطاء القراءة تُكتم بصمت داخل وحدات أخرى.

**الحل:**
```python
import os, sys

def main():
    if os.geteuid() != 0:
        print("[ERROR] This tool must be run as root: sudo python3 main.py")
        sys.exit(1)
    ...
```

#### [LOW] لا يوجد exit code بناءً على النتيجة
**المشكلة:** الأداة دائماً تخرج بكود `0` (نجاح)، حتى لو كانت النتيجة "Critical".
هذا يمنع استخدامها في CI/CD pipelines.

**الحل:**
```python
score = run_audit(args.audit, rules, args.output)
sys.exit(0 if score >= 60 else 1)
```

---

## 2. ssh_audit.py — فحص SSH

### ماذا يفعل؟
- يفتح `/etc/ssh/sshd_config` ويقرأه سطراً بسطر
- يتجاهل التعليقات والأسطر الفارغة
- يقارن كل إعداد بالقيمة المتوقعة من `cis_rules.json`
- يدعم مقارنتين: مساواة (`eq`) وأصغر أو يساوي (`lte`)

### المشاكل

#### [CRITICAL] فحص `Protocol` قديم ومُضلِّل
**المشكلة:** الإعداد `Protocol` حُذف من OpenSSH منذ الإصدار 7.0 (عام 2015).
أي سيرفر Ubuntu/Debian/Kali حديث **لن يحتوي على هذا السطر**،
فالأداة ستعطي دائماً `WARN - Not set in config` رغم أن النظام آمن تلقائياً لأنه يدعم SSH2 فقط.

```
[WARN] Protocol: Not set in config (expected: 2)  ← مضلل، النظام آمن فعلياً
```

**الحل:** إما حذف هذا الفحص من `cis_rules.json`، أو تعديل المنطق ليعطي PASS عند غياب الإعداد:
```python
# في ssh_audit.py، بعد قراءة actual:
if actual is None:
    # Protocol absent = SSH2 only (safe by default on modern OpenSSH)
    if key == "Protocol":
        status, detail, earned = "PASS", "Not in config (SSH2 default)", weight
    else:
        status, detail, earned = "WARN", f"Not set (expected: {expected})", 0
```

#### [MEDIUM] لا يتبع إعدادات `Include`
**المشكلة:** الكود الحالي يقرأ ملف واحد فقط. لكن sshd_config الحديث يدعم:
```
Include /etc/ssh/sshd_config.d/*.conf
```
أي أن الإعدادات قد تكون موزعة على ملفات متعددة، والأداة لن ترى تلك الإعدادات.

**الحل:**
```python
def _parse_sshd_config(path):
    config = {}
    _read_config_file(path, config)
    return config

def _read_config_file(path, config):
    import glob
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("include "):
                pattern = line.split(None, 1)[1].strip()
                for included in sorted(glob.glob(pattern)):
                    _read_config_file(included, config)
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].lower() not in config:
                # sshd uses FIRST occurrence wins
                config[parts[0].lower()] = parts[1].strip()
```

#### [LOW] آخر قيمة تفوز، لكن sshd يستخدم أول قيمة
**المشكلة:** إذا تكرر إعداد في الملف، الكود يحفظ **آخر** قيمة، لكن sshd يعتمد **أول** قيمة.
الحل في الكود أعلاه: `if parts[0].lower() not in config`.

---

## 3. firewall_audit.py — فحص الجدار الناري

### ماذا يفعل؟
- يتحقق من أن UFW نشط
- يتحقق من أن السياسة الافتراضية للاتصالات الواردة هي `deny`
- يتحقق من أن المنافذ الخطرة (21، 23، 3389...) مغلقة

### المشاكل

#### [LOW] كشف المنافذ قد يفوّت بعض الحالات
**المشكلة:** الكود يبحث عن `":port "` أو `":port\t"` في مخرجات `ss`.
على بعض الأنظمة قد يكون الفاصل مختلفاً، أو تكون المنافذ مرتبطة بـ IPv6 (`:::21`).

```python
# الكود الحالي
return [p for p in ports if f":{p} " in out or f":{p}\t" in out]
```

**اختبار:** `:::21` لا يحتوي على مسافة بعد المنفذ مباشرة في بعض صيغ الإخراج.

**الحل الأكثر أماناً:**
```python
import re

def _open_dangerous_ports(ports):
    out = _run("ss -tlnp")
    if not out.strip():
        out = _run("netstat -tlnp")
    open_ports = []
    for p in ports:
        if re.search(rf"[:\s]{p}[\s\t]", out):
            open_ports.append(p)
    return open_ports
```

**ملاحظة:** استخدام `shell=True` في `_run()` آمن هنا لأن جميع الأوامر نصوص ثابتة لا يدخل عليها المستخدم.

---

## 4. users_audit.py — فحص المستخدمين

### ماذا يفعل؟
- يتحقق من أن حساب root مقفل
- يبحث عن حسابات بـ UID=0 غير root
- يبحث عن حسابات بكلمة مرور فارغة عبر `/etc/shadow`
- يبحث عن قواعد `NOPASSWD` في ملفات sudoers

### المشاكل

#### [CRITICAL] False PASS عند غياب الصلاحيات
**المشكلة الأخطر في المشروع:**

```python
def _empty_passwords():
    accounts = []
    try:
        with open("/etc/shadow", "r") as f:
            ...
    except OSError:
        pass          # ← يُكتم الخطأ بصمت
    return accounts   # ← يُعيد قائمة فارغة = PASS !!
```

نفس المشكلة في `_nopasswd_sudo()`.

**إذا شُغّلت الأداة بدون sudo:**
- لا يمكن قراءة `/etc/shadow` → `PermissionError` يُكتم
- `_empty_passwords()` تُعيد `[]` → نتيجة `PASS`
- المستخدم يعتقد أنه لا توجد كلمات مرور فارغة، لكن الفحص لم يجرِ أصلاً

**الحل:** التمييز بين "لا توجد مشاكل" و"لم نستطع الفحص":
```python
def _empty_passwords():
    accounts = []
    try:
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "":
                    accounts.append(parts[0])
        return accounts
    except PermissionError:
        return None   # None = تعذّر الفحص (يختلف عن [] = لا مشاكل)
    except OSError:
        return None
```

ثم في `audit_users()`:
```python
empty = _empty_passwords()
if empty is None:
    status, detail, earned = "WARN", "Cannot read /etc/shadow (run as root)", 0
elif not empty:
    status, detail, earned = "PASS", "None found", weight
else:
    status, detail, earned = "FAIL", f"Found: {', '.join(empty)}", 0
```

#### [CRITICAL] نفس المشكلة في `_nopasswd_sudo()`
```python
def _nopasswd_sudo():
    hits = []
    for path in candidates:
        try:
            with open(path, "r") as f:
                ...
        except OSError:
            pass   # ← لو كل الملفات محجوبة، تُعيد [] = PASS خاطئ
    return hits
```

**الحل:** نفس أسلوب `None` للتمييز.

---

## 5. scoring.py — حساب الدرجات

### ماذا يفعل؟
- يحسب نسبة النجاح لكل نطاق (SSH، Firewall، Users)
- يحسب الدرجة النهائية الموزونة (40% + 35% + 25%)
- ينظّم الأوزان تلقائياً إذا فُحص نطاق واحد فقط

### المشاكل

لا توجد مشاكل منطقية أو أمنية في هذا الملف. الكود صحيح.

**ملاحظة بسيطة:** `score_label()` مكررة في `ui.py` — تكرار غير ضروري لكنه لا يُسبب مشكلة.

---

## 6. ui.py — الواجهة

### ماذا يفعل؟
- يطبع البانر الملون عند التشغيل
- يطبع نتائج كل فحص بلون يناسب حالته (أخضر/أحمر/أصفر)
- يطبع ملخص الدرجات والنتيجة النهائية

### المشاكل

لا توجد أخطاء برمجية. الكود سليم تماماً.

**ملاحظة:** `score_label()` معرّفة هنا وفي `scoring.py` — يمكن حذفها من `ui.py` واستيراد الواحدة من `scoring.py` لكن هذا تحسين اختياري.

---

## 7. exporter.py — التصدير

### ماذا يفعل؟
- يصدّر نتائج الفحص إلى ملف JSON مع timestamp ودرجات
- يصدّر نتائج الفحص إلى ملف TXT منسق

### المشاكل

#### [LOW] لا يوجد معالجة لخطأ الكتابة
```python
with open(filepath, "w", encoding="utf-8") as f:
    json.dump(data, f, ...)
# ← إذا المجلد محجوب أو القرص ممتلئ، يرمي exception غير معالج
```

**الحل:**
```python
try:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON report saved: {filepath}")
except OSError as e:
    print(f"[ERROR] Could not write report: {e}")
```

---

## 8. cis_rules.json — قاعدة القواعد

### ماذا يفعله؟
- يخزّن كل قواعد CIS Benchmarks
- يحدد الوزن والقيمة المتوقعة لكل فحص
- منفصل تماماً عن الكود (يمكن تعديله دون تعديل Python)

### المشاكل

#### [CRITICAL] `Protocol` موجود في القواعد لكنه لا يُستخدم في أنظمة حديثة
كما ذُكر في ssh_audit.py، هذا السطر في `cis_rules.json`:
```json
"Protocol": {
    "expected": "2",
    "weight": 10,
    ...
}
```
سيُعطي دائماً `WARN` على أنظمة OpenSSH 7.0+ لأن الإعداد حُذف من sshd تلقائياً.
هذا يُضيّع 10 نقاط من SSH بدون سبب حقيقي.

**الحل:** إما حذفه، أو خفض وزنه لـ 0 مؤقتاً، أو معالجته بشكل خاص في `ssh_audit.py`.

---

## 9. مراجعة ما بعد الاختبار — الجولة الثانية

تشغيل الأداة على سيرفر حقيقي (انظر قسم Testing في التقرير) كشف 4 ملاحظات مفهومية لم تظهر في مراجعة الكود الساكنة. **كلها عُولِجت.**

### [CRITICAL] False FAIL عند غياب `sshd_config`
**المشكلة:** الكود القديم كان يُعطي `FAIL` وصفر/65 عند غياب الملف — أي «SSH غير آمن بأقصى درجة». لكن غياب الملف قد يعني أن **SSH غير مثبّت أصلاً** (أكثر أماناً، لا أقل). هذا تناقض مباشر مع مبدأ الأداة (تجنّب الخلط بين «تعذّر التقييم» و«غير آمن»).
**الإصلاح:** غياب الملف → `WARN`/«غير منطبق» بدرجة محايدة، لا عقوبة 40 نقطة.

### [MEDIUM] لا يُنمذج القيم الافتراضية (الغياب يُعامَل دائماً كخطر)
**المشكلة:** كل إعداد غير مكتوب كان يأخذ `WARN`/صفر، رغم أن بعض الـdefaults آمنة (`PermitRootLogin prohibit-password`) وأخرى لا (`PasswordAuthentication yes`). فسيرفر بإعدادات افتراضية معقولة يُعاقَب كأنه مُهيّأ خطأً عمداً.
**الإصلاح:** قراءة الإعداد **الفعلي** عبر `sshd -T`، ومع تعذّره استخدام جدول `SSH_DEFAULTS` لتقييم الإعداد غير المكتوب بقيمته الحقيقية.

### [MEDIUM] هشاشة المطابقة مع اختلاف الـlocale
**المشكلة:** الفحوص تعتمد نصوصاً إنجليزية حرفية (`Status: active`, `deny (incoming)`, رايات `L`/`LK` من `passwd -S`). على سيرفر بـlocale غير إنجليزي قد تنكسر وتعطي نتيجة خاطئة.
**الإصلاح:** تشغيل كل أوامر الـshell تحت `LC_ALL=C` في الوحدات الثلاث.

### [LOW] تمييز `None` غير مكتمل في فحوص المستخدمين
**المشكلة:** `_empty_passwords` و`_nopasswd_sudo` كانا يميّزان «تعذّر القراءة» (None→WARN)، لكن `_root_locked` و`_uid0_non_root` يرجعان `False`/قائمة فارغة عند الفشل — تناقض جزئي.
**الإصلاح:** الدالتان الآن تُرجعان `None`→`WARN` عند تعذّر القراءة، فاكتمل التمييز عبر الفحوص الأربعة.

---

## ملخص الإصلاحات المطلوبة

| # | الملف | المشكلة | الخطورة | الإصلاح |
|---|-------|---------|---------|--------|
| 1 | `main.py` | لا يتحقق من صلاحية root | متوسط | أضف فحص `os.geteuid() != 0` |
| 2 | `main.py` | لا exit code بناءً على الدرجة | منخفض | `sys.exit(0 if score >= 60 else 1)` |
| 3 | `ssh_audit.py` | فحص `Protocol` مضلل على OpenSSH الحديث | حرج | عامله كـ PASS عند غيابه |
| 4 | `ssh_audit.py` | لا يتبع `Include` في sshd_config | متوسط | أضف قراءة الملفات المضمنة |
| 5 | `ssh_audit.py` | يأخذ آخر قيمة بدل أول قيمة | منخفض | أضف شرط `not in config` |
| 6 | `users_audit.py` | false PASS عند عدم وجود صلاحية لـ `/etc/shadow` | حرج | أعد `None` عند PermissionError |
| 7 | `users_audit.py` | false PASS عند عدم وجود صلاحية لـ `sudoers` | حرج | أعد `None` عند PermissionError |
| 8 | `firewall_audit.py` | كشف المنافذ قد يفوّت IPv6 | متوسط | استخدم regex بدل string search |
| 9 | `exporter.py` | لا معالجة لخطأ الكتابة | منخفض | أضف try/except حول file write |
| 10 | `ssh_audit.py` | False FAIL عند غياب `sshd_config` | حرج | غياب الملف → WARN/غير منطبق |
| 11 | `ssh_audit.py` | لا يُنمذج الـdefaults (الغياب = خطر دائماً) | متوسط | قراءة `sshd -T` + جدول `SSH_DEFAULTS` |
| 12 | الكل | هشاشة المطابقة مع الـlocale | متوسط | `LC_ALL=C` في كل `_run()` |
| 13 | `users_audit.py` | تمييز `None` غير مكتمل (root/uid0) | منخفض | إرجاع `None`→WARN عند الفشل |

> **الحالة:** جميع الـ13 (1–9 من الجولة الأولى، 10–13 من الجولة الثانية) **مُطبَّقة في النسخة الحالية**.

---

## الخلاصة

الكود **سليم بشكل عام** وبنيته جيدة، وقد عُولِجت كل الملاحظات على جولتين:

1. **الجولة الأولى** عالجت الخطر الأهم: **False PASS** في فحوص `/etc/shadow` و`sudoers`، وفحص `Protocol` المضلِّل.
2. **الجولة الثانية (بعد الاختبار)** عالجت أخطاء في الاتجاه الآمن: **False FAIL** عند غياب `sshd_config`، وعدم نمذجة الـdefaults، وهشاشة الـlocale، واكتمال تمييز `None`.

النتيجة: الأداة الآن تقيس **الإعداد الفعلي** (لا ما هو مكتوب فقط)، ولا تُنتج لا False PASS ولا False FAIL في الحالات المعروفة. القيود المتبقية (دعم UFW فقط، 3 نطاقات، وزن `Protocol` كـtrade-off) موثّقة في التقرير.
