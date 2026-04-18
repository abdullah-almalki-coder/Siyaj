# sshd_auditor.py

def audit_ssh():
    """
    دالة تقوم بقراءة ملف إعدادات SSH واستخراج القيم المهمة
    وترجعها في شكل Dictionary
    """

    config_path = "/etc/ssh/sshd_config"

    # القيم اللي نبي نستخرجها
    settings = {
        "PermitRootLogin": None,
        "PasswordAuthentication": None,
        "Port": None,
        "Protocol": None,
        "MaxAuthTries": None
    }

    try:
        # محاولة فتح الملف
        with open(config_path, "r") as file:
            for line in file:
                # حذف الفراغات من البداية والنهاية
                line = line.strip()

                # تجاهل الأسطر الفاضية أو التعليقات
                if not line or line.startswith("#"):
                    continue

                # تقسيم السطر إلى مفتاح وقيمة
                parts = line.split()

                # التأكد أن السطر يحتوي على مفتاح وقيمة
                if len(parts) < 2:
                    continue

                key = parts[0]
                value = parts[1]

                # إذا كان المفتاح من ضمن الإعدادات المطلوبة نحفظه
                if key in settings:
                    settings[key] = value

        return settings

    except FileNotFoundError:
        # في حال الملف غير موجود
        return {
            "error": "sshd_config file not found"
        }

    except PermissionError:
        # في حال ما عندك صلاحيات (لازم sudo)
        return {
            "error": "Permission denied. Try running with sudo."
        }

    except Exception as e:
        # أي خطأ غير متوقع
        return {
            "error": f"Unexpected error: {str(e)}"
        }
