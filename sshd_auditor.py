import os

def audit_ssh():
    # مسار ملف إعدادات SSH في خوادم لينكس
    ssh_config_path = "/etc/ssh/sshd_config"
    results = {}
    
    # التحقق من وجود الملف لتجنب انهيار الأداة
    if not os.path.exists(ssh_config_path):
        return {"error": "ملف إعدادات SSH غير موجود في هذا المسار."}

    try:
        with open(ssh_config_path, 'r') as file:
            lines = file.readlines()
            
            for line in lines:
                line = line.strip()
                # تجاهل الأسطر الفارغة والتعليقات
                if not line or line.startswith('#'):
                    continue
                
                # استخراج الإعدادات الحرجة
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0]
                    value = parts[1]
                    
                    if key in ['PermitRootLogin', 'PasswordAuthentication', 'Port', 'Protocol']:
                        results[key] = value
                        
    except PermissionError:
        return {"error": "صلاحيات غير كافية. يجب تشغيل الأداة بصلاحيات Root (sudo)."}

    return results

# لتجربة الكود مباشرة عند تشغيل هذا الملف فقط
if __name__ == "__main__":
    print("[-] جاري فحص إعدادات SSH...")
    ssh_data = audit_ssh()
    print(ssh_data)
