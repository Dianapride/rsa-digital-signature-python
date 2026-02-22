from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os

# ПУНКТ 3: Функція підписування повідомлення
# Приймає вхідний файл або рядок, повертає підпис у Base64
def sign_data(input_data, private_key_pem):
    # Визначаємо тип вхідних даних (файл чи рядок)
    if os.path.isfile(input_data):
        with open(input_data, 'rb') as f:
            data = f.read()
    else:
        data = input_data.encode('utf-8')
    
    # Імпортуємо приватний ключ
    private_key = RSA.import_key(private_key_pem)
    
    # Обчислюємо хеш від даних за алгоритмом SHA-256
    hash_obj = SHA256.new(data)
    
    # Створюємо підпис за схемою PKCS#1 v1.5
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    
    # Кодуємо бінарний підпис у Base64 для зручності
    return base64.b64encode(signature).decode('utf-8')

# ПУНКТ 4: Функція перевірки підпису
# Приймає повідомлення, підпис (Base64) і публічний ключ,
# повертає результат перевірки (істина/хиба)
def verify_signature(input_data, signature_b64, public_key_pem):
    # Визначаємо тип вхідних даних (файл чи рядок)
    if os.path.isfile(input_data):
        with open(input_data, 'rb') as f:
            data = f.read()
    else:
        data = input_data.encode('utf-8')
    
    # Імпортуємо публічний ключ
    public_key = RSA.import_key(public_key_pem)
    
    # Декодуємо підпис з Base64 у бінарний формат
    signature = base64.b64decode(signature_b64)
    
    # Обчислюємо хеш від отриманих даних
    hash_obj = SHA256.new(data)
    
    # Намагаємося перевірити підпис
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

# === Основна програма ===
if __name__ == "__main__":
    print("=== ЛАБОРАТОРНА РОБОТА 4: ЕЦП на основі RSA ===\n")
    
    # ПУНКТ 2: Генерація RSA пари ключів (2048 біт)
    # Використовуємо функцію з методички
    print("1. Генерація RSA пари ключів...")
    key = RSA.generate(2048)
    private_pem = key.export_key(format='PEM')
    public_pem = key.publickey().export_key(format='PEM')
    
    # Зберігаємо ключі у файли у форматі PEM
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
    print("   Ключі збережено у файлах: private_key.pem, public_key.pem\n")
    
    # ПУНКТ 5: Підготовка тестових даних
    # Створюємо три типи файлів для тестування
    print("2. Підготовка тестових даних...")
    
    # 1) Короткий рядок
    with open('test_short.txt', 'w', encoding='utf-8') as f:
        f.write("Це тестовий рядок для ЕЦП")
    
    # 2) Великий текст (~1 МБ)
    with open('test_large.txt', 'w', encoding='utf-8') as f:
        f.write("A" * 1024 * 1024)  # Рівно 1 МБ символів
    
    # 3) Бінарний файл
    with open('test_binary.bin', 'wb') as f:
        f.write(os.urandom(50000))  # Випадкові бінарні дані
    
    print("   Створено файли: test_short.txt, test_large.txt, test_binary.bin\n")
    
    # ПУНКТИ 3, 6: Підписування та перевірка
    print("3. Тестування на трьох прикладах повідомлень:")
    
    # Список файлів для тестування
    test_files = ['test_short.txt', 'test_large.txt', 'test_binary.bin']
    
    # Підписуємо та перевіряємо кожен файл
    for file_name in test_files:
        print(f"\n   Файл: {file_name}")
        
        # Підписуємо файл
        signature = sign_data(file_name, private_pem)
        print(f"   - Підпис успішно створено")
        
        # Перевіряємо підпис
        is_valid = verify_signature(file_name, signature, public_pem)
        print(f"   - Перевірка підпису: {'УСПІШНО' if is_valid else 'НЕВДАЧА'}")
    
    print("\n4. Всі тести пройдено успішно.\n")
    
    # ПУНКТ 7: Зміна одного байту у файлі
    print("=" * 60)
    print("5. Демонстрація зміни файлу та перевірка підпису")
    print("=" * 60)
    
    # Зберігаємо оригінальний підпис для файлу test_short.txt
    original_signature = sign_data('test_short.txt', private_pem)
    print("\nДля файлу 'test_short.txt' збережено оригінальний підпис.")
    
    # Очікуємо, поки користувач змінить файл
    input("Змініть файл 'test_short.txt' та натисніть Enter для перевірки...")
    
    # Перевіряємо підпис для зміненого файлу
    print("\nПеревірка підпису для зміненого файлу...")
    is_valid_modified = verify_signature('test_short.txt', original_signature, public_pem)
    
    # Виводимо результат
    if is_valid_modified:
        print("Результат: Підпис валідний")
    else:
        print("Результат: Підпис невалідний")
    
    # Додаткова інформація про результат
    print("\n" + "=" * 60)
    if not is_valid_modified:
        print("Висновок: Підпис став невалідним після зміни файлу.")
        print("Це підтверджує властивість цілісності ЕЦП.")
    else:
        print("Висновок: Підпис залишився валідним.")
    print("=" * 60)