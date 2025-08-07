from pygost.asn1schemas import x509
from pygost import gost34112012
from pygost.gost3410 import verify, CURVES
from pygost.utils import hexenc
from asn1crypto import cms

def parse_gost_signature(signature_bytes):
    sig_len = len(signature_bytes)

    if sig_len == 64:  # GOST R 34.10-2012 256-bit
        r = signature_bytes[:32]
        s = signature_bytes[32:64]
        return r, s
    else:
        raise ValueError(f"Неожиданная длина подписи: {sig_len}")

def extract_certificate(filepath):
    with open(filepath, "rb") as f:
        signed_data = f.read()

    # Парсим CMS структуру
    content_info = cms.ContentInfo.load(signed_data)
    signed_data = content_info['content']

    # Извлекаем все сертификаты из подписи
    certificates = signed_data['certificates']

    # Сохраняем первый сертификат в файл
    if certificates:
        with open("extracted_cert.cer", "wb") as f:
            f.write(certificates[0].dump())
        print("Сертификат сохранен в extracted_cert.cer")
    else:
        print("В подписи не найдены сертификаты")

def extract_public_key(filepath):
    # Загружаем публичный ключ из сертификата
    with open(filepath, "rb") as f:
        cert_bytes = f.read()

    cert, _ = x509.Certificate().decode(cert_bytes)
    pubkey = bytes(cert["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"])

    print(f'pubkey_byte: {pubkey}')
    print("Публичный ключ (hex):", hexenc(pubkey))
    x, y = pubkey[:32], pubkey[32:]
    print(f'x_byte: {x}')
    print(f'y_byte: {y}')
    print(f'x_hex: {x.hex()}')
    print(f'y_hex: {y.hex()}')

    return x, y

def extract_r_s(filename):

    # Парсим CMS/PKCS#7 структуру
    with open(filename, "rb") as f:
        data = f.read()
    cms_data = cms.ContentInfo.load(data)
    signed_data = cms_data['content']

    # Извлекаем все подписи
    for signer in signed_data['signer_infos']:
        signature_bytes = signer['signature'].native
        r, s = parse_gost_signature(signature_bytes)
        print(f'r_hex: {r.hex()}')
        print(f's_hex: {s.hex()}')

        # ГОСТ использует little-endian
        r_int = int.from_bytes(r, byteorder='little')
        s_int = int.from_bytes(s, byteorder='little')
        print(f"r: {r_int.bit_length()} бит. Должно быть ≤ 256")
        print(f"s: {s_int.bit_length()} бит. Должно быть ≤ 256")

    return r,s

def hash_file(filename):
    # Вычисляем хэш файла
    with open(filename, "rb") as f:
        file_data = f.read()
    hash_obj = gost34112012.GOST34112012(digest_size=256)
    hash_obj.update(file_data)
    message_hash = hash_obj.digest()

    return message_hash


if __name__ == '__main__':
    main_file = "file.pdf"
    signature_file = "signature.sig"

    extract_certificate(signature_file)
    print("_" * 100)
    x,y = extract_public_key("extracted_cert.cer")
    print("_" * 100)
    r,s = extract_r_s(signature_file)
    message_hash = hash_file(main_file)

    # Проверяем подпись
    curve = CURVES["id-tc26-gost-3410-2012-256-paramSetA"]

    # print(len(x))
    # print(len(y))

    pub_key = (int.from_bytes(x, "little"), int.from_bytes(y, "little"))
    signature = (int.from_bytes(r, "little"), int.from_bytes(s, "little"))

    # pub_key = (x,y)
    # signature = (r,s)

    is_valid = verify(curve, pub_key, message_hash, signature)

    print("✅ Подпись верна!" if is_valid else "❌ Подпись недействительна!")