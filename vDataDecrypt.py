#!/usr/bin/env python3
import sys
import pickle
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.exceptions import InvalidTag

# -------------------------------
# 함수: 전체 raw_data에서 marker(4바이트)를 찾는 함수
# -------------------------------
def find_all_markers(data, marker):
    indices = []
    idx = data.find(marker)
    while idx != -1:
        indices.append(idx)
        idx = data.find(marker, idx + 1)
    return indices

# -------------------------------
# 1. 파일 로드 및 전처리
# -------------------------------
# encData.txt 파일 (hex 문자열, 공백 및 줄바꿈 제거)
with open("../encData/encData.txt", "r") as f:
    hex_data = f.read().replace(" ", "").replace("\n", "").replace("\r", "")
raw_data = bytes.fromhex(hex_data)

# -------------------------------
# 2. 블록 단위로 데이터 분리 (블록은 "inet" 즉, 696e6574 로 시작)
# -------------------------------
marker = bytes.fromhex("696E6574")
block_indices = find_all_markers(raw_data, marker)
if not block_indices:
    print("[ERROR] 'inet' 마커를 찾을 수 없습니다.")
    sys.exit(1)

# 각 블록은 marker 위치에서 시작하여 다음 marker 직전까지로 가정
blocks = []
for i, start in enumerate(block_indices):
    end = block_indices[i+1] if i+1 < len(block_indices) else len(raw_data)
    block = raw_data[start:end]
    # 블록 길이가 최소 100바이트 이상이어야 (필수 필드 총 100바이트 이상: 4+16+4+4+4+4+40+12+>=16(tag)+12)
    if len(block) < 100:
        continue
    blocks.append(block)

if not blocks:
    print("[ERROR] 최소 길이의 블록을 찾지 못했습니다.")
    sys.exit(1)

print(f"[INFO] 총 {len(blocks)} 개의 블록이 발견되었습니다.")

# -------------------------------
# 3. CLAS6 키 로딩 (키 언래핑용)
# -------------------------------
with open("../keyBag/CLAS6_UWPKY.pkl", "rb") as f:
    class_key = pickle.load(f)

# -------------------------------
# 4. 각 블록 처리: 필수 키 클래스가 "06000000" 인 블록만 처리
# -------------------------------
for block in blocks:
    # 블록 구조 (각 블록 내 오프셋, 모두 바이트 단위):
    # Field1: inet          : block[0:4]
    # Field2: v_persistentRef: block[4:20]  → AAD = block[4:20]
    # Field3: 쓰레기값         : block[20:24]
    # Field4: 암호화 클래스     : block[24:28]
    # Field5: 필요 키 클래스   : block[28:32] → 확인, 필요 키 클래스가 "06000000"인지 검사
    # Field6: 래핑된 키 길이   : block[32:36]  (예: "28000000")
    # Field7: 래핑된 키        : block[36:76]  (40 bytes)
    # Field8: Nonce           : block[76:88]  (12 bytes)
    # Field9: 암호화된 내용 (cipherText+Tag): block[88 : block_length - 12]
    # Field10: trailer (쓰레기값): block[-12:]
    if len(block) < 100:
        continue  # 최소 블록 길이 부족
    required_key_class = block[28:32]
    if required_key_class.hex().lower() != "06000000":
        # 필요 키 클래스가 06000000이 아니면 건너뜀
        continue
    
    aad = block[4:20]  # AAD: 16 bytes (inet 제거)
    # DEBUG: 출력
    print("\n==============================================")
    print(f"[INFO] 블록 처리 시작 (Block 길이: {len(block)} bytes)")
    print(f"    AAD: {aad.hex()}")
    
    # 래핑된 키: field7
    wrapped_key_block = block[36:76]
    try:
        unwrapped_key = aes_key_unwrap(class_key, wrapped_key_block)
        print(f"[✅] 키 언래핑 성공!")
        print(f"    unwrapped_key: {unwrapped_key.hex()}")
    except Exception as e:
        print(f"[❌] 키 언래핑 실패: {e}")
        continue

    aesgcm = AESGCM(unwrapped_key)
    
    # Nonce: field8
    nonce = block[76:88]
    print(f"    Nonce: {nonce.hex()}")
    
    # Field9: 암호화된 blob = block[88 : -12]
    enc_blob = block[88:-12]
    if len(enc_blob) < 16:
        print("[WARN] 암호화된 blob 길이가 너무 짧습니다 (최소 16바이트 필요).")
        continue
    # 여기서 AES-GCM은 tag가 16바이트이므로, ciphertext = enc_blob[:-16] and tag = enc_blob[-16:]
    ciphertext = enc_blob[:-16]
    tag = enc_blob[-16:]
    
    print(f"    Tag: {tag.hex()}")
    print(f"    Ciphertext: (길이 {len(ciphertext)} bytes)")
    if len(ciphertext) >= 32:
        print(f"        시작 32 bytes: {ciphertext[:32].hex()}")
        print(f"        끝   32 bytes: {ciphertext[-32:].hex()}")
    else:
        print(f"        전체: {ciphertext.hex()}")
    
    # ---------------------------
    # 복호화 시도: AAD가 있는 경우와 None인 경우 모두 시도
    # ---------------------------
    for aad_candidate in [aad, None]:
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad_candidate)
            print("\n[✅] 복호화 성공!")
            print(f"    AAD 사용: {aad_candidate.hex() if aad_candidate else 'None'}")
            print(f"    Plaintext (hex): {plaintext.hex()}")
            try:
                print(f"    Plaintext (ascii): {plaintext.decode(errors='replace')}")
            except Exception:
                print(f"    Plaintext (ascii): {plaintext}")
            break  # 성공하면 블록 처리 종료
        except Exception as e:
            print(f"[❌] 복호화 실패 (AAD={'persistent_ref[4:]' if aad_candidate else 'None'}): {e}")
    print("==============================================")
