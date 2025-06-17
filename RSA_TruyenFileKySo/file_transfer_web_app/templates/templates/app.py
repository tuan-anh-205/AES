# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
import os
import json # Dùng để đóng gói metadata khi gửi qua API (nếu có)
import requests # Để gửi file qua HTTP POST
import time # Dùng để tạo tên file duy nhất

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.secret_key = 'supersecretkey' # Khóa bí mật để Flash messages hoạt động, đổi thành chuỗi ngẫu nhiên trong thực tế

UPLOAD_FOLDER_SENDER = 'uploads_sender' # Thư mục tạm lưu file gửi đi
UPLOAD_FOLDER_RECEIVER = 'uploads_receiver' # Thư mục tạm lưu file nhận được
KEY_FOLDER = os.getcwd() # Khóa nằm ở thư mục gốc của ứng dụng Flask

# Tạo các thư mục nếu chưa tồn tại
os.makedirs(UPLOAD_FOLDER_SENDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER_RECEIVER, exist_ok=True)


# --- Các hàm mật mã cơ bản (tái sử dụng từ sender.py và receiver.py) ---

def load_private_key(key_path=os.path.join(KEY_FOLDER, "private_key.pem")):
    """Tải khóa bí mật từ file."""
    try:
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        flash(f"Lỗi: Không tìm thấy private_key.pem tại {key_path}. Hãy chạy generate_keys.py trước!", 'danger')
        return None
    except Exception as e:
        flash(f"Lỗi khi tải khóa bí mật: {e}", 'danger')
        return None

def load_public_key(key_path=os.path.join(KEY_FOLDER, "public_key.pem")):
    """Tải khóa công khai từ file."""
    try:
        with open(key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except FileNotFoundError:
        flash(f"Lỗi: Không tìm thấy public_key.pem tại {key_path}. Hãy chạy generate_keys.py trước!", 'danger')
        return None
    except Exception as e:
        flash(f"Lỗi khi tải khóa công khai: {e}", 'danger')
        return None

def calculate_file_hash(file_data):
    """Tính toán giá trị băm (hash) của dữ liệu file."""
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(file_data)
    return hasher.finalize()

def sign_hash(private_key, data_hash):
    """Ký giá trị băm bằng khóa bí mật."""
    signature = private_key.sign(
        data_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, data_hash, signature):
    """Xác minh chữ ký bằng khóa công khai."""
    try:
        public_key.verify(
            signature,
            data_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Lỗi khi xác minh chữ ký: {e}")
        return False


# --- Routes (Đường dẫn URL) cho Flask ---

@app.route('/')
def index():
    """Trang chủ để gửi file."""
    return render_template('index.html')

@app.route('/send_file', methods=['POST'])
def send_file():
    """Xử lý việc gửi file từ form."""
    if 'file' not in request.files:
        flash('Không có file nào được chọn!', 'warning')
        return redirect(request.url)

    file = request.files['file']
    receiver_url = request.form.get('receiver_url')

    if file.filename == '':
        flash('File chưa được chọn!', 'warning')
        return redirect(request.url)

    if not receiver_url:
        flash('Vui lòng nhập địa chỉ URL của máy nhận!', 'warning')
        return redirect(request.url)

    if file and receiver_url:
        private_key = load_private_key()
        if private_key is None:
            return redirect(request.url) # Lỗi đã được flash bên trong load_private_key

        try:
            # Đọc dữ liệu file từ bộ nhớ tạm
            file_data = file.read()
            original_filename = file.filename

            # Tính toán hash
            file_hash = calculate_file_hash(file_data)

            # Ký hash
            signature = sign_hash(private_key, file_hash)

            # Gói dữ liệu để gửi
            # Chúng ta sẽ gửi file, chữ ký, và tên file qua một POST request
            files = {
                'file': (original_filename, file_data, file.content_type),
                'signature': ('signature.bin', signature, 'application/octet-stream')
            }
            # public_key cũng được gửi kèm để bên nhận có thể xác minh ngay
            public_key = load_public_key()
            if public_key is None:
                return redirect(request.url)
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            data = {
                'public_key': public_key_pem.decode('utf-8')
            }

            print(f"Đang gửi file '{original_filename}' và chữ ký tới: {receiver_url}")
            response = requests.post(receiver_url, files=files, data=data)

            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    flash(f"Gửi file '{original_filename}' thành công! Kết quả xác minh từ máy nhận: {result.get('message')}", 'success')
                else:
                    flash(f"Gửi file '{original_filename}' thành công, nhưng có lỗi xác minh từ máy nhận: {result.get('message')}", 'danger')
            else:
                flash(f"Lỗi khi gửi file: Server trả về mã {response.status_code}. Phản hồi: {response.text}", 'danger')

        except requests.exceptions.ConnectionError:
            flash(f"Lỗi kết nối: Không thể kết nối đến máy nhận tại {receiver_url}. Đảm bảo máy nhận đang chạy.", 'danger')
        except Exception as e:
            flash(f"Đã xảy ra lỗi không mong muốn khi gửi file: {e}", 'danger')

    return redirect(url_for('index')) # Quay lại trang gửi file


@app.route('/receive_file', methods=['GET', 'POST'])
def receive_file():
    """Trang và API endpoint để nhận file."""
    if request.method == 'POST':
        # Đây là API endpoint khi một bên khác gửi file đến
        if 'file' not in request.files or 'signature' not in request.files or 'public_key' not in request.form:
            return {'status': 'error', 'message': 'Thiếu dữ liệu file, chữ ký hoặc khóa công khai.'}, 400

        file = request.files['file']
        signature = request.files['signature'].read()
        public_key_pem = request.form['public_key'].encode('utf-8')

        if file.filename == '':
            return {'status': 'error', 'message': 'Tên file trống.'}, 400

        try:
            # Tải khóa công khai của người gửi (được gửi kèm)
            received_public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )

            # Đọc dữ liệu file
            received_file_data = file.read()
            original_filename = file.filename

            # Lưu file đã nhận vào thư mục tạm thời
            timestamp = int(time.time())
            safe_filename = f"{timestamp}_{original_filename}"
            save_path = os.path.join(UPLOAD_FOLDER_RECEIVER, safe_filename)
            with open(save_path, "wb") as f:
                f.write(received_file_data)
            print(f"Đã lưu file nhận được tới: {save_path}")

            # Tính toán hash của file đã nhận
            actual_file_hash = calculate_file_hash(received_file_data)

            # Xác minh chữ ký
            if verify_signature(received_public_key, actual_file_hash, signature):
                message = "Xác minh chữ ký THÀNH CÔNG! File là xác thực và chưa bị thay đổi."
                flash(message, 'success')
                print(message)
                return {'status': 'success', 'message': message}, 200
            else:
                message = "Xác minh chữ ký THẤT BẠI! File có thể đã bị giả mạo hoặc không phải từ người gửi hợp lệ."
                flash(message, 'danger')
                print(message)
                return {'status': 'error', 'message': message}, 200 # Vẫn là 200 OK vì request được xử lý

        except InvalidSignature:
            message = "Lỗi xác minh: Chữ ký không hợp lệ."
            flash(message, 'danger')
            return {'status': 'error', 'message': message}, 200
        except Exception as e:
            message = f"Đã xảy ra lỗi khi xử lý file nhận: {e}"
            flash(message, 'danger')
            return {'status': 'error', 'message': message}, 500

    # Nếu là GET request, chỉ hiển thị trang nhận file
    # Lấy danh sách các file đã nhận để hiển thị
    received_files = []
    for filename in os.listdir(UPLOAD_FOLDER_RECEIVER):
        filepath = os.path.join(UPLOAD_FOLDER_RECEIVER, filename)
        if os.path.isfile(filepath):
            received_files.append(filename)
    return render_template('receiver_page.html', received_files=received_files)

@app.route('/download/<filename>')
def download_file(filename):
    """Cho phép tải xuống file đã nhận."""
    return send_from_directory(UPLOAD_FOLDER_RECEIVER, filename, as_attachment=True)


if __name__ == '__main__':
    # Chạy ứng dụng Flask. debug=True chỉ nên dùng khi phát triển.
    # host='0.0.0.0' để ứng dụng có thể truy cập từ các máy khác trong mạng cục bộ.
    # port=5000 là cổng mặc định của Flask.
    app.run(debug=True, host='0.0.0.0', port=5000)