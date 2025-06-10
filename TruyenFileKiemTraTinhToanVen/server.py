import os
from flask import Flask, request, render_template, send_from_directory, flash, redirect, url_for
from werkzeug.utils import secure_filename
import hashlib

# Cấu hình Flask
app = Flask(__name__)
app.secret_key = "supersecretkey_for_flash_messages" # Khóa bí mật cho flash messages, đổi thành giá trị mạnh hơn trong thực tế
app.config['UPLOAD_FOLDER'] = 'uploaded_files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Giới hạn kích thước file upload 16MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', 'py', 'docx', 'xlsx'}

# Tạo thư mục lưu trữ file nếu chưa tồn tại
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_sha256(filepath):
    """Tính toán SHA-256 hash của một file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(4096)  # Đọc từng khối 4KB
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

@app.route('/')
def index():
    # Lấy danh sách các file đã upload để hiển thị
    files_in_folder = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            files_in_folder.append({
                'name': filename,
                'sha256': calculate_sha256(filepath) # Tính hash để hiển thị
            })
    return render_template('index.html', files=files_in_folder)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('Không có phần file trong request')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('Không có file được chọn')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Tính toán SHA-256 của file vừa nhận
        received_hash = calculate_sha256(filepath)

        # Hash được gửi từ client (nếu có)
        client_hash = request.form.get('file_hash')

        if client_hash and client_hash != received_hash:
            flash(f'Kiểm tra tính toàn vẹn thất bại cho file "{filename}"! Hash nhận được: {received_hash}, Hash từ client: {client_hash}', 'danger')
            # Có thể xóa file nếu hash không khớp
            # os.remove(filepath)
        else:
            flash(f'File "{filename}" đã được upload thành công. SHA-256: {received_hash}', 'success')
    else:
        flash('File không được phép hoặc có lỗi.', 'danger')
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    else:
        flash(f'File "{filename}" không tồn tại.', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) # debug=True sẽ tự động tải lại server khi có thay đổi và hiển thị lỗi chi tiết