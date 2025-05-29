Studify
=============================

Deskripsi:
Studify adalah platform pendidikan komprehensif yang memungkinkan pengguna untuk membuat dan mengelola rumus, catatan, dan kuis untuk berbagai mata pelajaran. Platform ini memiliki antarmuka pengguna dan admin, sehingga cocok untuk siswa dan pendidik.

Features
--------
1. User Features:
   - Registrasi dan login pengguna  
   - Membuat dan mengelola rumus/catatan  
   - Membuat dan mengelola kuis  
   - Melihat dashboard pribadi  
   - Organisasi berdasarkan mata pelajaran (Matematika, Fisika, Kimia)

2. Admin Features:
   - Melihat semua pengguna yang terdaftar  
   - Melihat detail pengguna termasuk rumus dan kuis mereka  
   - Menghapus pengguna  
   - Mengelola semua konten di platform

Installation
-----------

1. Clone the repository:

   ```
   git clone https://github.com/GavinAnggreas/Studify.git
   cd Studify
   ```

2. Create and activate a virtual environment:

   ```
   # Windows
   python -m venv env
   env\Scripts\activate
   ```

   ```
   # Linux/MacOS
   python3 -m venv env
   source env/bin/activate
   ```

3. Install dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Run the application:

   ```
   python app.py
   ```

The application will be available at http://localhost:5000

Database
--------
Aplikasi ini menggunakan SQLite sebagai basis datanya. File database studify.db akan dibuat secara otomatis saat aplikasi pertama kali dijalankan.

Akun Admin Default
-------------------
Username: admin
Password: admin123

Requirements
-----------
- Python 3.8+
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Werkzeug

Untuk daftar yang lebih lengkap, lihat requirements.txt
