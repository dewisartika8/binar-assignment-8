# To-Do List API

## Cara Menjalankan

1. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

2. **Jalankan server:**
   ```
   python app.py
   ```

3. **Base URL:**  
   ```
   http://localhost:5000/api
   ```

## Endpoint Utama

- **POST /api/register**  
  Register user baru.  
  Body: `{ "email": "...", "password": "..." }`

- **POST /api/login**  
  Login, dapatkan token.  
  Body: `{ "email": "...", "password": "..." }`  
  Response: `{ "token": "..." }`

- **GET/POST /api/lists**  
  CRUD List (header: `Authorization: Bearer <token>`)

- **GET/POST /api/lists/<list_id>/tasks**  
  CRUD Task (header: `Authorization: Bearer <token>`)

## Alur Autentikasi

1. Register → Login → Dapatkan token
2. Kirim token di header setiap request:
   ```
   Authorization: Bearer <token>
   ```

## Cara Testing (Step by Step)

1. **Register user baru:**  
   POST ke `/api/register` dengan email & password.

2. **Login:**  
   POST ke `/api/login` dengan email & password.  
   Simpan token dari response.

3. **Akses endpoint lain:**  
   Tambahkan header:  
   ```
   Authorization: Bearer <token>
   ```
   Coba GET/POST/PUT/DELETE ke `/api/lists` dan `/api/lists/<list_id>/tasks`.

4. **Cek error:**  
   Coba akses endpoint tanpa token → harus dapat 401 Unauthorized.

---

**Tips:**  
- Bisa test pakai Postman/Insomnia, import endpoint di atas.
- Untuk reset database, hapus file `todo.db`.

from flasgger import Swagger

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "To-Do List API",
        "description": "API documentation for To-Do List with JWT Auth",
        "version": "1.0"
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Bearer <token>"
        }
    }
}

swagger = Swagger(app, template=swagger_template)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
