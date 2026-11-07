# So'zTop Python Backend (Render.com uchun tayyor)

Ushbu backend Python FastAPI va SQLite asosida yaratilgan bo'lib, o'qituvchilar va o'quvchilar uchun sodda avtorizatsiya (username + parol), so'z to'plamlari va statistikalarni sinxronlashtirishni ta'minlaydi.

## Render.com ga joylash (Deploy):

1. Ushbu `server` papkasidagi fayllarni GitHub omboringizga (repository) yuklang.
2. [Render.com](https://render.com) ga kiring va **New +** -> **Web Service** ni tanlang.
3. GitHub omboringizni tanlang.
4. Quyidagi parametrlarni kiriting:
   - **Name**: `soztop-api`
   - **Language**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. **Create Web Service** tugmasini bosing!
6. Render sizga bepul havola beradi (masalan: `https://soztop-api.onrender.com`).
7. Frontend `.env` fayliga yoki sozlamalariga shu havolani qo'yasiz:
   `VITE_API_URL=https://soztop-api.onrender.com`

## Mahalliy ishga tushirish (Local):
```bash
cd server
pip install -r requirements.txt
python main.py
```
Server `http://localhost:8000` manzilida ishlaydi. Hujjatlar: `http://localhost:8000/docs`.
