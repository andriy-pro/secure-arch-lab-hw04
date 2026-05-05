# Зведення виявлень ZAP

Ціль: http://172.27.224.80:3000/
Інструмент: OWASP ZAP Desktop
Середовище: OWASP ZAP Desktop у Windows сканує Juice Shop, запущений у Docker/WSL

| № | Виявлення | Ризик | Достовірність | Кількість / доказ | Приклад URL | Нотатки |
|---|---|---|---|---|---|---|
| 1 | SQL Injection | High | Low | 1 виявлення; відповідь `500 Internal Server Error` на ін'єкційний пошуковий запит | `GET http://172.27.224.80:3000/rest/products/search?q=%27%28` | Основний високоризиковий приклад DAST зі звіту ZAP для цільового сервісу. |
| 2 | Content Security Policy (CSP) Header Not Set | Medium | High | 5 виявлень | `GET http://172.27.224.80:3000` | Відсутній CSP послаблює браузерний захист від XSS та наслідків ін'єкції даних. |
| 3 | Cross-Domain Misconfiguration | Medium | Medium | 5 виявлень | `GET http://172.27.224.80:3000/chunk-24EZLZ4I.js` | ZAP позначив міждоменну поведінку на ресурсах цільового сервісу. |
| 4 | Session ID in URL Rewrite | Medium | High | 5 виявлень | `GET http://172.27.224.80:3000/socket.io/?EIO=4&transport=polling&t=PtvYL_Z&sid=oCSgl27LzFT4KybHAAAC` | Ідентифікатор сесії є в параметрах URL, тому може потрапляти в логи, історію браузера або referrer-заголовки. |
| 5 | Missing Anti-clickjacking Header | Medium | Medium | 1 виявлення | `POST http://172.27.224.80:3000/socket.io/?EIO=4&transport=polling&t=PtvYL_Y&sid=oCSgl27LzFT4KybHAAAC` | Відсутній захист від відкриття сторінки у frame може створити clickjacking-ризик. |
| 6 | X-Content-Type-Options Header Missing | Low | Medium | 3 виявлення | `GET http://172.27.224.80:3000/socket.io/?EIO=4&transport=polling&t=PtvYLtn` | Відсутність `nosniff` може дозволити MIME sniffing у старішій або legacy-поведінці браузерів. |
